//! Daemon-side lifecycle for the infrastructure services a device hosts
//! for the mesh: the frozen LegacyV1 member forwarder, the self-hosted
//! signaling relay, and the STUN / TURN servers.
//!
//! The [`ServiceManager`] owns the running handles, reconciles them
//! against [`ServicesConfig`] on demand (start what should run, stop
//! what shouldn't), and keeps every joined network's advertised
//! capabilities in sync so peers discover the roles this device offers.
//! It's shared (behind an `Arc`) between [`crate::cli::serve`] — which
//! applies the initial config and tears everything down on shutdown —
//! and the control socket, which handles live `services set` requests.
//!
//! Service start failures are non-fatal: a port already in use shouldn't
//! take the daemon down, so a failed start is logged and surfaced in the
//! status report as `enabled but not running`, leaving the rest of the
//! mesh untouched.

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this import is confined to the frozen LegacyV1 adapter"
)]
use myownmesh_core::legacy_v1::{LegacyV1Network, LegacyV1Runtime, RelayService};
use myownmesh_core::services::{ServiceAdvert, ServiceRole};
use myownmesh_core::{CapabilityAdvert, MeshConfig, MeshHandle, NetworkConfig, ServicesConfig};
use myownmesh_services::{StunServer, StunServerHandle, TurnServer, TurnServerHandle};
use myownmesh_signaling::server::{RelayStatsSnapshot, SignalingServer, SignalingServerHandle};
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::registry::NetworkRegistry;

/// Owns every running service handle and the config they were started
/// from. Reconfiguration goes through [`ServiceManager::apply`].
pub struct ServiceManager {
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    state: Mutex<ManagerState>,
    #[cfg(feature = "legacy-v1")]
    legacy_v1: Option<LegacyV1Runtime>,
}

#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this alias is confined to the frozen LegacyV1 adapter"
)]
type LegacyNetworkRuntime = LegacyV1Network;

#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this alias is confined to the frozen LegacyV1 adapter"
)]
type LegacyRelayRuntime = RelayService;

#[cfg(not(feature = "legacy-v1"))]
struct LegacyNetworkRuntime;

#[cfg(not(feature = "legacy-v1"))]
struct LegacyRelayRuntime;

#[derive(Debug, thiserror::Error)]
pub enum ServicePolicyError {
    #[error("ordinary-member application payload relay is forbidden by the V4 endpoint path")]
    LegacyPayloadRelayForbidden,

    #[error("connector resource policy is required before enabling node participation")]
    ConnectorPolicyRequired,
}

struct ManagerState {
    config: ServicesConfig,
    stun: Option<StunServerHandle>,
    turn: Option<TurnServerHandle>,
    signaling: Option<SignalingServerHandle>,
    /// One frozen LegacyV1 routing owner per joined network.
    legacy_v1_networks: HashMap<String, LegacyNetworkRuntime>,
    /// One optional frozen LegacyV1 plain-envelope relay per joined network.
    legacy_v1_relays: HashMap<String, LegacyRelayRuntime>,
}

/// Status snapshot for the control protocol / CLI / GUI.
#[derive(Debug, Clone, Serialize)]
pub struct ServicesReport {
    pub node: NodeReport,
    pub relay: RelayReport,
    pub signaling: EndpointReport,
    pub stun: EndpointReport,
    pub turn: EndpointReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeReport {
    pub enabled: bool,
    /// Networks this device has currently joined as a node (0 in
    /// pure-infrastructure mode).
    pub joined: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointReport {
    pub enabled: bool,
    /// True when the listener is actually bound and serving. Differs
    /// from `enabled` when a start failed (e.g. port in use).
    pub running: bool,
    /// The address the listener bound, when running.
    pub listen: Option<String>,
    /// Live activity, for the signaling relay only (None for STUN/TURN).
    /// Lets an operator see at a glance whether peers are reaching it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<RelayStatsSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayReport {
    pub enabled: bool,
    /// Number of networks currently being relayed.
    pub networks: usize,
    pub max_fanout: u32,
}

impl ServiceManager {
    pub fn validate_config(desired: &ServicesConfig) -> Result<(), ServicePolicyError> {
        if desired.relay.enabled {
            return Err(ServicePolicyError::LegacyPayloadRelayForbidden);
        }
        Ok(())
    }

    /// Validate a service configuration against this daemon incarnation.
    ///
    /// An infrastructure-only daemon has no connector owner. It cannot be
    /// changed into a participating node through live configuration because
    /// doing so would otherwise persist a state whose connector attempts can
    /// never be admitted.
    pub fn validate_config_for_runtime(
        &self,
        desired: &ServicesConfig,
    ) -> Result<(), ServicePolicyError> {
        if desired.relay.enabled {
            #[cfg(not(feature = "legacy-v1"))]
            return Err(ServicePolicyError::LegacyPayloadRelayForbidden);
            #[cfg(feature = "legacy-v1")]
            if self.legacy_v1.is_none() {
                return Err(ServicePolicyError::LegacyPayloadRelayForbidden);
            }
        }
        if desired.node.enabled && self.mesh.connector_resource_report().is_none() {
            return Err(ServicePolicyError::ConnectorPolicyRequired);
        }
        Ok(())
    }

    pub fn new(mesh: MeshHandle, registry: Arc<NetworkRegistry>) -> Arc<Self> {
        Arc::new(Self {
            mesh,
            registry,
            state: Mutex::new(ManagerState {
                config: ServicesConfig::default(),
                stun: None,
                turn: None,
                signaling: None,
                legacy_v1_networks: HashMap::new(),
                legacy_v1_relays: HashMap::new(),
            }),
            #[cfg(feature = "legacy-v1")]
            legacy_v1: None,
        })
    }

    #[cfg(feature = "legacy-v1")]
    #[allow(
        deprecated,
        reason = "this constructor is the explicit frozen LegacyV1 boundary"
    )]
    pub fn new_with_legacy_v1(
        mesh: MeshHandle,
        registry: Arc<NetworkRegistry>,
        runtime: LegacyV1Runtime,
    ) -> Arc<Self> {
        Arc::new(Self {
            mesh,
            registry,
            state: Mutex::new(ManagerState {
                config: ServicesConfig::default(),
                stun: None,
                turn: None,
                signaling: None,
                legacy_v1_networks: HashMap::new(),
                legacy_v1_relays: HashMap::new(),
            }),
            legacy_v1: Some(runtime),
        })
    }

    /// Reconcile running services against `desired`. Starts newly-enabled
    /// or reconfigured services, stops disabled ones, rebuilds the LegacyV1
    /// member-forwarder set from the current network registry, and refreshes capability
    /// adverts. Returns the resulting status. Per-service start failures
    /// are logged, not propagated.
    pub async fn apply(
        &self,
        desired: ServicesConfig,
    ) -> Result<ServicesReport, ServicePolicyError> {
        self.validate_config_for_runtime(&desired)?;
        let mut g = self.state.lock().await;

        // ---- Node participation ----
        // Toggling node membership joins or leaves every configured
        // network. Handle it first so the relay rebuild below sees the
        // resulting registry membership.
        if g.config.node.enabled && !desired.node.enabled {
            info!("node participation disabled — leaving all networks (pure-infra mode)");
            g.legacy_v1_networks.clear();
            g.legacy_v1_relays.clear();
            leave_all(&self.registry).await;
        } else if !g.config.node.enabled && desired.node.enabled {
            info!("node participation enabled — joining configured networks");
            join_configured(&self.mesh, &self.registry).await;
        }

        // ---- STUN ----
        // A TURN server already answers STUN Binding requests on its own
        // port, so a standalone STUN listener alongside TURN is redundant
        // — and on the default config both want :3478, so it would just
        // fail with "address in use". When both are enabled we fold STUN
        // into TURN: skip the standalone listener entirely (no warning),
        // and report STUN as served-by-TURN rather than a failed start.
        // Turn STUN back on by itself the moment TURN is disabled.
        let run_standalone_stun = desired.stun.enabled && !desired.turn.enabled;
        if g.stun.is_some() != run_standalone_stun
            || g.config.stun != desired.stun
            || g.config.turn != desired.turn
        {
            if let Some(h) = g.stun.take() {
                h.stop();
            }
            if run_standalone_stun {
                match StunServer::start(&desired.stun).await {
                    Ok(h) => g.stun = Some(h),
                    Err(e) => warn!("STUN service failed to start: {e}"),
                }
            } else if desired.stun.enabled && desired.turn.enabled {
                info!(
                    "STUN folded into TURN — TURN answers STUN Binding on the same \
                     port, so the standalone STUN listener isn't needed"
                );
            }
        }

        // ---- TURN ----
        if g.turn.is_some() != desired.turn.enabled || g.config.turn != desired.turn {
            if let Some(h) = g.turn.take() {
                let _ = h.stop().await;
            }
            if desired.turn.enabled {
                match TurnServer::start(&desired.turn).await {
                    Ok(h) => g.turn = Some(h),
                    Err(e) => warn!("TURN service failed to start: {e}"),
                }
            }
        }

        // ---- Signaling ----
        if g.signaling.is_some() != desired.signaling.enabled
            || g.config.signaling != desired.signaling
        {
            if let Some(h) = g.signaling.take() {
                h.stop();
            }
            if desired.signaling.enabled {
                match SignalingServer::start(
                    &desired.signaling.bind,
                    desired.signaling.port,
                    desired.signaling.limits.clone(),
                )
                .await
                {
                    Ok(h) => g.signaling = Some(h),
                    Err(e) => warn!("signaling service failed to start: {e}"),
                }
            }
        }

        // ---- Frozen LegacyV1 compatibility owners (per network) ----
        // The topology-routing facade and plain-envelope member relay are
        // separate subscriptions. Each reserved-wire envelope has one
        // semantic consumer.
        g.legacy_v1_networks.clear();
        g.legacy_v1_relays.clear();
        #[cfg(feature = "legacy-v1")]
        if let Some(runtime) = self.legacy_v1.as_ref() {
            for summary in self.registry.summaries() {
                if let Some(joined) = self.registry.get(&summary.config_id) {
                    let network = LegacyNetworkRuntime::bind(runtime, &joined);
                    if desired.relay.enabled {
                        let relay = LegacyRelayRuntime::start(
                            joined.state(),
                            desired.relay.max_fanout,
                            runtime,
                        );
                        g.legacy_v1_relays.insert(summary.config_id.clone(), relay);
                    }
                    g.legacy_v1_networks.insert(summary.config_id, network);
                }
            }
        }

        g.config = desired;
        self.refresh_adverts_locked(&g);
        let joined = self.registry.summaries().len();
        info!(
            node = g.config.node.enabled,
            joined,
            stun = g.stun.is_some(),
            turn = g.turn.is_some(),
            signaling = g.signaling.is_some(),
            legacy_v1_networks = g.legacy_v1_networks.len(),
            legacy_v1_relays = g.legacy_v1_relays.len(),
            "services reconciled"
        );
        Ok(g.report(joined))
    }

    /// Snapshot the current service status without changing anything.
    pub async fn status(&self) -> ServicesReport {
        let joined = self.registry.summaries().len();
        self.state.lock().await.report(joined)
    }

    /// The currently-applied config (for persistence round-trips).
    pub async fn current_config(&self) -> ServicesConfig {
        self.state.lock().await.config.clone()
    }

    /// Hook for when a network joins after services were applied: start its
    /// frozen LegacyV1 routing owner and optional member relay, then push the
    /// current advert.
    pub async fn on_network_added(&self, config_id: &str) {
        #[cfg(feature = "legacy-v1")]
        {
            let mut g = self.state.lock().await;
            let (enabled, fanout) = (g.config.relay.enabled, g.config.relay.max_fanout);
            if let Some(joined) = self.registry.get(config_id) {
                let Some(runtime) = self.legacy_v1.as_ref() else {
                    warn!("legacy compatibility enablement has no LegacyV1 runtime");
                    self.refresh_adverts_locked(&g);
                    return;
                };
                if !g.legacy_v1_networks.contains_key(config_id) {
                    let network = LegacyNetworkRuntime::bind(runtime, &joined);
                    g.legacy_v1_networks.insert(config_id.to_string(), network);
                }
                if enabled && !g.legacy_v1_relays.contains_key(config_id) {
                    let relay = LegacyRelayRuntime::start(joined.state(), fanout, runtime);
                    g.legacy_v1_relays.insert(config_id.to_string(), relay);
                }
            }
            self.refresh_adverts_locked(&g);
        }
        #[cfg(not(feature = "legacy-v1"))]
        {
            let _ = config_id;
            let g = self.state.lock().await;
            self.refresh_adverts_locked(&g);
        }
    }

    /// Hook for when a network leaves: drop both compatibility owners.
    pub async fn on_network_removed(&self, config_id: &str) {
        let mut g = self.state.lock().await;
        g.legacy_v1_networks.remove(config_id);
        g.legacy_v1_relays.remove(config_id);
    }

    /// Stop every running service. Called on daemon shutdown.
    pub async fn shutdown(&self) {
        let mut g = self.state.lock().await;
        g.legacy_v1_networks.clear();
        g.legacy_v1_relays.clear();
        if let Some(h) = g.stun.take() {
            h.stop();
        }
        if let Some(h) = g.signaling.take() {
            h.stop();
        }
        if let Some(h) = g.turn.take() {
            let _ = h.stop().await;
        }
    }

    /// Push the service-role capability advert to every joined network so
    /// peers see what this device hosts.
    fn refresh_adverts_locked(&self, g: &ManagerState) {
        let advert = build_capability_advert(&g.config);
        for summary in self.registry.summaries() {
            if let Some(joined) = self.registry.get(&summary.config_id) {
                joined.advertise(advert.clone());
            }
        }
        // Touch `mesh` so the field is considered used even on builds
        // where no networks are joined yet; keeps the handle around for
        // future per-device advert needs.
        let _ = &self.mesh;
    }
}

impl ManagerState {
    fn report(&self, joined_networks: usize) -> ServicesReport {
        ServicesReport {
            node: NodeReport {
                enabled: self.config.node.enabled,
                joined: joined_networks,
            },
            relay: RelayReport {
                enabled: self.config.relay.enabled,
                networks: if self.config.relay.enabled {
                    self.legacy_v1_relays.len()
                } else {
                    0
                },
                max_fanout: self.config.relay.max_fanout,
            },
            signaling: EndpointReport {
                enabled: self.config.signaling.enabled,
                running: self.signaling.is_some(),
                listen: self.signaling.as_ref().map(|h| h.local_addr().to_string()),
                activity: self.signaling.as_ref().map(|h| h.stats()),
            },
            stun: {
                // When STUN is folded into TURN (both enabled, no
                // standalone listener) report it as running at TURN's
                // address — STUN Binding genuinely is served there, so an
                // operator shouldn't see it as "enabled but not running".
                let folded =
                    self.config.stun.enabled && self.config.turn.enabled && self.stun.is_none();
                EndpointReport {
                    enabled: self.config.stun.enabled,
                    running: self.stun.is_some() || (folded && self.turn.is_some()),
                    listen: self
                        .stun
                        .as_ref()
                        .map(|h| h.local_addr().to_string())
                        .or_else(|| {
                            folded
                                .then(|| self.turn.as_ref().map(|h| h.local_addr().to_string()))
                                .flatten()
                        }),
                    activity: None,
                }
            },
            turn: EndpointReport {
                enabled: self.config.turn.enabled,
                running: self.turn.is_some(),
                listen: self.turn.as_ref().map(|h| h.local_addr().to_string()),
                activity: None,
            },
        }
    }
}

/// Build the capability advert describing the services this device
/// hosts. Role tags are always set for enabled services so peers can
/// discover the host; concrete endpoint URLs are added only when a
/// public address is known (we use the TURN `public_ip` as the host
/// hint, since an operator who set it has declared the device's routable
/// address).
fn build_capability_advert(config: &ServicesConfig) -> CapabilityAdvert {
    let mut tags = Vec::new();
    if config.relay.enabled {
        #[cfg(feature = "legacy-v1")]
        tags.push(ServiceRole::LegacyV1MemberRelay.tag().to_string());
    }
    if config.signaling.enabled {
        tags.push(ServiceRole::Signaling.tag().to_string());
    }
    if config.stun.enabled {
        tags.push(ServiceRole::Stun.tag().to_string());
    }
    if config.turn.enabled {
        tags.push(ServiceRole::Turn.tag().to_string());
    }

    let host = {
        let h = config.turn.public_ip.trim();
        if h.is_empty() {
            None
        } else {
            Some(h.to_string())
        }
    };
    let mut advert = ServiceAdvert {
        legacy_v1_member_relay: cfg!(feature = "legacy-v1") && config.relay.enabled,
        ..Default::default()
    };
    if let Some(host) = host {
        if config.signaling.enabled {
            advert.signaling_url = Some(format!("ws://{host}:{}", config.signaling.port));
        }
        if config.stun.enabled {
            advert.stun_url = Some(format!("stun:{host}:{}", config.stun.port));
        }
        if config.turn.enabled {
            advert.turn_url = Some(format!("turn:{host}:{}", config.turn.port));
        }
    }

    let mut extra = serde_json::Value::Null;
    advert.write_into_extra(&mut extra);

    CapabilityAdvert {
        tags,
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        max_connections: None,
        extra,
    }
}

/// Join one configured network: bring it up on the mesh, attach the
/// Nostr signaling driver, and register it. Skips networks already in the
/// registry. Shared by daemon startup and the node-enable transition so
/// there's a single join path. Best-effort — a failed join is logged, not
/// fatal.
pub(crate) async fn join_network(
    mesh: &MeshHandle,
    registry: &NetworkRegistry,
    cfg: NetworkConfig,
) {
    if registry.contains(&cfg.id) || registry.contains(&cfg.network_id) {
        return;
    }
    match mesh.join(cfg.clone()).await {
        Ok(joined) => {
            let drivers = myownmesh_core::engine::attach_signaling(&joined.state());
            if drivers.is_none() {
                warn!(network = %cfg.network_id, "signaling attach returned no handle");
            }
            registry.insert(joined, drivers);
            info!(network = %cfg.network_id, "joined network");
        }
        Err(e) => warn!(network = %cfg.network_id, "join failed: {e:#}"),
    }
}

/// Join every network in the on-disk config — the node-enable transition.
async fn join_configured(mesh: &MeshHandle, registry: &NetworkRegistry) {
    let cfg = match MeshConfig::load() {
        Ok(c) => c,
        Err(e) => {
            warn!("load config for node join: {e}");
            return;
        }
    };
    for net in cfg.networks {
        join_network(mesh, registry, net).await;
    }
}

/// Leave every joined network — the node-disable transition.
async fn leave_all(registry: &NetworkRegistry) {
    // Announce a graceful departure first so peers drop our sessions now
    // instead of waiting out their heartbeat timeout (~90 s) — without it,
    // disabling the node leaves us showing online-but-unconnectable on every
    // peer for over a minute.
    registry.announce_all_departures().await;
    for net in registry.take_all() {
        if let Err(e) = net.leave().await {
            warn!("leave failed: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::services::ServiceAdvert;

    #[test]
    fn advert_tags_track_enabled_services() {
        let mut cfg = ServicesConfig::default();
        cfg.signaling.enabled = true;
        cfg.turn.enabled = true;
        let advert = build_capability_advert(&cfg);
        assert!(advert.tags.contains(&"service:signaling".to_string()));
        assert!(advert.tags.contains(&"service:turn".to_string()));
        assert!(!advert.tags.contains(&"service:stun".to_string()));
    }

    #[test]
    fn advert_endpoints_use_turn_public_ip_as_host() {
        let mut cfg = ServicesConfig::default();
        cfg.signaling.enabled = true;
        cfg.turn.enabled = true;
        cfg.turn.public_ip = "203.0.113.9".into();
        let advert = build_capability_advert(&cfg);
        let svc = ServiceAdvert::from_extra(&advert.extra).unwrap();
        assert_eq!(
            svc.signaling_url.as_deref(),
            Some(format!("ws://203.0.113.9:{}", cfg.signaling.port).as_str())
        );
        assert_eq!(svc.turn_url.as_deref(), Some("turn:203.0.113.9:3478"));
    }

    #[test]
    fn advert_without_public_ip_has_tags_but_no_urls() {
        let mut cfg = ServicesConfig::default();
        cfg.signaling.enabled = true;
        let advert = build_capability_advert(&cfg);
        // Role tag present...
        assert!(advert.tags.contains(&"service:signaling".to_string()));
        // ...but no URL since we don't know a reachable host.
        assert_eq!(ServiceAdvert::from_extra(&advert.extra), None);
    }

    #[test]
    fn v4_daemon_policy_rejects_ordinary_member_payload_relay() {
        let mut cfg = ServicesConfig::default();
        cfg.relay.enabled = true;

        assert!(matches!(
            ServiceManager::validate_config(&cfg),
            Err(ServicePolicyError::LegacyPayloadRelayForbidden)
        ));
    }

    #[tokio::test]
    async fn infrastructure_runtime_rejects_later_node_enable_without_mutation() {
        let identity = Arc::new(myownmesh_core::Identity::ephemeral());
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            MeshConfig::default(),
            identity,
        )
        .await
        .expect("open infrastructure-only mesh");
        let registry = NetworkRegistry::new();
        let manager = ServiceManager::new(mesh, registry);
        let mut infrastructure = ServicesConfig::default();
        infrastructure.node.enabled = false;
        manager
            .apply(infrastructure.clone())
            .await
            .expect("disable node participation");

        let mut attempted = infrastructure;
        attempted.node.enabled = true;
        assert!(matches!(
            manager.apply(attempted).await,
            Err(ServicePolicyError::ConnectorPolicyRequired)
        ));
        assert!(!manager.current_config().await.node.enabled);
    }

    #[cfg(feature = "legacy-v1")]
    #[allow(
        deprecated,
        reason = "this is the positive control for the frozen LegacyV1 daemon and Channel path"
    )]
    #[tokio::test]
    async fn legacy_v1_runtime_explicitly_enables_one_daemon_channel_relay() {
        use std::num::NonZeroUsize;

        let one = NonZeroUsize::new(1).expect("fixture value is nonzero");
        let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
            myownmesh_core::ConnectorCallbackMailboxCapacities::new(one, one),
            myownmesh_core::ConnectorCallbackServiceWeights::data_only(one, one),
            myownmesh_core::RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture data-only callback policy is valid");
        let webrtc = myownmesh_core::WebRtcConnectorProfile::new(
            callbacks,
            myownmesh_core::PendingRemoteCandidatePolicy::new(one, one, one, one),
        );
        let policy = myownmesh_core::WebRtcConnectorCapablePolicy::new(
            crate::test_resource_provider(),
            webrtc,
        );
        let mesh = myownmesh_core::Mesh::open_connector_capable_with_identity(
            MeshConfig::default(),
            Arc::new(myownmesh_core::Identity::ephemeral()),
            policy,
        )
        .await
        .expect("open explicitly bounded compatibility fixture");
        let joined = mesh
            .join(NetworkConfig {
                id: "legacy-v1-positive".to_string(),
                network_id: "legacy-v1-positive".to_string(),
                label: "LegacyV1 positive control".to_string(),
                kind: Default::default(),
                topology: Default::default(),
                signaling: Default::default(),
                stun_servers: Vec::new(),
                turn_servers: Vec::new(),
                roster_path: None,
                pinned_peers: Vec::new(),
                auto_approve: false,
            })
            .await
            .expect("join one compatibility network");
        let registry = NetworkRegistry::new();
        registry.insert(joined, None);
        let manager = ServiceManager::new_with_legacy_v1(
            mesh,
            Arc::clone(&registry),
            LegacyV1Runtime::frozen(),
        );
        manager
            .apply(ServicesConfig::default())
            .await
            .expect("explicit runtime installs routing without relay hosting");
        {
            let state = manager.state.lock().await;
            assert_eq!(state.legacy_v1_networks.len(), 1);
            assert!(state.legacy_v1_relays.is_empty());
        }
        let mut desired = ServicesConfig::default();
        desired.relay.enabled = true;
        let report = manager
            .apply(desired)
            .await
            .expect("explicit runtime admits the frozen relay path");
        tokio::task::yield_now().await;
        assert!(report.relay.enabled);
        assert_eq!(report.relay.networks, 1);
        {
            let state = manager.state.lock().await;
            assert_eq!(state.legacy_v1_networks.len(), 1);
            assert_eq!(state.legacy_v1_relays.len(), 1);
        }

        manager.shutdown().await;
        for joined in registry.take_all() {
            joined
                .leave()
                .await
                .expect("fixture network leaves cleanly");
        }
    }
}
