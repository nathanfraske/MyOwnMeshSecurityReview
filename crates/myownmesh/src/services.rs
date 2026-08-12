//! Daemon-side lifecycle for the infrastructure services a device hosts
//! for the mesh: the self-hosted signaling relay, and the STUN / TURN
//! servers.
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

use std::sync::Arc;

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
}

/// Why a service configuration was refused.
///
/// A second variant used to sit here, refusing any configuration that enabled
/// ordinary-member application payload relay. There is no longer a
/// configuration that can ask for it: the key is gone from `ServicesConfig`, so
/// the refusal has nothing left to refuse and the exclusion is now structural.
/// See `no_service_configuration_can_advertise_a_member_payload_relay`.
#[derive(Debug, thiserror::Error)]
pub enum ServicePolicyError {
    #[error("connector resource policy is required before enabling node participation")]
    ConnectorPolicyRequired,
}

struct ManagerState {
    config: ServicesConfig,
    stun: Option<StunServerHandle>,
    turn: Option<TurnServerHandle>,
    signaling: Option<SignalingServerHandle>,
}

/// Status snapshot for the control protocol / CLI / GUI.
#[derive(Debug, Clone, Serialize)]
pub struct ServicesReport {
    pub node: NodeReport,
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

// There is no member-payload-relay report.
//
// It carried `enabled`, a relayed-network count, and a fanout ceiling for a
// service an ordinary member could host to forward other members' application
// payload. Nothing publishes it now: the configuration key, the runtime, the
// service role, and the advert field are all gone, so a status field would be a
// permanent `false` describing a service the daemon has no way to run.

impl ServiceManager {
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
            }),
        })
    }

    /// Reconcile running services against `desired`. Starts newly-enabled
    /// or reconfigured services, stops disabled ones, and refreshes capability
    /// adverts. Returns the resulting status. Per-service start failures
    /// are logged, not propagated.
    pub async fn apply(
        &self,
        desired: ServicesConfig,
    ) -> Result<ServicesReport, ServicePolicyError> {
        self.validate_config_for_runtime(&desired)?;
        let mut g = self.state.lock().await;

        // ---- Node participation ----
        // Toggling node membership joins or leaves every configured network.
        if g.config.node.enabled && !desired.node.enabled {
            info!("node participation disabled — leaving all networks (pure-infra mode)");
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

        g.config = desired;
        self.refresh_adverts_locked(&g);
        let joined = self.registry.summaries().len();
        info!(
            node = g.config.node.enabled,
            joined,
            stun = g.stun.is_some(),
            turn = g.turn.is_some(),
            signaling = g.signaling.is_some(),
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

    /// Hook for when a network joins after services were applied: push the
    /// current advert onto it.
    ///
    /// Nothing per-network is started here any more. The two owners this hook
    /// used to bind — a routing facade and a plain-envelope member relay — were
    /// the only per-network service runtimes, and both are gone; the surviving
    /// services (signaling, STUN, TURN) are device-wide listeners.
    pub async fn on_network_added(&self, config_id: &str) {
        let _ = config_id;
        let g = self.state.lock().await;
        self.refresh_adverts_locked(&g);
    }

    /// Hook for when a network leaves. No per-network service runtime exists to
    /// drop; kept so the registry has one symmetric departure notification.
    pub async fn on_network_removed(&self, config_id: &str) {
        let _ = config_id;
    }

    /// Stop every running service. Called on daemon shutdown.
    pub async fn shutdown(&self) {
        let mut g = self.state.lock().await;
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
                // Reported per network and never aborts the sweep: the refusals
                // are per-network, so one network that would not take the new
                // advert must not stop the rest from getting it. A network that
                // refuses keeps publishing its previous roles, which is a
                // divergence between what this device hosts and what its peers
                // believe — worth a warning even though there is no caller here
                // to return it to.
                if let Err(error) = joined.advertise(advert.clone()) {
                    warn!(
                        network = %summary.config_id,
                        "service-role advert was refused; this network still \
                         publishes its previous roles: {error}"
                    );
                }
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
    // Every role a device can advertise is here. There is no member-relay tag
    // because there is no such role to offer — see
    // `no_service_configuration_can_advertise_a_member_payload_relay`.
    let mut tags = Vec::new();
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
    let mut advert = ServiceAdvert::default();
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
            // Attach is now fallible, and a refusal is not the same event as
            // the receiver having been taken. A network that joined but could
            // not attach is unreachable, so it is taken back down rather than
            // registered — the same disposal the id-refusal path below performs
            // — instead of being left running as a network nothing can signal
            // through. This stays best-effort per this function's contract:
            // neither caller (daemon startup, the node-enable transition) has
            // anywhere to return a per-network failure to.
            let attached = {
                let net_state = joined.state();
                myownmesh_core::engine::attach_signaling(&net_state)
            };
            let drivers = match attached {
                Ok(drivers) => drivers,
                Err(error) => {
                    warn!(network = %cfg.network_id, "signaling attach failed: {error}");
                    if let Err(e) = joined.shutdown().await {
                        warn!(
                            network = %cfg.network_id,
                            "network with no signaling failed to shut down: {e:#}"
                        );
                    }
                    return;
                }
            };
            if drivers.is_none() {
                warn!(
                    network = %cfg.network_id,
                    "signaling outbound receiver was already taken — \
                     this network keeps no driver handle"
                );
            }
            // The `contains` check above is advisory — it is a separate lock
            // acquisition from the insert, so a join racing a removal or
            // another join can still arrive at a held id. The registry decides
            // under its own state lock, and it hands the network back rather
            // than dropping it, so a refusal is shut down here instead of being
            // left running with nothing able to name it.
            if let Some(refused) = registry.insert(joined, drivers).into_refusal() {
                warn!(
                    network = %cfg.network_id,
                    state = ?refused.state,
                    "join refused: that id is held by a runtime that has not stopped"
                );
                drop(refused.drivers);
                if let Err(e) = refused.joined.shutdown().await {
                    warn!(network = %cfg.network_id, "refused join failed to shut down: {e:#}");
                }
                return;
            }
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
    // Every distinct network, none skipped. This is the node-disable
    // transition, so a network the previous drain could not take sole
    // ownership of stayed running while the node reported itself disabled.
    for outcome in registry.shutdown_all().await {
        if let Err(e) = outcome {
            warn!("network shutdown failed: {e}");
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

    /// No service configuration reaches a member payload relay.
    ///
    /// This used to be a refusal: a config could ask for `relay.enabled` and
    /// the daemon answered with an error. The key is now gone from
    /// `ServicesConfig`, so the stronger claim is available and is what this
    /// asserts — with *every* service a device can host turned on, nothing the
    /// daemon offers peers names a payload relay. A peer reading this advert
    /// has no way to select this device as a hop for another member's data.
    ///
    /// Non-vacuous by construction: the same advert must carry the three roles
    /// that do exist, so a build that stopped advertising anything at all fails
    /// here rather than passing as "no relay".
    #[test]
    fn no_service_configuration_can_advertise_a_member_payload_relay() {
        let mut cfg = ServicesConfig::default();
        cfg.node.enabled = true;
        cfg.signaling.enabled = true;
        cfg.stun.enabled = true;
        cfg.turn.enabled = true;
        cfg.turn.public_ip = "203.0.113.9".into();

        let advert = build_capability_advert(&cfg);
        assert_eq!(
            advert.tags,
            vec![
                "service:signaling".to_string(),
                "service:stun".to_string(),
                "service:turn".to_string(),
            ],
            "the roles a device can host are exactly these three"
        );
        let published = serde_json::to_string(&advert).expect("advert serializes");
        assert!(
            !published.contains("relay"),
            "nothing published to peers may name a relay: {published}"
        );
    }

    #[tokio::test]
    async fn infrastructure_runtime_rejects_later_node_enable_without_mutation() {
        let identity = Arc::new(myownmesh_core::Identity::ephemeral());
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            MeshConfig::default(),
            identity,
            crate::test_resource_provider(),
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

    /// A running daemon reports no member payload relay authority.
    ///
    /// The refusal this replaces asked the manager to enable `relay` and
    /// checked the error. That request is now unrepresentable, so what is left
    /// to prove is the other half: a live manager's published status describes
    /// no relay it could be asked about. A client cannot read a relay state off
    /// this daemon, because it has none to report.
    ///
    /// Asserted on a real running manager rather than on the report type,
    /// because the claim is about what a daemon serving the control socket
    /// actually says, not about which fields a struct happens to declare.
    #[tokio::test]
    async fn a_running_daemon_reports_no_member_payload_relay_authority() {
        let identity = Arc::new(myownmesh_core::Identity::ephemeral());
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            MeshConfig::default(),
            identity,
            crate::test_resource_provider(),
        )
        .await
        .expect("open infrastructure-only mesh");
        let manager = ServiceManager::new(mesh, NetworkRegistry::new());

        let mut infrastructure = ServicesConfig::default();
        infrastructure.node.enabled = false;
        manager
            .apply(infrastructure)
            .await
            .expect("an infrastructure-only config applies");

        let status = serde_json::to_string(&manager.status().await).expect("status serializes");
        assert!(
            status.contains("\"signaling\"") && status.contains("\"turn\""),
            "the status must still describe the services that do exist: {status}"
        );
        assert!(
            !status.contains("relay"),
            "a running daemon publishes no relay state: {status}"
        );
    }
}
