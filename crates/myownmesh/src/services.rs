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
use tokio::sync::{Mutex, MutexGuard};
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
/// A former policy check referred to ordinary-member application-payload
/// relay. That capability is not part of the hosted-services
/// configuration/status/advertisement namespace: `ServicesConfig` exposes the
/// signaling relay, STUN, and TURN services only, so there is no such request
/// for this error to refuse.
#[derive(Debug, thiserror::Error)]
pub enum ServicePolicyError {
    #[error("connector resource policy is required before enabling node participation")]
    ConnectorPolicyRequired,
}

/// Terminal failures observed while stopping hosted services.
///
/// Every stop is still attempted in the prescribed order; the aggregate is
/// returned only after all owned handles have reached their terminal boundary.
#[derive(Debug, thiserror::Error)]
#[error("hosted service shutdown failed: {failures:?}")]
pub struct ServiceShutdownError {
    pub failures: Vec<ServiceShutdownFailure>,
}

#[derive(Debug)]
pub struct ServiceShutdownFailure {
    pub service: &'static str,
    pub error: String,
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

/// One coherently observed services-status source. It owns the sole manager
/// guard, measures only borrowed/Copy fields, and can be committed exactly once
/// after the caller has acquired its returned claim.
pub(crate) struct ServicesStatusSource<'a> {
    state: MutexGuard<'a, ManagerState>,
    captured: CapturedServicesReport,
}

struct CapturedServicesReport {
    node_enabled: bool,
    joined: usize,
    signaling: CapturedEndpoint,
    stun: CapturedEndpoint,
    turn: CapturedEndpoint,
}

struct CapturedEndpoint {
    enabled: bool,
    running: bool,
    listen: Option<std::net::SocketAddr>,
    activity: Option<RelayStatsSnapshot>,
}

pub(crate) struct FundedServicesStatus {
    report: ServicesReport,
    config: ServicesConfig,
    _retention: myownmesh_core::ResourceLease,
}

impl FundedServicesStatus {
    pub(crate) fn report(&self) -> &ServicesReport {
        &self.report
    }

    pub(crate) fn config(&self) -> &ServicesConfig {
        &self.config
    }
}

#[derive(Serialize)]
struct ServicesStatusView<'a> {
    status: ServicesReportView,
    config: &'a ServicesConfig,
}

#[derive(Serialize)]
struct ServicesReportView {
    node: NodeReport,
    signaling: EndpointReportView,
    stun: EndpointReportView,
    turn: EndpointReportView,
}

#[derive(Serialize)]
struct EndpointReportView {
    enabled: bool,
    running: bool,
    listen: Option<SocketDisplay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activity: Option<RelayStatsSnapshot>,
}

#[derive(Clone, Copy)]
struct SocketDisplay(std::net::SocketAddr);

impl Serialize for SocketDisplay {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

// The hosted-services report contains node participation plus signaling relay,
// STUN, and TURN endpoint state. It has no separate application-payload relay
// field because that capability is outside this namespace and has no daemon
// runtime or configuration entry.

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
                if let Err(error) = h.stop_and_wait().await {
                    warn!("STUN service failed to stop during reconfiguration: {error}");
                }
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
                if let Err(error) = h.stop_and_wait().await {
                    warn!("signaling service failed to stop during reconfiguration: {error}");
                }
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
        let joined = self.registry.joined_count();
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
    #[cfg(test)]
    pub async fn status(&self) -> ServicesReport {
        self.status_source().await.build_report()
    }

    /// The currently-applied config (for persistence round-trips).
    #[cfg(test)]
    pub async fn current_config(&self) -> ServicesConfig {
        self.state.lock().await.config.clone()
    }

    pub(crate) async fn status_source(&self) -> ServicesStatusSource<'_> {
        let joined = self.registry.joined_count();
        let state = self.state.lock().await;
        let captured = state.capture(joined);
        ServicesStatusSource { state, captured }
    }

    /// Hook for when a network joins after services were applied: push the
    /// current advert onto it.
    ///
    /// Nothing per-network is started here. The hosted signaling relay, STUN,
    /// and TURN services are device-wide listeners; this hook only refreshes
    /// their advertised roles on the newly joined network.
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
    ///
    /// All owned handles are consumed and awaited before returning. A failure
    /// is retained as a typed terminal result instead of being discarded as
    /// if the service had stopped cleanly.
    pub async fn shutdown(&self) -> Result<(), ServiceShutdownError> {
        let mut g = self.state.lock().await;
        let mut failures = Vec::new();
        if let Some(h) = g.stun.take() {
            if let Err(error) = h.stop_and_wait().await {
                warn!("STUN service failed to stop: {error}");
                failures.push(ServiceShutdownFailure {
                    service: "stun",
                    error: error.to_string(),
                });
            }
        }
        if let Some(h) = g.signaling.take() {
            if let Err(error) = h.stop_and_wait().await {
                warn!("signaling service failed to stop: {error}");
                failures.push(ServiceShutdownFailure {
                    service: "signaling",
                    error: error.to_string(),
                });
            }
        }
        if let Some(h) = g.turn.take() {
            if let Err(error) = h.stop().await {
                warn!("TURN service failed to stop: {error}");
                failures.push(ServiceShutdownFailure {
                    service: "turn",
                    error: error.to_string(),
                });
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ServiceShutdownError { failures })
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
        self.capture(joined_networks).build()
    }

    fn capture(&self, joined: usize) -> CapturedServicesReport {
        let folded = self.config.stun.enabled && self.config.turn.enabled && self.stun.is_none();
        let turn_addr = self.turn.as_ref().map(|handle| handle.local_addr());
        CapturedServicesReport {
            node_enabled: self.config.node.enabled,
            joined,
            signaling: CapturedEndpoint {
                enabled: self.config.signaling.enabled,
                running: self.signaling.is_some(),
                listen: self.signaling.as_ref().map(|handle| handle.local_addr()),
                activity: self.signaling.as_ref().map(|handle| handle.stats()),
            },
            stun: CapturedEndpoint {
                enabled: self.config.stun.enabled,
                running: self.stun.is_some() || (folded && self.turn.is_some()),
                listen: self
                    .stun
                    .as_ref()
                    .map(|handle| handle.local_addr())
                    .or_else(|| folded.then_some(turn_addr).flatten()),
                activity: None,
            },
            turn: CapturedEndpoint {
                enabled: self.config.turn.enabled,
                running: self.turn.is_some(),
                listen: turn_addr,
                activity: None,
            },
        }
    }
}

impl ServicesStatusSource<'_> {
    fn view(&self) -> ServicesStatusView<'_> {
        self.captured.view(&self.state.config)
    }
}

impl CapturedServicesReport {
    fn view<'a>(&self, config: &'a ServicesConfig) -> ServicesStatusView<'a> {
        ServicesStatusView {
            status: ServicesReportView {
                node: NodeReport {
                    enabled: self.node_enabled,
                    joined: self.joined,
                },
                signaling: EndpointReportView {
                    enabled: self.signaling.enabled,
                    running: self.signaling.running,
                    listen: self.signaling.listen.map(SocketDisplay),
                    activity: self.signaling.activity,
                },
                stun: EndpointReportView {
                    enabled: self.stun.enabled,
                    running: self.stun.running,
                    listen: self.stun.listen.map(SocketDisplay),
                    activity: self.stun.activity,
                },
                turn: EndpointReportView {
                    enabled: self.turn.enabled,
                    running: self.turn.running,
                    listen: self.turn.listen.map(SocketDisplay),
                    activity: self.turn.activity,
                },
            },
            config,
        }
    }
}

impl ServicesStatusSource<'_> {
    pub(crate) fn typed_claim(
        &self,
    ) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
        serialized_typed_claim::<(ServicesReport, ServicesConfig)>(&self.view())
    }

    pub(crate) fn line_ceiling(&self) -> Result<usize, myownmesh_core::ResourceMailboxItemError> {
        services_status_line_ceiling(&self.view())
    }

    #[cfg(test)]
    fn build_report(&self) -> ServicesReport {
        self.captured.build()
    }

    #[expect(
        clippy::result_large_err,
        reason = "the exact admitted lease must be returned by value; boxing would allocate on refusal"
    )]
    pub(crate) fn commit(
        self,
        retention: myownmesh_core::ResourceLease,
    ) -> Result<FundedServicesStatus, myownmesh_core::ResourceLease> {
        if retention.claim()
            != self
                .typed_claim()
                .expect("a previously measured source remains representable")
        {
            return Err(retention);
        }
        let report = self.captured.build();
        let config = self.state.config.clone();
        Ok(FundedServicesStatus {
            report,
            config,
            _retention: retention,
        })
    }
}

fn serialized_typed_claim<T>(
    value: &impl serde::Serialize,
) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
    let (retained, queued, allocations) = myownmesh_core::mailbox_measure_serialized(value)?;
    let fixed = std::mem::size_of::<T>().checked_add(retained).ok_or(
        myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let fixed = u64::try_from(fixed).map_err(|_| {
        myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let queued = u64::try_from(queued).map_err(|_| {
        myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::QueuedBytes,
        }
    })?;
    let allocations = u64::try_from(allocations)
        .map_err(|_| myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        })?
        .checked_add(1)
        .ok_or(myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        })?;
    Ok(myownmesh_core::ResourceClaim::try_from_entries([
        (myownmesh_core::ResourceClass::AccountedMemoryBytes, fixed),
        (myownmesh_core::ResourceClass::QueuedBytes, queued),
        (myownmesh_core::ResourceClass::ParsingOrCpuWork, queued),
        (
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            allocations,
        ),
    ])?)
}

fn services_status_line_ceiling(
    view: &ServicesStatusView<'_>,
) -> Result<usize, myownmesh_core::ResourceMailboxItemError> {
    let (_, encoded, _) = myownmesh_core::mailbox_measure_serialized(view)?;
    encoded
        .checked_add("{\"ok\":true,\"data\":".len())
        .and_then(|bytes| bytes.checked_add("}\n".len()))
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "services status line length overflowed",
        ))
}

impl CapturedServicesReport {
    fn build(&self) -> ServicesReport {
        fn endpoint(value: &CapturedEndpoint) -> EndpointReport {
            EndpointReport {
                enabled: value.enabled,
                running: value.running,
                listen: value.listen.map(|address| address.to_string()),
                activity: value.activity,
            }
        }
        ServicesReport {
            node: NodeReport {
                enabled: self.node_enabled,
                joined: self.joined,
            },
            signaling: endpoint(&self.signaling),
            stun: endpoint(&self.stun),
            turn: endpoint(&self.turn),
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
    // Every hosted service role is emitted here. The signaling relay is the
    // only relay role in this advert namespace; application-payload relay is
    // not a hosted service role.
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
            let attached = joined.attach_signaling();
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
                if let Some(drivers) = refused.drivers {
                    drivers.shutdown().await;
                }
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
    // Start authenticated departures and teardown together. A silent peer's
    // departure waiter is resolved by shutdown; awaiting announcements first
    // would prevent that cancellation from ever being requested. The carrier
    // hint remains part of each departure future.
    // Every distinct network is included; teardown reports each failure.
    for outcome in registry.shutdown_all_with_departures().await {
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

    /// Hosted-service adverts contain only the configured infrastructure roles.
    /// The signaling relay is advertised as `service:signaling`; no separate
    /// application-payload relay role exists in this namespace.
    ///
    /// Non-vacuous by construction: the advert must carry all three roles that
    /// do exist, so a build that stopped advertising services fails here.
    #[test]
    fn hosted_service_advertises_only_infrastructure_roles() {
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

    /// A running daemon's hosted-services status contains the infrastructure
    /// endpoints and no application-payload relay field.
    ///
    /// Asserted on a real running manager rather than on the report type,
    /// because the claim is about what a daemon serving the control socket
    /// actually says, not about which fields a struct happens to declare.
    #[tokio::test]
    async fn a_running_daemon_reports_hosted_services_only() {
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
            !status.contains("application_payload_relay")
                && !status.contains("member_payload_relay"),
            "hosted-services status has no application-payload relay field: {status}"
        );
    }

    #[test]
    fn services_status_measurement_matches_built_multidigit_folded_projection() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let turn = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3478);
        let captured = CapturedServicesReport {
            node_enabled: false,
            joined: 2,
            signaling: CapturedEndpoint {
                enabled: true,
                running: true,
                listen: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7447)),
                activity: Some(RelayStatsSnapshot {
                    connections: 12,
                    connections_total: 345,
                    rooms: 67,
                    events_relayed: 8901,
                }),
            },
            stun: CapturedEndpoint {
                enabled: true,
                running: true,
                listen: Some(turn),
                activity: None,
            },
            turn: CapturedEndpoint {
                enabled: true,
                running: true,
                listen: Some(turn),
                activity: None,
            },
        };
        let mut config = ServicesConfig::default();
        config.node.enabled = false;
        config.signaling.enabled = true;
        config.stun.enabled = true;
        config.turn.enabled = true;

        let measured = serde_json::to_vec(&captured.view(&config)).expect("borrowed view encodes");
        let report = captured.build();
        #[derive(Serialize)]
        struct Data<'a> {
            status: &'a ServicesReport,
            config: &'a ServicesConfig,
        }
        #[derive(Serialize)]
        struct Envelope<'a> {
            ok: bool,
            data: Data<'a>,
        }
        let built = serde_json::to_vec(&Data {
            status: &report,
            config: &config,
        })
        .expect("built status data encodes");
        let mut full_line = serde_json::to_vec(&Envelope {
            ok: true,
            data: Data {
                status: &report,
                config: &config,
            },
        })
        .expect("full prepared response encodes");
        full_line.push(b'\n');
        let ceiling = services_status_line_ceiling(&captured.view(&config))
            .expect("the full response ceiling is representable");
        assert_eq!(
            ceiling,
            full_line.len(),
            "the planned ceiling is the exact compact response wrapper plus newline"
        );
        assert_eq!(
            measured, built,
            "measurement and one built snapshot are identical"
        );
        assert!(
            std::str::from_utf8(&measured)
                .expect("JSON is UTF-8")
                .contains("\"events_relayed\":8901"),
            "non-vacuity: multi-digit activity participates in the measurement"
        );
        assert_eq!(
            report.stun.listen, report.turn.listen,
            "non-vacuity: folded STUN reports the captured TURN endpoint"
        );

        let absent = CapturedServicesReport {
            node_enabled: true,
            joined: 0,
            signaling: CapturedEndpoint {
                enabled: true,
                running: false,
                listen: None,
                activity: None,
            },
            stun: CapturedEndpoint {
                enabled: true,
                running: false,
                listen: None,
                activity: None,
            },
            turn: CapturedEndpoint {
                enabled: true,
                running: false,
                listen: None,
                activity: None,
            },
        };
        let absent_measured =
            serde_json::to_vec(&absent.view(&config)).expect("borrowed null-listen view encodes");
        let absent_report = absent.build();
        let absent_built = serde_json::to_vec(&Data {
            status: &absent_report,
            config: &config,
        })
        .expect("built null-listen status data encodes");
        let mut absent_full_line = serde_json::to_vec(&Envelope {
            ok: true,
            data: Data {
                status: &absent_report,
                config: &config,
            },
        })
        .expect("full null-listen prepared response encodes");
        absent_full_line.push(b'\n');
        let absent_ceiling = services_status_line_ceiling(&absent.view(&config))
            .expect("the null-listen response ceiling is representable");
        assert_eq!(
            absent_ceiling,
            absent_full_line.len(),
            "the null-listen plan covers the exact compact wrapper plus newline"
        );
        assert_eq!(
            absent_measured, absent_built,
            "the borrowed and built projections both retain explicit null listeners"
        );
        assert_eq!(
            std::str::from_utf8(&absent_measured)
                .expect("JSON is UTF-8")
                .matches("\"listen\":null")
                .count(),
            3,
            "all three absent endpoints preserve the public listen:null contract"
        );
    }
}
