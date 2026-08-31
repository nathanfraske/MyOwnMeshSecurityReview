use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::NetworkConfig;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::protocol::{FactBundleMessage, MeshMessage};
use crate::resource::{LocalApplicationResourceScope, MeshRuntimeResourceScope};
use crate::semantic::{
    BootstrapRecord, ClosedProfileId, DeviceId, ExpectedMeshContext, MeshContextId, SignedFact,
    VerifiedBootstrap, VerifiedProjectPolicy,
};
use crate::transport::Transport;

use super::state::NetworkState;

#[cfg(feature = "transport-lab")]
use crate::resource::ProcessResourceRoot;

/// Spawn the engine for a single joined network. Returns the
/// shared [`NetworkState`] handle plus the join handle of the
/// driver task (waitable for clean shutdown).
#[cfg(feature = "transport-lab")]
pub(crate) async fn spawn_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    spawn_network_impl(config, identity, transport).await
}

#[cfg(feature = "transport-lab")]
async fn spawn_network_impl(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = bootstrap_for_spawn(&config, None)?;
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    let local_resources = ProcessResourceRoot::global().issue_local_application_scope()?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        &mesh_scope,
        &local_resources,
        bootstrap,
        None,
    )
    .await
}

/// Create and durably install the local Closed bootstrap before exposing an
/// engine for it. The creation id is caller-owned semantic input; the local
/// signing key is the only authority root accepted by this profile.
#[cfg(feature = "transport-lab")]
pub(crate) async fn create_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    create_network_impl(config, identity, transport, creation_id).await
}

#[cfg(feature = "transport-lab")]
async fn create_network_impl(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = create_local_bootstrap(&config, &identity, None, creation_id)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, None, bootstrap).await
}

/// Transport-lab variant of [`create_network`] with instance-owned bootstrap
/// persistence. The record is verified and durably installed before the
/// engine becomes observable, so a second node can import the exact same
/// semantic context into a distinct root.
#[cfg(feature = "transport-lab")]
pub(crate) async fn create_network_in_instance_root(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    root: PathBuf,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = create_local_bootstrap(&config, &identity, Some(root.as_path()), creation_id)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, Some(root), bootstrap).await
}

/// Import and durably install a caller-provided bootstrap only after it has
/// matched the locally expected semantic context. The expected context id is
/// an import constraint, never a replacement for record verification.
#[cfg(feature = "transport-lab")]
pub(crate) async fn import_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    import_network_impl(config, identity, transport, expected_context_id, record).await
}

#[cfg(feature = "transport-lab")]
async fn import_network_impl(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = import_local_bootstrap(&config, None, expected_context_id, record)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, None, bootstrap).await
}

/// Transport-lab variant of [`import_network`] that verifies and persists the
/// supplied record below one explicit instance root before exposing the
/// imported engine.
#[cfg(feature = "transport-lab")]
pub(crate) async fn import_network_in_instance_root(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    root: PathBuf,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap =
        import_local_bootstrap(&config, Some(root.as_path()), expected_context_id, record)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, Some(root), bootstrap).await
}

/// Spawn a transport-lab node with instance-owned on-disk projections.
///
/// The supplied root is local custody only: the config's wire-level
/// `network_id` is preserved exactly. The root is passed through a private
/// constructor seam, which derives the normal `states/` and `rosters/`
/// layouts. Ordinary production callers continue through [`spawn_network`]
/// and retain the default root.
#[cfg(feature = "transport-lab")]
pub(crate) async fn spawn_network_in_instance_root(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    root: std::path::PathBuf,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = bootstrap_for_spawn(&config, Some(root.as_path()))?;
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    let local_resources = ProcessResourceRoot::global().issue_local_application_scope()?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        &mesh_scope,
        &local_resources,
        bootstrap,
        Some(root),
    )
    .await
}

pub(crate) async fn spawn_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = bootstrap_for_spawn(&config, None)?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        mesh_scope,
        local_resources,
        bootstrap,
        None,
    )
    .await
}

/// Create a Closed network below the already-issued Mesh scopes.
///
/// This is the handle facade's only creation seam. Keeping bootstrap
/// verification and driver construction below the caller's exact scopes means
/// creation cannot silently install a second process authority owner.
pub(crate) async fn create_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = create_local_bootstrap(&config, &identity, None, creation_id)?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        mesh_scope,
        local_resources,
        bootstrap,
        None,
    )
    .await
}

/// Import a Closed network below the already-issued Mesh scopes.
///
/// The expected context is an import constraint; the persisted record remains
/// the authority-bearing input and is verified before the driver is exposed.
pub(crate) async fn import_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = import_local_bootstrap(&config, None, expected_context_id, record)?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        mesh_scope,
        local_resources,
        bootstrap,
        None,
    )
    .await
}

#[cfg(feature = "transport-lab")]
async fn spawn_network_with_verified_bootstrap(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    instance_root: Option<PathBuf>,
    bootstrap: VerifiedBootstrap,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    let local_resources = ProcessResourceRoot::global().issue_local_application_scope()?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        &mesh_scope,
        &local_resources,
        bootstrap,
        instance_root,
    )
    .await
}

async fn spawn_network_in_mesh_scope_with_verified_bootstrap(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
    bootstrap: VerifiedBootstrap,
    instance_root: Option<std::path::PathBuf>,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let (state, signaling_inbound_rx, cmd_rx) = NetworkState::new_in_mesh_scope_with_instance_root(
        config,
        identity,
        transport,
        bootstrap,
        mesh_scope,
        local_resources,
        instance_root,
    )?;
    let driver_state = state.clone();
    let handle = tokio::spawn(async move {
        super::run_driver(driver_state, signaling_inbound_rx, cmd_rx).await;
    });
    Ok((state, handle))
}

/// Explicitly join the local Open lifecycle at the low-level engine seam.
///
/// Authentication and carrier presence never author participation. A fresh
/// Open network joins once; a persisted negative participation head re-enters
/// through the causal rejoin API; an already-positive head is left untouched.
/// Closed networks have no local Open lifecycle fact to manufacture.
pub(crate) async fn join_open_participation(state: &Arc<NetworkState>) -> Result<()> {
    join_open_participation_impl(state).await
}

async fn join_open_participation_impl(state: &Arc<NetworkState>) -> Result<()> {
    if !matches!(
        state.verified_bootstrap().policy(),
        VerifiedProjectPolicy::Open
    ) {
        return Ok(());
    }
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|error| Error::Other(format!("local Open identity is not canonical: {error}")))?;
    let participation = {
        let graph = state.authoritative_fact_graph();
        let graph = graph.read();
        graph.evaluator().effective_open_participation(&local)
    };
    match participation {
        Some(true) => Ok(()),
        Some(false) => super::governance::rejoin_open_participation(state)
            .await
            .map(|_| ()),
        None => super::governance::join_open_participation(state)
            .await
            .map(|_| ()),
    }
}

/// Ingest one authenticated canonical fact through the production semantic
/// reducer. Carrier/session identity is deliberately absent: the signed fact
/// supplies its own authority and the reducer supplies durable admission,
/// quarantine custody, projection, and broadcast ordering.
pub(crate) async fn ingest_semantic_fact(state: &Arc<NetworkState>, fact: SignedFact) {
    let Ok(exchange) = super::semantic_ingress::DurableSemanticPort::admit(MeshMessage::Fact(fact))
    else {
        return;
    };
    super::semantic_ingress::reduce(state, exchange, None).await;
}

/// Import a verified bundle of canonical facts through the same durable
/// semantic reducer used by wire delivery.
///
/// This is a bootstrap/repair seam, not an authority seam: signatures and
/// canonical content are checked before framing, while authorization,
/// dependency quarantine, custody, and projection remain exclusively owned by
/// the bootstrap-bound `FactGraph` and durable semantic owner. Success means
/// the bundle was accepted by the durable reducer; individual facts may still
/// be quarantined until their dependencies arrive.
pub(crate) async fn import_signed_facts(
    state: &Arc<NetworkState>,
    facts: Vec<SignedFact>,
) -> Result<()> {
    if facts.is_empty() {
        return Err(Error::Other("signed fact import cannot be empty".into()));
    }
    let expected_context = state.mesh_context_id();
    for fact in &facts {
        if fact.content.mesh_context != expected_context {
            return Err(Error::Other(format!(
                "signed fact {} belongs to a foreign mesh context",
                fact.id
            )));
        }
        fact.verify()
            .map_err(|error| Error::Other(format!("signed fact {} rejected: {error}", fact.id)))?;
    }
    let exchange = super::semantic_ingress::DurableSemanticPort::admit(MeshMessage::FactBundle(
        FactBundleMessage { facts },
    ))
    .map_err(|_| Error::Other("signed fact bundle was not a durable exchange".into()))?;
    super::semantic_ingress::reduce(state, exchange, None).await;
    Ok(())
}

fn bootstrap_root(instance_root: Option<&Path>) -> Result<PathBuf> {
    match instance_root {
        Some(root) => Ok(root.to_path_buf()),
        None => Ok(crate::dirs::data_dir()?.join("mesh")),
    }
}

fn bootstrap_store(
    config: &NetworkConfig,
    instance_root: Option<&Path>,
) -> Result<crate::semantic::store::BootstrapStore> {
    Ok(crate::semantic::store::BootstrapStore::new(
        bootstrap_root(instance_root)?,
        &config.id,
    ))
}

fn local_bootstrap_principal() -> crate::application_gateway::LocalPrincipalCapability {
    crate::application_gateway::LocalPrincipalCapability::for_local_process(
        crate::runtime::RuntimeIncarnation::new(),
    )
}

fn bootstrap_error(action: &str, error: impl std::fmt::Display) -> Error {
    Error::Other(format!("{action} bootstrap: {error}"))
}

fn ensure_bootstrap_for_config(
    config: &NetworkConfig,
    bootstrap: VerifiedBootstrap,
) -> Result<VerifiedBootstrap> {
    if bootstrap.context().scope != config.network_id {
        return Err(bootstrap_error(
            "rejecting",
            format!(
                "semantic scope {} does not match network_id {}",
                bootstrap.context().scope,
                config.network_id
            ),
        ));
    }

    let valid_shape = match config.kind {
        crate::config::NetworkKind::Closed => matches!(
            bootstrap.policy(),
            VerifiedProjectPolicy::Closed(policy)
                if policy.profile() == ClosedProfileId::SingleRootSignedMemberLogV1
        ),
        crate::config::NetworkKind::Open | crate::config::NetworkKind::Silent => {
            matches!(bootstrap.policy(), VerifiedProjectPolicy::Open)
        }
    };
    if !valid_shape {
        return Err(bootstrap_error(
            "rejecting",
            format!(
                "bootstrap policy does not match configured kind {:?}",
                config.kind
            ),
        ));
    }
    Ok(bootstrap)
}

fn bootstrap_for_spawn(
    config: &NetworkConfig,
    instance_root: Option<&Path>,
) -> Result<VerifiedBootstrap> {
    let bootstrap = match config.kind {
        crate::config::NetworkKind::Open | crate::config::NetworkKind::Silent => {
            VerifiedBootstrap::open(config.network_id.clone())
                .map_err(|error| bootstrap_error("creating founderless", error))?
        }
        crate::config::NetworkKind::Closed => bootstrap_store(config, instance_root)?
            .restore()
            .map_err(|error| bootstrap_error("restoring Closed", error))?,
    };
    ensure_bootstrap_for_config(config, bootstrap)
}

fn create_local_bootstrap(
    config: &NetworkConfig,
    identity: &Identity,
    instance_root: Option<&Path>,
    creation_id: [u8; 32],
) -> Result<VerifiedBootstrap> {
    if config.kind != crate::config::NetworkKind::Closed {
        return Err(bootstrap_error(
            "creating",
            "explicit local creation requires Closed network kind",
        ));
    }
    let bootstrap = VerifiedBootstrap::create_closed(
        config.network_id.clone(),
        [identity.signing_key()],
        creation_id,
    )
    .map_err(|error| bootstrap_error("creating", error))?;
    let principal = local_bootstrap_principal();
    let stored = bootstrap_store(config, instance_root)?
        .persist_new(&principal, bootstrap.record())
        .map_err(|error| bootstrap_error("persisting created", error))?;
    ensure_bootstrap_for_config(config, stored)
}

fn import_local_bootstrap(
    config: &NetworkConfig,
    instance_root: Option<&Path>,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<VerifiedBootstrap> {
    if config.kind != crate::config::NetworkKind::Closed {
        return Err(bootstrap_error(
            "importing",
            "explicit bootstrap import requires Closed network kind",
        ));
    }
    let principal = local_bootstrap_principal();
    let expected = ExpectedMeshContext::for_local_import(&principal, expected_context_id);
    let imported = bootstrap_store(config, instance_root)?
        .import_expected(&expected, record)
        .map_err(|error| bootstrap_error("importing", error))?;
    ensure_bootstrap_for_config(config, imported)
}
