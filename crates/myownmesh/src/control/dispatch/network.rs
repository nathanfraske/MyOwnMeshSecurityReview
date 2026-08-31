//! Network lifecycle: join, leave, update, reconnect, reset — and the
//! on-disk config each of them has to keep in step.
//!
//! Every one of these is reversible up to the last point it touches
//! `config.json`, which is why the persist helpers live here rather than
//! beside the router: the ordering between a live mutation and its saved
//! form is the thing these functions exist to get right.

use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use myownmesh_core::{MeshConfig, NetworkConfig, TopologyMode};
use tokio::sync::{Mutex, MutexGuard};
use tracing::{info, warn};

use crate::registry::RemoveResult;

use super::super::{ConnectionCancel, ControlState};
use super::{funded, unknown_network, Answer};
use crate::control::framing::{prepare_typed_and_line_building, AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    prepare_reply_then, FundedVariableReply, NetworkLifecycleSummary, OperationReplyData,
    PreparedReply, ResponseOwner,
};

/// Serialize control-surface mutations that pair a registry transition with
/// its config-file read-modify-write. The registry's exact-current fence
/// remains the lifecycle authority; this gate prevents independent dispatch
/// operations from losing each other's config-file updates.
static NETWORK_MUTATION_GATE: OnceLock<Mutex<()>> = OnceLock::new();

async fn network_mutation_guard() -> MutexGuard<'static, ()> {
    NETWORK_MUTATION_GATE
        .get_or_init(Mutex::default)
        .lock()
        .await
}

/// Preserve the operation's primary failure while still surfacing a failure
/// from the mandatory joined-network teardown. The control reply API carries
/// errors as text, so keep both causes unambiguously in that one response.
fn preserve_shutdown_failure(primary: impl Into<String>, shutdown: Result<()>) -> String {
    let primary = primary.into();
    match shutdown {
        Ok(()) => primary,
        Err(error) => format!("{primary}; shutdown failed: {error:#}"),
    }
}

/// Report purge, on-disk persistence, and runtime-teardown outcomes together.
/// All operations have already completed when this is called, so no later
/// failure hides an earlier one.
fn combine_remove_failures(
    config_id: String,
    purge_error: Option<String>,
    persistence_error: Option<String>,
    teardown_error: Option<String>,
) -> std::result::Result<String, String> {
    let mut failures = Vec::new();
    if let Some(error) = purge_error {
        failures.push(error);
    }
    if let Some(error) = persistence_error {
        failures.push(error);
    }
    if let Some(error) = teardown_error {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(config_id)
    } else {
        Err(failures.join("; "))
    }
}

/// Join a fresh network through the live mesh, attach signaling,
/// register the result, and persist the new config to disk. Each
/// step that mutates daemon-visible state is reversible up to the
/// last point we touch the on-disk config — config.json is updated
/// after the join + attach succeeds so a failed join leaves the
/// saved config untouched.
pub(in crate::control) async fn network_add(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let _mutation_guard = network_mutation_guard().await;
    // Reject duplicates against the running registry. We rely on
    // the registry's two-key indexing — checking both the local
    // config id and the wire-level network id covers the user
    // trying to add the same network twice (under any alias).
    if state.registry.contains(&config.id) {
        return owner.finish(Err(format!("config id '{}' already in use", config.id)));
    }
    if state.registry.contains(&config.network_id) {
        return owner.finish(Err(format!(
            "network id '{}' already joined under a different config",
            config.network_id
        )));
    }

    // Join the live mesh first — if the engine refuses (bad
    // network id, etc.) we want to know before we touch disk.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => return owner.finish(Err(format!("join: {e}"))),
    };

    // Take a summary BEFORE handing ownership to the registry so we
    // can return it in the response payload without re-locking.
    let summary = NetworkLifecycleSummary {
        config_id: joined.config_id().to_owned(),
        network_id: joined.network_id().to_owned(),
        label: joined.label().to_owned(),
        phase: joined.current_phase(),
        topology: joined.current_topology(),
        restarted: false,
    };

    // Attach the signaling driver(s) the network's config selects
    // (Nostr and/or mDNS).
    //
    // Two outcomes, and they are not the same. `Ok(None)` means the outbound
    // receiver was already taken — an in-process test driver holds it — and the
    // network still works. `Err` means the attach itself was refused, which is a
    // startup failure and is reported as one: a joined network left
    // installed with no signaling and no explanation would look identical to
    // the benign case from every later request's point of view.
    let drivers = {
        match joined.attach_signaling() {
            Ok(drivers) => drivers,
            Err(error) => {
                let message = preserve_shutdown_failure(
                    format!("signaling attach failed: {error}"),
                    joined.shutdown().await,
                );
                return owner.finish(Err(message));
            }
        }
    };
    if drivers.is_none() {
        warn!(
            network = %config.network_id,
            "signaling outbound receiver was already taken — this network keeps no driver handle"
        );
    }
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        let message = preserve_shutdown_failure(
            format!("network id is held by a runtime in {refusal_state:?} state"),
            refused.joined.shutdown().await,
        );
        return owner.finish(Err(message));
    }

    // Refresh the service-role advert so the new network advertises what
    // this device hosts.
    state.services.on_network_added(&config.id).await;

    // Persist to disk. We re-load the config rather than rely on
    // the in-memory copy from startup so concurrent edits (a user
    // hand-editing config.json) survive — we append to whatever's
    // on disk now. Best-effort: if save fails, the network is live
    // but won't re-join on next daemon restart. Surface the disk
    // error to the caller so the GUI can show it.
    if let Err(e) = persist_network_add(&config) {
        return owner.finish(Err(format!(
            "network joined but config.json save failed: {e}"
        )));
    }

    owner.finish(Ok(OperationReplyData::Added(summary)))
}

/// Complete the on-disk half of forgetting a network under its exact owner.
///
/// The generic owner and injected operations keep the production order and
/// failure contract directly testable without constructing a live network: no
/// owner or failed semantic purge can be turned into a successful removal.
fn purge_owned_state<T>(
    network_id: &str,
    owner: Option<&T>,
    purge_semantic: impl FnOnce(&T) -> Result<()>,
    delete_roster: impl FnOnce(&str) -> Result<()>,
) -> std::result::Result<(), String> {
    let owner = owner.ok_or_else(|| {
        format!("purge refused for {network_id}: canonical semantic snapshot owner unavailable")
    })?;
    purge_semantic(owner).map_err(|error| {
        format!(
            "purge refused for {network_id}: canonical semantic snapshot purge failed: {error:#}"
        )
    })?;
    delete_roster(network_id).map_err(|error| {
        format!("purge refused for {network_id}: roster delete failed: {error:#}")
    })?;
    Ok(())
}

fn purge_network_projection(network_id: &str) -> Result<()> {
    myownmesh_core::roster::delete(network_id).map_err(|error| anyhow!("{error:#}"))
}

/// Leave a live network and remove it from the on-disk config. The registry
/// owns signaling and engine teardown through completion and reports its exact
/// outcome.
pub(in crate::control) async fn network_remove(
    state: &Arc<ControlState>,
    key: &str,
    purge: bool,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let result = network_remove_result(state, key, purge, &owner).await;
    owner.finish(result.map(OperationReplyData::Removed))
}

async fn network_remove_result(
    state: &Arc<ControlState>,
    key: &str,
    purge: bool,
    _owner: &ResponseOwner,
) -> std::result::Result<String, String> {
    let _mutation_guard = network_mutation_guard().await;
    let key_owned = key.to_string();
    let (ids, joined_for_purge, removal) = if let Some(joined) = state.registry.get(key) {
        let ids = (
            joined.config_id().to_string(),
            joined.network_id().to_string(),
        );
        // Start the authenticated departure and registry removal together.
        // A silent peer's DepartObserved waiter is cancelled by teardown;
        // awaiting the announcement first would deadlock this removal.
        let departure = joined.announce_leave();
        let removal = state.registry.remove(key);
        let (_, removal) = tokio::join!(departure, removal);
        (Some(ids), Some(joined), Some(removal))
    } else {
        (None, None, None)
    };
    let removal = match removal {
        Some(removal) => removal,
        None => state.registry.remove(key).await,
    };
    match removal {
        RemoveResult::Removed(outcome) => {
            let (config_id, network_id) =
                ids.unwrap_or_else(|| (key_owned.clone(), key_owned.clone()));
            state.services.on_network_removed(&config_id).await;
            let purge_error = if purge {
                purge_owned_state(
                    &network_id,
                    joined_for_purge.as_ref(),
                    |joined| joined.purge_durable_semantic_state(),
                    purge_network_projection,
                )
                .err()
            } else {
                None
            };
            let persistence_error = persist_network_remove(&config_id, &network_id)
                .err()
                .map(|error| format!("network left but config.json save failed: {error}"));
            let teardown_error = outcome.err().map(|error| {
                format!("network removed but runtime teardown reported failure: {error}")
            });
            combine_remove_failures(config_id, purge_error, persistence_error, teardown_error)
        }
        RemoveResult::AlreadyClosing(observation) => match observation.outcome {
            Ok(()) => Err(format!(
                "network teardown already completed (state {:?}); purge was not attempted",
                observation.state
            )),
            Err(error) => Err(format!(
                "network teardown already in progress but reported failure: {error}"
            )),
        },
        RemoveResult::NotFound => Err(format!("unknown network: {key_owned}")),
    }
}

/// Forget every joined network at once — the bulk `NetworkRemove{purge:true}`.
/// Each network is torn down live and its canonical semantic snapshot plus
/// roster projection are deleted from disk; the device identity is kept.
/// Snapshots the set first so removing as we
/// go can't skip an entry.
///
/// The runtime shutdown that drops every in-memory cache around the wipe is not
/// this function's to start: the connection loop submits it once the response to
/// this request has actually been attempted, so no cache is dropped while the
/// answer is still unwritten and no duration stands in for the write.
pub(in crate::control) async fn forget_all_networks(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let mut forgotten = Vec::new();
    let mut failures = Vec::new();
    for n in state.registry.summaries() {
        // `network_remove` resolves either alias; the config id is stable.
        match network_remove_result(state, &n.config_id, true, &owner).await {
            Ok(config_id) => forgotten.push(config_id),
            Err(error) => failures.push(format!("{}: {error}", n.config_id)),
        }
    }
    if !failures.is_empty() {
        let mut message = format!(
            "forget all failed for {} network(s): {}",
            failures.len(),
            failures.join("; ")
        );
        if !forgotten.is_empty() {
            message.push_str(&format!("; completed: {}", forgotten.join(", ")));
        }
        return owner.finish(Err(message));
    }
    owner.finish(Ok(OperationReplyData::Forgotten(forgotten)))
}

/// Factory reset — return this device to a brand-new state. First quiesce every
/// network (tear it down + purge its files) so nothing re-persists mid-wipe,
/// then remove the whole state directory (identity, config, and any leftovers),
/// so a fresh runtime mints a new identity on empty state. Every destructive
/// step is reported: a partial wipe is not reported as a successful reset. The
/// connection loop still submits the one runtime shutdown request after this
/// answer has been attempted either way, rather than leaving a half-wiped
/// daemon re-persisting stale caches.
pub(in crate::control) async fn factory_reset(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    // Quiesce writers first: tearing each network down stops its engine driver
    // from writing a roster/state file back out while we're deleting the tree.
    let mut failures = Vec::new();
    for n in state.registry.summaries() {
        if let Err(error) = network_remove_result(state, &n.config_id, true, &owner).await {
            failures.push(format!("{}: {error}", n.config_id));
        }
    }
    let dir = match myownmesh_core::dirs::data_dir() {
        Ok(d) => d,
        Err(e) => {
            // The networks above are already torn down and purged, so the
            // connection loop's shutdown request still follows this answer: a
            // half-done reset must not go on running either.
            return owner.finish(Err(format!("factory reset: resolve state dir: {e}")));
        }
    };
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        // A missing dir already reads as reset. Any other failure means the
        // requested wipe did not happen and must not be acknowledged as one.
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(dir = %dir.display(), "factory reset: remove_dir_all: {e:#}");
            failures.push(format!("remove state directory: {e}"));
        }
    }
    if !failures.is_empty() {
        return owner.finish(Err(format!(
            "factory reset failed: {}",
            failures.join("; ")
        )));
    }
    owner.finish(Ok(OperationReplyData::Reset))
}

/// Reconnect a joined network in place — the non-destructive twin of
/// [`network_remove`] + [`network_add`]. Hands the live `JoinedNetwork` a
/// reconnect request (redial signaling + renegotiate ICE) without leaving the
/// room, so peers keep their sessions and app-level state. `peer` omitted
/// reconnects every peer; `peer` set reconnects just that one (a per-node
/// refresh). Fire-and-forget — the engine driver runs the reconnect, so this
/// returns as soon as the request is queued.
pub(in crate::control) fn network_reconnect(
    state: &Arc<ControlState>,
    key: &str,
    peer: Option<String>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    match state.registry.get(key) {
        Some(joined) => {
            joined.reconnect(peer);
            owner.finish(Ok(OperationReplyData::Reconnecting(key.to_owned())))
        }
        None => owner.finish(Err(format!("unknown network: {key}"))),
    }
}

/// One client-requested dial, exactly as the request stated it.
///
/// A carrier for the fields the `Connect` arm destructured. `wait_ms` is the
/// client's own bound on how long it will wait for an answer; it is not
/// resource authority and creates or releases nothing.
pub(in crate::control) struct ConnectPeer {
    pub network: String,
    pub peer: String,
    pub pin: bool,
    pub wait_ms: u64,
}

/// Deliberately dial one peer on a joined network, and answer.
///
/// The `Option` is the truthful shape for an operation the connection can
/// outlive: a dial cancelled by the socket draining produced no outcome, so
/// there is nothing to say and the loop ends. Every other result — including
/// a refused or timed-out dial — is a reply.
///
/// The right to answer is taken *before* the dial starts, which is why the
/// owner is acquired here rather than after the `select!`: a dial that succeeds
/// must not then discover it has nowhere to report the success.
pub(in crate::control) async fn connect_peer(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    cancel: &ConnectionCancel,
    connect: ConnectPeer,
) -> Result<Option<Answer>> {
    let ConnectPeer {
        network,
        peer,
        pin,
        wait_ms,
    } = connect;
    let owner =
        ResponseOwner::acquire(admission).context("network connect result was not admitted")?;
    let variable = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(None),
        result = connect_peer_funded(state, &network, &peer, pin, wait_ms, owner) => result,
    };
    funded(PreparedReply::Variable(variable), admission)
        .context("network connect response line was not admitted")
        .map(Some)
}

/// The dial itself — the control-socket wrapper around
/// [`myownmesh_core::JoinedNetwork::connect_peer`]. Single-shot: queues the
/// offerer-side dial on the engine and returns at once (the outcome rides the
/// event stream), so a daemon client on a `Silent` network can open exactly
/// one connection after matching a peer's Support ID.
async fn connect_peer_funded(
    state: &Arc<ControlState>,
    key: &str,
    peer: &str,
    pin: bool,
    wait_ms: u64,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let Some(joined) = state.registry.get(key) else {
        return owner.finish(Err(format!("unknown network: {key}")));
    };
    let result = if pin || wait_ms > 0 {
        // Waited/pinned dial: resolves on ACTIVE (or the caller's exact
        // deadline). A zero wait is intentionally zero; this layer must not
        // invent a timing policy for a caller that supplied none.
        let deadline = std::time::Duration::from_millis(wait_ms);
        match joined.connect_peer_wait(peer, pin, deadline).await {
            Ok(()) => Ok(true),
            Err(e) if wait_ms == 0 => {
                // Caller didn't ask to wait — a deadline miss is not
                // an error, just "still connecting".
                let msg = e.to_string();
                if msg.contains("still pending") {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    } else {
        joined.connect_peer(peer).await.map(|_| false)
    };
    owner.finish(match result {
        Ok(active) => Ok(OperationReplyData::Connecting {
            peer: peer.to_owned(),
            network: key.to_owned(),
            pinned: pin,
            active,
        }),
        Err(e) => Err(e.to_string()),
    })
}

/// Re-establish the exact predecessor after a replacement failed after the
/// predecessor had already been removed. Every successful restoration is
/// persisted under the restored runtime's exact registry owner; a successor
/// or a lost owner never gets to overwrite the config record.
async fn rollback_old_network(state: &Arc<ControlState>, old_config: &NetworkConfig) -> String {
    let restored = match state.mesh.join(old_config.clone()).await {
        Ok(restored) => restored,
        Err(error) => {
            warn!(network = %old_config.id, "network update rollback failed: {error:#}");
            return " — AND rollback failed; re-add it from the Networks tab".to_string();
        }
    };
    let attached = restored.attach_signaling();
    let drivers = match attached {
        Ok(drivers) => drivers,
        Err(error) => {
            return preserve_shutdown_failure(
                format!(" — AND the rollback join could not attach signaling: {error}"),
                restored.shutdown().await,
            );
        }
    };
    if let Some(refused) = state.registry.insert(restored, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        return preserve_shutdown_failure(
            format!(
                " — rollback join was refused by a {refusal_state:?} runtime; config was not overwritten"
            ),
            refused.joined.shutdown().await,
        );
    }

    let restored_owner = match state.registry.get(&old_config.id) {
        Some(owner) => owner,
        None => {
            return " — rollback runtime lost its lifecycle owner; config was not overwritten"
                .to_string();
        }
    };
    let persisted = state
        .registry
        .with_current(&old_config.id, &restored_owner, |_| {
            persist_network_update(old_config)
        });
    match persisted {
        Some(Ok(())) => {
            state.services.on_network_added(&old_config.id).await;
            " — restored the previous config".to_string()
        }
        Some(Err(error)) => {
            state.services.on_network_added(&old_config.id).await;
            format!(" — rollback runtime restored but config.json save failed: {error}")
        }
        None => {
            " — rollback runtime lost its lifecycle owner; config was not overwritten".to_string()
        }
    }
}

/// Retire a replacement only when the registry still holds the exact Arc that
/// failed its persistence commit. This intentionally does not fall back to a
/// key-only remove: a stale update must never tear down a successor. The
/// registry implementation owns the compare-and-claim fence and waits for an
/// already-claimed exact owner to finish.
async fn retire_failed_replacement(
    state: &Arc<ControlState>,
    key: &str,
    expected: &Arc<myownmesh_core::JoinedNetwork>,
) {
    let _ = state.registry.remove_if_current(key, expected).await;
}

/// Update an already-joined network in place. Hot-reloadable edits
/// (topology / label / auto_approve / roster path) apply without
/// touching live sessions; transport edits (signaling / STUN / TURN /
/// network_id) tear the network down and rejoin under the new config,
/// because the ICE server set is baked into each `RTCPeerConnection`
/// when it's created — there's no way to retrofit a new TURN server
/// onto an existing connection. Either way config.json is rewritten so
/// the change survives a daemon restart.
pub(in crate::control) async fn network_update(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let _mutation_guard = network_mutation_guard().await;
    // This is update, not add: the network must already be joined. Resolve
    // both aliases before teardown. If they name different live runtimes,
    // this is an id collision rather than an update and the disk must remain
    // untouched while both owners stay current.
    let by_config_id = state.registry.get(&config.id);
    let by_network_id = state.registry.get(&config.network_id);
    let joined = match (by_config_id, by_network_id) {
        (Some(config_owner), Some(network_owner)) if Arc::ptr_eq(&config_owner, &network_owner) => {
            config_owner
        }
        (Some(_), Some(_)) => {
            return owner.finish(Err(format!(
                "network update refused: config id '{}' and network id '{}' belong to different live networks",
                config.id, config.network_id
            )));
        }
        (Some(owner), None) | (None, Some(owner)) => owner,
        (None, None) => {
            return owner.finish(Err(format!(
                "unknown network '{}' — join it with network_add first",
                config.id
            )));
        }
    };
    if joined.config_id() != config.id.as_str() {
        return owner.finish(Err(format!(
            "network update refused: config id '{}' does not match current owner '{}'",
            config.id,
            joined.config_id()
        )));
    }

    // Compare the incoming config against the engine's live config to
    // decide hot-apply vs. transport restart.
    let (needs_restart, signaling_changed, network_id_changed) = joined.reconcile_status(&config);
    // Name the path taken so a config-driven flap is greppable: a hot-apply
    // keeps every live peer; a restart drops them. Only network_id/signaling
    // force the restart now (STUN/TURN are hot — see `reconcile`).
    info!(
        network = %config.network_id,
        needs_restart,
        signaling_changed,
        network_id_changed,
        "network_update: {}",
        if needs_restart { "transport restart (drops live peers)" } else { "hot-applied in place" }
    );

    if !needs_restart {
        // STUN/TURN / topology / label / auto_approve / roster — apply in
        // place, no peers dropped. ICE servers are read fresh on the next
        // connect, so a credential rotation reaches new connections without
        // tearing down the live ones (see `reconcile::apply_hot`).
        let hot_result =
            state
                .registry
                .with_current(&config.id, &joined, |current| -> Result<()> {
                    persist_network_update(&config)?;
                    current.apply_hot(config.clone())?;
                    Ok(())
                });
        let hot_result = match hot_result {
            Some(result) => Some(result),
            None => {
                state
                    .registry
                    .with_current(&config.network_id, &joined, |current| -> Result<()> {
                        persist_network_update(&config)?;
                        current.apply_hot(config.clone())?;
                        Ok(())
                    })
            }
        };
        match hot_result {
            None => {
                return owner.finish(Err(
                    "network update refused: lifecycle owner is no longer current".to_string(),
                ));
            }
            Some(Err(e)) => {
                return owner.finish(Err(format!("apply or persist config: {e}")));
            }
            Some(Ok(())) => {}
        }
        drop(joined);
        return owner.finish(Ok(OperationReplyData::UpdatedId {
            id: config.id,
            restarted: false,
        }));
    }

    // Transport restart path. Snapshot the live config FIRST so that if
    // the rejoin under the new config is rejected (a bad TURN URL the
    // daemon won't parse, say) we can restore the network exactly as it
    // was rather than leaving the user with nothing — the roster file
    // survives on disk regardless, but a vanished network with no
    // recovery surface is a footgun. Then release our Arc clones so the
    // registry can begin its single owned teardown.
    let old_config = joined.config_snapshot();
    // Start the authenticated departure and teardown together so teardown can
    // cancel a silent peer's DepartObserved waiter. The carrier hint remains
    // part of the departure future.
    let departure = joined.announce_leave();
    let removal = state.registry.remove(&old_config.id);
    let (_, removal) = tokio::join!(departure, removal);
    drop(joined);

    match removal {
        RemoveResult::Removed(Ok(())) => {}
        RemoveResult::Removed(Err(error)) => {
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "old runtime teardown failed: {error}{rollback}"
            )));
        }
        RemoveResult::AlreadyClosing(observation) => {
            let error = match observation.outcome {
                Ok(()) => format!(
                    "network update refused after teardown completed (state {:?})",
                    observation.state
                ),
                Err(error) => format!(
                    "network update refused because prior teardown reported failure: {error}"
                ),
            };
            return owner.finish(Err(error));
        }
        RemoveResult::NotFound => {
            if let Some(runtime) = state.registry.state(&old_config.id) {
                return owner.finish(Err(format!(
                    "network update refused while prior runtime is {runtime:?}"
                )));
            }
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "network update lost the predecessor during teardown{rollback}"
            )));
        }
    }

    // Re-join under the new transport config. If the daemon rejects it,
    // roll back to the snapshot so the network (and its live session) is
    // restored instead of silently disappearing.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => {
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!("rejoin with new config: {e}{rollback}")));
        }
    };
    let summary = NetworkLifecycleSummary {
        config_id: joined.config_id().to_owned(),
        network_id: joined.network_id().to_owned(),
        label: joined.label().to_owned(),
        phase: joined.current_phase(),
        topology: joined.current_topology(),
        restarted: true,
    };
    let drivers = {
        match joined.attach_signaling() {
            Ok(drivers) => drivers,
            Err(error) => {
                let attach_error = preserve_shutdown_failure(
                    format!("signaling attach failed after update: {error}"),
                    joined.shutdown().await,
                );
                let rollback = rollback_old_network(state, &old_config).await;
                return owner.finish(Err(format!("{attach_error}{rollback}")));
            }
        }
    };
    if drivers.is_none() {
        warn!(
            network = %config.network_id,
            "signaling outbound receiver was already taken after update — \
             this network keeps no driver handle"
        );
    }
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        let replacement_error = preserve_shutdown_failure(
            format!("replacement runtime refused while predecessor is {refusal_state:?}"),
            refused.joined.shutdown().await,
        );
        let rollback = rollback_old_network(state, &old_config).await;
        return owner.finish(Err(format!("{replacement_error}{rollback}")));
    }

    // The insert is the replacement's ownership boundary. Resolve the exact
    // current Arc and commit persistence under the registry fence; a
    // refusal/successor path above deliberately never reaches this write.
    let replacement_owner = match state.registry.get(&config.id) {
        Some(owner) => owner,
        _ => {
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(
                format!(
                    "replacement runtime lost its lifecycle owner; config was not overwritten{rollback}"
                ),
            ));
        }
    };

    let persisted = state
        .registry
        .with_current(&config.id, &replacement_owner, |_| {
            persist_network_update(&config)
        });
    match persisted {
        None => {
            retire_failed_replacement(state, &config.id, &replacement_owner).await;
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "replacement runtime lost its lifecycle owner before persistence{rollback}"
            )));
        }
        Some(Err(e)) => {
            retire_failed_replacement(state, &config.id, &replacement_owner).await;
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "network updated but config.json save failed: {e}{rollback}"
            )));
        }
        Some(Ok(())) => {}
    }
    // The old network was torn down and a fresh one registered under the
    // same id; only after the fenced persistence succeeds do the async hooks
    // refresh the advert for the replacement.
    state.services.on_network_removed(&config.id).await;
    state.services.on_network_added(&config.id).await;
    owner.finish(Ok(OperationReplyData::Updated(summary)))
}

fn persist_network_add(net: &NetworkConfig) -> Result<()> {
    MeshConfig::transaction(|cfg| {
        // Append only if not already present — covers the case where
        // the user edited config.json by hand between daemon start and
        // this add, and added the same network there too.
        if !cfg
            .networks
            .iter()
            .any(|n| n.id == net.id || n.network_id == net.network_id)
        {
            cfg.networks.push(net.clone());
        }
        Ok(())
    })
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_remove(config_id: &str, network_id: &str) -> Result<()> {
    MeshConfig::transaction(|cfg| {
        cfg.networks
            .retain(|n| n.id != config_id && n.network_id != network_id);
        Ok(())
    })
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_update(net: &NetworkConfig) -> Result<()> {
    MeshConfig::transaction(|cfg| {
        // Replace the matching record in place (by either alias). If it's
        // somehow absent — e.g. the user hand-deleted it between join and
        // this update — append so the on-disk config still agrees with the
        // now-running engine rather than silently dropping it.
        if let Some(slot) = cfg
            .networks
            .iter_mut()
            .find(|n| n.id == net.id || n.network_id == net.network_id)
        {
            *slot = net.clone();
        } else {
            cfg.networks.push(net.clone());
        }
        Ok(())
    })
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

pub(in crate::control) fn parse_topology(
    name: &str,
    hub: Option<&str>,
) -> std::result::Result<TopologyMode, String> {
    match name {
        "ring" => Ok(TopologyMode::Ring { n_preferred: None }),
        "star" => {
            let hub = hub.ok_or_else(|| "star topology requires --hub <device_id>".to_string())?;
            Ok(TopologyMode::Star {
                hub: hub.to_string(),
            })
        }
        "full_mesh" | "fullmesh" => Ok(TopologyMode::FullMesh),
        "hubs" => {
            let list = hub.ok_or_else(|| {
                "hubs topology requires --hub <id[,id…][:redundancy]>".to_string()
            })?;
            let (ids, redundancy) = match list.rsplit_once(':') {
                Some((ids, r)) => (
                    ids,
                    Some(r.parse::<u32>().map_err(|_| {
                        format!("invalid spoke redundancy '{r}' — expected a number")
                    })?),
                ),
                None => (list, None),
            };
            let hubs: Vec<String> = ids
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if hubs.is_empty() {
                return Err("hubs topology requires at least one hub id".into());
            }
            Ok(TopologyMode::Hubs {
                hubs,
                spoke_redundancy: redundancy,
            })
        }
        other => Err(format!(
            "unknown topology '{other}' — expected ring | star | hubs | full_mesh"
        )),
    }
}

/// This node's overall status: identity, networks, realtime, all at once.
///
/// The snapshot is taken behind one admission rather than field by field, so
/// the answer describes a single moment instead of a walk across several.
pub(in crate::control) fn node_status(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let source = state
        .registry
        .status_source(state.mesh.identity(), &state.realtime);
    let typed_claim = source
        .typed_claim()
        .context("status typed claim was not representable")?;
    let line_ceiling = source
        .line_ceiling()
        .context("status line ceiling was not representable")?;
    let (committed, output) =
        prepare_typed_and_line_building(typed_claim, line_ceiling, admission, |typed| {
            source.commit(typed)
        })
        .context("status snapshot or response line was not admitted")?;
    let status = committed.map_err(|_| anyhow!("status typed claim changed before commit"))?;
    Ok((PreparedReply::Status(status), output))
}

/// Every network this device has joined.
pub(in crate::control) fn networks_list(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let plan = state
        .registry
        .prepare_networks_list()
        .context("NetworksList capacity was not representable")?;
    let typed = admission
        .acquire_claim(plan.typed_claim())
        .context("NetworksList typed snapshot was not admitted")?;
    let work = admission
        .acquire_claim(plan.work_claim())
        .context("NetworksList snapshot work was not admitted")?;
    let plan = plan
        .measure_line_ceiling(&work)
        .context("NetworksList line capacity was not representable")?;
    let output = AdmittedLineOut::prepare_capacity(plan.line_ceiling(), admission)
        .context("NetworksList response line was not admitted")?;
    let networks = plan
        .commit(typed, work)
        .map_err(|_| anyhow!("NetworksList changed shape while its funded snapshot was built"))?;
    Ok((PreparedReply::Networks(networks), output))
}

/// Advertise what this device can do on one network.
pub(in crate::control) async fn capabilities_set(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    capabilities: myownmesh_core::protocol::CapabilityAdvert,
) -> Result<Answer> {
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let reply = PreparedReply::Bool {
        key: "advertised",
        value: true,
    };
    let (advertised, output) =
        prepare_reply_then(&reply, admission, || net.advertise(capabilities))
            .context("capability-advert response capacity was not admitted")?;
    match advertised {
        Ok(()) => Ok((reply, output)),
        Err(error) => {
            drop(output);
            super::refused_text(
                format!(
                    "capabilities were not advertised; the node is still publishing its \
                     previous ones: {error}"
                ),
                admission,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::combine_remove_failures;
    use super::preserve_shutdown_failure;
    use super::purge_owned_state;

    #[test]
    fn mandatory_shutdown_failure_preserves_each_primary_response_cause() {
        for primary in [
            "signaling attach failed: attach refused",
            "network id is held by a runtime in Closing state",
            "rollback join was refused by a Closing runtime; config was not overwritten",
            "replacement runtime refused while predecessor is Closing",
        ] {
            let combined =
                preserve_shutdown_failure(primary, Err(anyhow::anyhow!("driver teardown failed")));
            assert_eq!(
                combined,
                format!("{primary}; shutdown failed: driver teardown failed")
            );
            assert_eq!(combined.matches("shutdown failed").count(), 1);
        }

        let primary = "signaling attach failed: attach refused";
        assert_eq!(preserve_shutdown_failure(primary, Ok(())), primary);
    }

    #[test]
    fn remove_failures_preserve_exact_single_and_combined_order() {
        let purge = "purge refused for network-a: semantic state is busy".to_string();
        let persistence = "network left but config.json save failed: disk full".to_string();
        let teardown =
            "network removed but runtime teardown reported failure: driver stopped with error"
                .to_string();

        assert_eq!(
            combine_remove_failures("network-a".into(), None, Some(persistence.clone()), None),
            Err(persistence.clone())
        );
        assert_eq!(
            combine_remove_failures("network-a".into(), None, None, Some(teardown.clone())),
            Err(teardown.clone())
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                None,
                Some(persistence.clone()),
                Some(teardown.clone())
            ),
            Err(format!("{persistence}; {teardown}"))
        );
        assert_eq!(
            combine_remove_failures("network-a".into(), Some(purge.clone()), None, None),
            Err(purge.clone())
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                Some(purge.clone()),
                Some(persistence.clone()),
                None
            ),
            Err(format!("{purge}; {persistence}"))
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                Some(purge.clone()),
                None,
                Some(teardown.clone())
            ),
            Err(format!("{purge}; {teardown}"))
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                Some(purge.clone()),
                Some(persistence.clone()),
                Some(teardown.clone())
            ),
            Err(format!("{purge}; {persistence}; {teardown}"))
        );
        assert_eq!(
            combine_remove_failures("network-a".into(), None, None, None),
            Ok("network-a".to_string())
        );
    }

    #[test]
    fn purge_without_the_joined_owner_is_refused() {
        let error = purge_owned_state(
            "network-a",
            None::<&()>,
            |_| panic!("semantic purge must not run without its owner"),
            |_| panic!("roster purge must not run without its owner"),
        )
        .expect_err("missing owner must not report a successful purge");
        assert!(error.contains("canonical semantic snapshot owner unavailable"));
    }

    #[test]
    fn semantic_writer_refusal_is_not_reported_as_removed() {
        let owner = ();
        let error = purge_owned_state(
            "network-a",
            Some(&owner),
            |_| Err(anyhow::anyhow!("WriterBusy: semantic writer is busy")),
            |_| panic!("roster purge must wait for semantic success"),
        )
        .expect_err("a semantic writer refusal must fail the purge");
        assert!(error.contains("WriterBusy"));
        assert!(error.contains("purge refused"));
    }

    #[test]
    fn roster_io_failure_is_not_reported_as_forgotten() {
        let owner = ();
        let error = purge_owned_state(
            "network-a",
            Some(&owner),
            |_| Ok(()),
            |_| Err(anyhow::anyhow!("I/O error removing roster")),
        )
        .expect_err("a roster I/O refusal must fail the purge");
        assert!(error.contains("roster delete failed"));
        assert!(error.contains("I/O error"));
    }

    #[test]
    fn successful_purge_requires_both_owned_steps() {
        let owner = ();
        let mut semantic_called = false;
        let mut roster_called = false;
        purge_owned_state(
            "network-a",
            Some(&owner),
            |_| {
                semantic_called = true;
                Ok(())
            },
            |_| {
                roster_called = true;
                Ok(())
            },
        )
        .expect("both owned purge steps succeeded");
        assert!(semantic_called);
        assert!(roster_called);
    }
}
