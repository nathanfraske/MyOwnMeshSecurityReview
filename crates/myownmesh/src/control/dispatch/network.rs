//! Network lifecycle: join, leave, update, reconnect, reset — and the
//! on-disk config each of them has to keep in step.
//!
//! Every one of these is reversible up to the last point it touches
//! `config.json`, which is why the persist helpers live here rather than
//! beside the router: the ordering between a live mutation and its saved
//! form is the thing these functions exist to get right.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use myownmesh_core::{MeshConfig, NetworkConfig, TopologyMode};
use tracing::{info, warn};

use crate::registry::RemoveResult;

use super::super::{ConnectionCancel, ControlState};
use super::{funded, unknown_network, Answer};
use crate::control::framing::{prepare_typed_and_line_building, AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    prepare_reply_then, FundedVariableReply, NetworkLifecycleSummary, OperationReplyData,
    PreparedReply, ResponseOwner,
};

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
        let net_state = joined.state();
        match myownmesh_core::engine::attach_signaling(&net_state) {
            Ok(drivers) => drivers,
            Err(error) => {
                let _ = joined.shutdown().await;
                return owner.finish(Err(format!("signaling attach failed: {error}")));
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
        drop(refused.drivers);
        let _ = refused.joined.shutdown().await;
        return owner.finish(Err(format!(
            "network id is held by a runtime in {refusal_state:?} state"
        )));
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

/// Leave a live network and remove it from the on-disk config. The registry
/// owns signaling and engine teardown through completion and reports its exact
/// outcome.
/// Drop a network's persisted **governance state + roster** — the on-disk half
/// of forgetting a network. Best-effort + logged: a leave that can't delete the
/// files isn't worth failing the request over, but leaving them is precisely
/// what made a rejoin reload a stale/forked genesis, so we try.
fn purge_network_state(network_id: &str) {
    if let Err(e) = myownmesh_core::network_state::delete(network_id) {
        warn!(%network_id, "purge: network_state delete failed: {e:#}");
    }
    if let Err(e) = myownmesh_core::roster::delete(network_id) {
        warn!(%network_id, "purge: roster delete failed: {e:#}");
    }
}

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
    let key_owned = key.to_string();
    let ids = if let Some(joined) = state.registry.get(key) {
        let ids = (
            joined.config_id().to_string(),
            joined.network_id().to_string(),
        );
        joined.announce_leave().await;
        Some(ids)
    } else {
        None
    };
    match state.registry.remove(key).await {
        RemoveResult::Removed(outcome) => {
            let (config_id, network_id) =
                ids.unwrap_or_else(|| (key_owned.clone(), key_owned.clone()));
            state.services.on_network_removed(&config_id).await;
            if let Err(e) = persist_network_remove(&config_id, &network_id) {
                return Err(format!("network left but config.json save failed: {e}"));
            }
            if purge {
                purge_network_state(&network_id);
            }
            match outcome {
                Ok(()) => Ok(config_id),
                Err(error) => Err(format!(
                    "network removed but runtime teardown reported failure: {error}"
                )),
            }
        }
        RemoveResult::AlreadyClosing(runtime) => Err(format!(
            "network teardown already in progress ({runtime:?})"
        )),
        RemoveResult::NotFound => Err(format!("unknown network: {key_owned}")),
    }
}

/// Forget every joined network at once — the bulk `NetworkRemove{purge:true}`.
/// Each network is torn down live and its signed state + roster deleted from
/// disk; the device identity is kept. Snapshots the set first so removing as we
/// go can't skip an entry. Schedules a daemon exit ([`schedule_daemon_exit`]) so
/// every layer reloads clean around the wipe.
pub(in crate::control) async fn forget_all_networks(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let mut forgotten = Vec::new();
    for n in state.registry.summaries() {
        // `network_remove` resolves either alias; the config id is stable.
        let _ = network_remove_result(state, &n.config_id, true, &owner).await;
        forgotten.push(n.config_id);
    }
    schedule_daemon_exit();
    owner.finish(Ok(OperationReplyData::Forgotten(forgotten)))
}

/// Factory reset — return this device to a brand-new state. First quiesce every
/// network (tear it down + purge its files) so nothing re-persists mid-wipe,
/// then remove the whole state directory (identity, config, and any leftovers),
/// and finally exit so a fresh daemon mints a new identity on empty state. The
/// live control socket + log file descriptors stay valid until exit; the
/// supervising service, or the GUI's `ensure_daemon_running` on relaunch, brings
/// the daemon back. Best-effort per step — we always schedule the exit so a
/// partial failure still ends in a clean restart rather than a half-wiped daemon
/// re-persisting stale caches.
pub(in crate::control) async fn factory_reset(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    // Quiesce writers first: tearing each network down stops its engine driver
    // from writing a roster/state file back out while we're deleting the tree.
    for n in state.registry.summaries() {
        let _ = network_remove_result(state, &n.config_id, true, &owner).await;
    }
    let dir = match myownmesh_core::dirs::data_dir() {
        Ok(d) => d,
        Err(e) => {
            // Can't find the dir to wipe — still restart so we don't leave the
            // caller hanging on a half-done reset.
            schedule_daemon_exit();
            return owner.finish(Err(format!("factory reset: resolve state dir: {e}")));
        }
    };
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        // A missing dir already reads as reset; anything else is worth logging,
        // but we still exit so caches can't resurrect what did get deleted.
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(dir = %dir.display(), "factory reset: remove_dir_all: {e:#}");
        }
    }
    schedule_daemon_exit();
    owner.finish(Ok(OperationReplyData::Reset))
}

/// Exit the daemon shortly after the current response flushes, so a fresh
/// instance reloads from the now-clean disk. The reset commands use this: the
/// only reliable way to drop every in-memory cache — which would otherwise
/// re-persist and "resurrect" the state we just deleted — is a clean process
/// restart. The short delay lets the JSON response reach the client first; the
/// supervising service (Restart=always) or the GUI's `ensure_daemon_running` on
/// relaunch starts a fresh daemon.
fn schedule_daemon_exit() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        info!("reset complete — exiting so a fresh daemon reloads clean state");
        std::process::exit(0);
    });
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
        // Waited/pinned dial: resolves on ACTIVE (or the deadline). A
        // pin with no wait still uses the waiting path with a minimal
        // deadline so the sticky flag is recorded engine-side; the
        // dial itself keeps going either way.
        let deadline = std::time::Duration::from_millis(wait_ms.max(1));
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
    // This is update, not add: the network must already be joined.
    let joined = match state
        .registry
        .get(&config.id)
        .or_else(|| state.registry.get(&config.network_id))
    {
        Some(j) => j,
        None => {
            return owner.finish(Err(format!(
                "unknown network '{}' — join it with network_add first",
                config.id
            )));
        }
    };

    // Compare the incoming config against the engine's live config to
    // decide hot-apply vs. transport restart.
    let net_state = joined.state();
    let (needs_restart, signaling_changed, network_id_changed) = {
        let current = net_state.config.read().clone();
        (
            myownmesh_core::engine::reconcile::requires_restart(&current, &config),
            current.signaling != config.signaling,
            current.network_id != config.network_id,
        )
    };
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
        if let Err(e) = myownmesh_core::engine::reconcile::apply_hot(&net_state, config.clone()) {
            return owner.finish(Err(format!("apply config: {e}")));
        }
        drop(net_state);
        drop(joined);
        if let Err(e) = persist_network_update(&config) {
            return owner.finish(Err(format!(
                "config applied but config.json save failed: {e}"
            )));
        }
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
    let old_config = net_state.config.read().clone();
    // Same graceful-departure courtesy as network_remove: peers drop our
    // session now rather than waiting out the heartbeat timeout, so the
    // rebuild under the new transport reconnects promptly instead of
    // racing the stale-session recovery path. Emitted while the signaling
    // driver is still live (before the registry remove below drops it).
    joined.announce_leave().await;
    drop(net_state);
    drop(joined);

    match state.registry.remove(&config.id).await {
        RemoveResult::Removed(Ok(())) => {}
        RemoveResult::Removed(Err(error)) => {
            return owner.finish(Err(format!("old runtime teardown failed: {error}")));
        }
        RemoveResult::AlreadyClosing(runtime) => {
            return owner.finish(Err(format!(
                "network update refused while teardown is already in progress ({runtime:?})"
            )));
        }
        RemoveResult::NotFound => {
            if let Some(runtime) = state.registry.state(&config.id) {
                return owner.finish(Err(format!(
                    "network update refused while prior runtime is {runtime:?}"
                )));
            }
        }
    }

    // Re-join under the new transport config. If the daemon rejects it,
    // roll back to the snapshot so the network (and its live session) is
    // restored instead of silently disappearing.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => {
            let rollback = match state.mesh.join(old_config).await {
                Ok(restored) => {
                    let attached = {
                        let net_state = restored.state();
                        myownmesh_core::engine::attach_signaling(&net_state)
                    };
                    match attached {
                        // The rollback rejoined but could not attach. Restoring
                        // a network that cannot signal is not a restore, so it
                        // is taken back down and the caller told both halves.
                        Err(error) => {
                            let _ = restored.shutdown().await;
                            format!(" — AND the rollback join could not attach signaling: {error}")
                        }
                        Ok(drivers) => {
                            match state.registry.insert(restored, drivers).into_refusal() {
                                None => {
                                    state.services.on_network_added(&config.id).await;
                                    " — restored the previous config".to_string()
                                }
                                Some(refused) => {
                                    let refusal_state = refused.state;
                                    drop(refused.drivers);
                                    let _ = refused.joined.shutdown().await;
                                    format!(
                                        " — rollback join was refused by a \
                                         {refusal_state:?} runtime"
                                    )
                                }
                            }
                        }
                    }
                }
                Err(re) => {
                    warn!(network = %config.id, "network update rollback failed: {re:#}");
                    " — AND rollback failed; re-add it from the Networks tab".to_string()
                }
            };
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
        let net_state = joined.state();
        match myownmesh_core::engine::attach_signaling(&net_state) {
            Ok(drivers) => drivers,
            Err(error) => {
                let _ = joined.shutdown().await;
                return owner.finish(Err(format!(
                    "signaling attach failed after update: {error}"
                )));
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
        drop(refused.drivers);
        let _ = refused.joined.shutdown().await;
        return owner.finish(Err(format!(
            "replacement runtime refused while predecessor is {refusal_state:?}"
        )));
    }

    // The old network was torn down and a fresh one registered under the
    // same id; re-run both hooks so the advert tracks the replacement.
    state.services.on_network_removed(&config.id).await;
    state.services.on_network_added(&config.id).await;

    if let Err(e) = persist_network_update(&config) {
        return owner.finish(Err(format!(
            "network updated but config.json save failed: {e}"
        )));
    }
    owner.finish(Ok(OperationReplyData::Updated(summary)))
}

fn persist_network_add(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
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
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_remove(config_id: &str, network_id: &str) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    let before = cfg.networks.len();
    cfg.networks
        .retain(|n| n.id != config_id && n.network_id != network_id);
    if cfg.networks.len() != before {
        cfg.save().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn persist_network_update(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
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
    cfg.save().map_err(anyhow::Error::msg)?;
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
