//! Network lifecycle: join, leave, update, reconnect, reset — and the
//! on-disk config each of them has to keep in step.
//!
//! Every one of these is reversible up to the last point it touches
//! `config.json`, which is why the persist helpers live here rather than
//! beside the router: the ordering between a live mutation and its saved
//! form is the thing these functions exist to get right.

use std::sync::Arc;

use anyhow::Result;
use myownmesh_core::{MeshConfig, NetworkConfig, TopologyMode};
use tracing::{info, warn};

use crate::registry::RemoveResult;

use super::super::{ControlState, Response};

/// Join a fresh network through the live mesh, attach signaling,
/// register the result, and persist the new config to disk. Each
/// step that mutates daemon-visible state is reversible up to the
/// last point we touch the on-disk config — config.json is updated
/// after the join + attach succeeds so a failed join leaves the
/// saved config untouched.
pub(super) async fn network_add(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // Reject duplicates against the running registry. We rely on
    // the registry's two-key indexing — checking both the local
    // config id and the wire-level network id covers the user
    // trying to add the same network twice (under any alias).
    if state.registry.contains(&config.id) {
        return Response::err(format!("config id '{}' already in use", config.id));
    }
    if state.registry.contains(&config.network_id) {
        return Response::err(format!(
            "network id '{}' already joined under a different config",
            config.network_id
        ));
    }

    // Join the live mesh first — if the engine refuses (bad
    // network id, etc.) we want to know before we touch disk.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => return Response::err(format!("join: {e}")),
    };

    // Take a summary BEFORE handing ownership to the registry so we
    // can return it in the response payload without re-locking.
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "label": joined.label(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });

    // Attach the signaling driver(s) the network's config selects
    // (Nostr and/or mDNS).
    //
    // Two outcomes that used to be one. `Ok(None)` means the outbound receiver
    // was already taken — an in-process test driver holds it — and the network
    // still works. `Err` means the attach itself was refused, which is a
    // startup failure and is now reported as one: a joined network left
    // installed with no signaling and no explanation would look identical to
    // the benign case from every later request's point of view.
    let drivers = {
        let net_state = joined.state();
        match myownmesh_core::engine::attach_signaling(&net_state) {
            Ok(drivers) => drivers,
            Err(error) => {
                let _ = joined.shutdown().await;
                return Response::err(format!("signaling attach failed: {error}"));
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
        return Response::err(format!(
            "network id is held by a runtime in {refusal_state:?} state"
        ));
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
        return Response::err(format!("network joined but config.json save failed: {e}"));
    }

    Response::ok(serde_json::json!({ "added": summary }))
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

pub(super) async fn network_remove(state: &Arc<ControlState>, key: &str, purge: bool) -> Response {
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
                return Response::err(format!("network left but config.json save failed: {e}"));
            }
            if purge {
                purge_network_state(&network_id);
            }
            match outcome {
                Ok(()) => Response::ok(serde_json::json!({ "removed": config_id })),
                Err(error) => Response::err(format!(
                    "network removed but runtime teardown reported failure: {error}"
                )),
            }
        }
        RemoveResult::AlreadyClosing(runtime) => Response::err(format!(
            "network teardown already in progress ({runtime:?})"
        )),
        RemoveResult::NotFound => Response::err(format!("unknown network: {key_owned}")),
    }
}

/// Forget every joined network at once — the bulk `NetworkRemove{purge:true}`.
/// Each network is torn down live and its signed state + roster deleted from
/// disk; the device identity is kept. Snapshots the set first so removing as we
/// go can't skip an entry. Schedules a daemon exit ([`schedule_daemon_exit`]) so
/// every layer reloads clean around the wipe.
pub(super) async fn forget_all_networks(state: &Arc<ControlState>) -> Response {
    let mut forgotten = Vec::new();
    for n in state.registry.summaries() {
        // `network_remove` resolves either alias; the config id is stable.
        let _ = network_remove(state, &n.config_id, true).await;
        forgotten.push(n.config_id);
    }
    schedule_daemon_exit();
    Response::ok(serde_json::json!({ "forgotten": forgotten, "restarting": true }))
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
pub(super) async fn factory_reset(state: &Arc<ControlState>) -> Response {
    // Quiesce writers first: tearing each network down stops its engine driver
    // from writing a roster/state file back out while we're deleting the tree.
    for n in state.registry.summaries() {
        let _ = network_remove(state, &n.config_id, true).await;
    }
    let dir = match myownmesh_core::dirs::data_dir() {
        Ok(d) => d,
        Err(e) => {
            // Can't find the dir to wipe — still restart so we don't leave the
            // caller hanging on a half-done reset.
            schedule_daemon_exit();
            return Response::err(format!("factory reset: resolve state dir: {e}"));
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
    Response::ok(serde_json::json!({ "reset": true, "restarting": true }))
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
pub(super) fn network_reconnect(
    state: &Arc<ControlState>,
    key: &str,
    peer: Option<String>,
) -> Response {
    match state.registry.get(key) {
        Some(joined) => {
            joined.reconnect(peer);
            Response::ok(serde_json::json!({ "reconnecting": key }))
        }
        None => Response::err(format!("unknown network: {key}")),
    }
}

/// Deliberately dial one peer on a joined network — the control-socket wrapper
/// around [`myownmesh_core::JoinedNetwork::connect_peer`]. Single-shot: queues
/// the offerer-side dial on the engine and returns at once (the outcome rides
/// the event stream), so a daemon client on a `Silent` network can open exactly
/// one connection after matching a peer's Support ID.
pub(super) async fn network_connect_peer(
    state: &Arc<ControlState>,
    key: &str,
    peer: &str,
    pin: bool,
    wait_ms: u64,
) -> Response {
    let Some(joined) = state.registry.get(key) else {
        return Response::err(format!("unknown network: {key}"));
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
    match result {
        Ok(active) => Response::ok(serde_json::json!({
            "connecting": peer,
            "network": key,
            "pinned": pin,
            "active": active,
        })),
        Err(e) => Response::err(e.to_string()),
    }
}

/// Update an already-joined network in place. Hot-reloadable edits
/// (topology / label / auto_approve / roster path) apply without
/// touching live sessions; transport edits (signaling / STUN / TURN /
/// network_id) tear the network down and rejoin under the new config,
/// because the ICE server set is baked into each `RTCPeerConnection`
/// when it's created — there's no way to retrofit a new TURN server
/// onto an existing connection. Either way config.json is rewritten so
/// the change survives a daemon restart.
pub(super) async fn network_update(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // This is update, not add: the network must already be joined.
    let joined = match state
        .registry
        .get(&config.id)
        .or_else(|| state.registry.get(&config.network_id))
    {
        Some(j) => j,
        None => {
            return Response::err(format!(
                "unknown network '{}' — join it with network_add first",
                config.id
            ))
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
            return Response::err(format!("apply config: {e}"));
        }
        drop(net_state);
        drop(joined);
        if let Err(e) = persist_network_update(&config) {
            return Response::err(format!("config applied but config.json save failed: {e}"));
        }
        return Response::ok(serde_json::json!({ "updated": config.id, "restarted": false }));
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
            return Response::err(format!("old runtime teardown failed: {error}"));
        }
        RemoveResult::AlreadyClosing(runtime) => {
            return Response::err(format!(
                "network update refused while teardown is already in progress ({runtime:?})"
            ));
        }
        RemoveResult::NotFound => {
            if let Some(runtime) = state.registry.state(&config.id) {
                return Response::err(format!(
                    "network update refused while prior runtime is {runtime:?}"
                ));
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
            return Response::err(format!("rejoin with new config: {e}{rollback}"));
        }
    };
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "label": joined.label(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });
    let drivers = {
        let net_state = joined.state();
        match myownmesh_core::engine::attach_signaling(&net_state) {
            Ok(drivers) => drivers,
            Err(error) => {
                let _ = joined.shutdown().await;
                return Response::err(format!("signaling attach failed after update: {error}"));
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
        return Response::err(format!(
            "replacement runtime refused while predecessor is {refusal_state:?}"
        ));
    }

    // The old network was torn down and a fresh one registered under the
    // same id; re-run both hooks so the advert tracks the replacement.
    state.services.on_network_removed(&config.id).await;
    state.services.on_network_added(&config.id).await;

    if let Err(e) = persist_network_update(&config) {
        return Response::err(format!("network updated but config.json save failed: {e}"));
    }
    Response::ok(serde_json::json!({ "updated": summary, "restarted": true }))
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

pub(super) fn parse_topology(
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
