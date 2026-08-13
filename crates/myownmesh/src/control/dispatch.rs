//! The control protocol's request router.
//!
//! One exhaustive `match` over [`Request`], and nothing else: a new request
//! variant is a compile error here rather than a silent fallthrough, which is
//! why the match was not split into per-domain sub-matches with catch-alls.
//! The work behind an arm lives in the domain module named for it.

use std::sync::Arc;

use myownmesh_core::transport as core_webrtc;
use tracing::info;

mod network;
mod services;

use network::{
    factory_reset, forget_all_networks, network_add, network_connect_peer, network_reconnect,
    network_remove, network_update, parse_topology,
};
use services::services_set;

use super::{realtime_refused, ConnectionCancel, ControlState, Request, Response};

pub(super) async fn dispatch(
    state: &Arc<ControlState>,
    cancel: &ConnectionCancel,
    req: Request,
) -> Response {
    match req {
        Request::Status => {
            unreachable!("Status commits and encodes at the prepared reply boundary")
        }
        Request::IdentityShow => Response::ok(serde_json::json!({
            "device_id": state.mesh.identity().display_id(),
            "pubkey": state.mesh.identity().public_id(),
            "label": state.mesh.identity().label(),
        })),
        Request::IdentitySetLabel { label } => {
            // Persist first; if the disk write fails we want the
            // in-memory copy to still reflect the on-disk reality, so
            // we don't update the live `Identity` on error.
            if let Err(e) = myownmesh_core::identity::set_label(&label) {
                return Response::err(e.to_string());
            }
            state.mesh.identity().set_label(&label);
            Response::ok(serde_json::json!({
                "device_id": state.mesh.identity().display_id(),
                "pubkey": state.mesh.identity().public_id(),
                "label": state.mesh.identity().label(),
            }))
        }
        Request::NetworksList => {
            unreachable!("NetworksList commits and encodes at the prepared reply boundary")
        }
        Request::PeersList { .. } => {
            unreachable!("PeersList commits and encodes at the prepared reply boundary")
        }
        Request::RosterList { network } => match state.registry.get(&network) {
            Some(net) => match net.roster_list().await {
                Ok(list) => Response::ok(serde_json::json!({ "roster": list })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterApprove {
            network,
            device_id,
            label,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .roster_approve(&device_id, label.as_deref().unwrap_or(""))
                .await
            {
                Ok(_) => Response::ok(serde_json::json!({ "approved": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterRemove { network, device_id } => match state.registry.get(&network) {
            Some(net) => match net.roster_remove(&device_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "removed": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::TopologySet {
            network,
            topology,
            hub,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => {
                    // A ratified TopologyChange owns the shape network-wide;
                    // a local set would silently fork this device off it
                    // (the engine ignores the command as a backstop — the
                    // refusal belongs here where the caller can see it).
                    if let Ok(gov) = net.governance_state().await {
                        if gov.topology.is_some() {
                            return Response::err(
                                "this network's topology is governed by a signed \
                                 owner transition — propose a change instead \
                                 (`networks topology-propose` / GovernanceProposeTopology)"
                                    .to_string(),
                            );
                        }
                    }
                    match net.set_topology(mode).await {
                        Ok(_) => Response::ok(serde_json::json!({ "topology": topology })),
                        Err(e) => Response::err(e.to_string()),
                    }
                }
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::NetworkIdGenerate | Request::NetworkIdNormalize { .. } => {
            unreachable!("network ids commit and encode at the prepared reply boundary")
        }
        Request::ConfigShow => {
            unreachable!("ConfigShow loads and encodes at the prepared reply boundary")
        }
        Request::NetworkAdd { config } => {
            info!(network = %config.network_id, config_id = %config.id, "control: network_add");
            network_add(state, config).await
        }
        Request::NetworkRemove { network, purge } => {
            info!(%network, purge, "control: network_remove");
            network_remove(state, &network, purge).await
        }
        Request::ForgetAllNetworks => {
            info!("control: forget_all_networks");
            forget_all_networks(state).await
        }
        Request::FactoryReset => {
            info!("control: factory_reset");
            factory_reset(state).await
        }
        Request::NetworkUpdate { config } => {
            info!(network = %config.network_id, config_id = %config.id, "control: network_update");
            network_update(state, config).await
        }
        Request::NetworkReconnect { network, peer } => {
            info!(%network, ?peer, "control: network_reconnect");
            network_reconnect(state, &network, peer)
        }
        Request::NetworkConnectPeer {
            network,
            peer,
            pin,
            wait_ms,
        } => {
            info!(%network, %peer, pin, wait_ms, "control: network_connect_peer");
            tokio::select! {
                biased;
                () = cancel.cancelled() => Response::err("control connection closing"),
                response = network_connect_peer(state, &network, &peer, pin, wait_ms) => response,
            }
        }

        // ---- realtime flows ----
        Request::RealtimeFlowOpen {
            network,
            peer,
            flow_label,
            direction,
            rtp_kind,
            mime,
            clock_rate,
            channels,
            client_id,
            client_capability,
        } => {
            // Authenticated before anything is opened, because the flow the
            // open produces has to be *owned*. A flow opened for nobody would
            // have to be dropped — which now closes it, so the open would have
            // been a round trip to core and back for nothing — or filed under a
            // coordinate, which is what this finding removes. Refusing first
            // means neither.
            let Some(owner) = state.clients.authenticate(client_id, &client_capability) else {
                return Response::err("invalid local client authority");
            };
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            // The name crosses as bytes; the string is only how JSON carries
            // it. Bounds are core's to enforce — an empty or over-long name is
            // refused there, in the one place that also owns the frame width it
            // is bounded by, rather than re-checked here against a copy of the
            // rule that could drift.
            let chosen = flow_label.clone();
            let open = core_webrtc::WebRtcRealtimeFlowOpen {
                label: flow_label.into_bytes(),
                direction,
                kind: rtp_kind,
                mime,
                clock_rate,
                channels,
            };
            // Synchronous: the label is claimed or refused before this returns,
            // so a client that gets `ok` may start writing units immediately and
            // one that gets a refusal knows the label is still its own to reuse.
            // Awaits: opening a flow brings its native half up with it — a
            // receive transceiver inbound, a sender and pump outbound. Still one
            // call and still all-or-nothing from here, so a refusal has released
            // both the label and the native object and leaves nothing behind.
            match net.open_webrtc_realtime(&peer, open).await {
                // The handle is stored, never returned. What the client gets is
                // the capability naming it: unguessable, minted here, and the
                // only thing that will authorize a write or a close. Core's
                // handle is move-only and not serializable, so there is nothing
                // to hand across the socket even if it were wanted.
                //
                // `flow_label` is echoed beside it because the client still
                // needs the name for its own control messages — and because it
                // is the caller's own string, so echoing cannot disagree with
                // what core holds. It authorizes nothing.
                Ok(flow) => match state.clients.install_realtime_flow(&owner, network, flow) {
                    Ok(capability) => Response::ok(serde_json::json!({
                        "flow_label": chosen,
                        "flow_capability": capability.expose(),
                    })),
                    Err(rejected) => {
                        // This completed open was never installed, so this
                        // branch is its sole close owner — whether the
                        // disconnect won the registry seam or the flow's own
                        // table entry was refused funding. The handle owns
                        // nothing, so dropping it here would leave the label
                        // claimed and the native half up.
                        let reason = rejected.reason.to_string();
                        let _ = net.close_realtime(rejected.flow).await;
                        Response::err(format!("realtime flow open refused: {reason}"))
                    }
                },
                Err(refusal) => realtime_refused(refusal),
            }
        }
        Request::RealtimeFlowClose {
            client_id,
            client_capability,
            flow_capability,
        } => {
            let Some(owner) = state.clients.authenticate(client_id, &client_capability) else {
                return Response::err("invalid local client authority");
            };
            // Taken out before the close runs, and taken by value. Two
            // concurrent closes therefore cannot both reach core with the same
            // flow — the second finds nothing — and a client cannot send on a
            // flow it has asked to close, because there is no longer an entry
            // for its pipe to borrow.
            // `_flow_funding` is bound, not discarded. It pays for `network`
            // below, which is read past the lookup, past the await, and into
            // the response — so it has to outlive all of them and is dropped at
            // the end of this arm with the string it funds.
            let Some(flow) = owner.take_realtime_flow(&flow_capability) else {
                return Response::err(
                    "unknown flow_capability: it was never issued to this client, or the \
                     flow it named has already been closed",
                );
            };
            let Some(net) = state.registry.get(flow.network()) else {
                return Response::err(format!("unknown network: {}", flow.network()));
            };
            // Awaits, and the wait is the guarantee. Closing retires the flow's
            // native half — a transceiver inbound, a sender outbound — and the
            // ack follows that retirement rather than the label release. So a
            // client that closes a label and immediately reopens it can rely on
            // the previous occupant being gone; acking on the release would make
            // that false in precisely the case where it matters.
            //
            // The handle is consumed here. A refusal therefore does not hand it
            // back, and that is right rather than merely convenient: every
            // refusal this can produce means the flow is already gone — its
            // session was replaced, or the label was closed with it — so
            // returning the capability would be re-issuing authority over
            // nothing.
            match flow.close_through(&net).await {
                Ok(()) => Response::ok(serde_json::json!({ "closed": true })),
                Err(refusal) => realtime_refused(refusal),
            }
        }

        // ---- self-update ----
        Request::UpdateStatus => match myownmesh_updater::status() {
            Ok(s) => Response::ok(serde_json::to_value(s).unwrap_or(serde_json::Value::Null)),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateCheck => match myownmesh_updater::check_now(true).await {
            Ok(o) => Response::ok(serde_json::to_value(o).unwrap_or(serde_json::Value::Null)),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateApply => match myownmesh_updater::apply_now() {
            Ok(applied) => Response::ok(serde_json::json!({ "applied": applied })),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateSetPrefs { prefs } => {
            match serde_json::from_value::<myownmesh_updater::UpdatePrefs>(prefs) {
                Ok(p) => match myownmesh_updater::set_prefs(p) {
                    Ok(s) => {
                        Response::ok(serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
                    }
                    Err(e) => Response::err(e.to_string()),
                },
                Err(e) => Response::err(format!("bad update prefs: {e}")),
            }
        }
        Request::ServicesStatus => {
            unreachable!("ServicesStatus commits and encodes at the prepared reply boundary")
        }
        Request::ServicesSet { services } => services_set(state, services).await,
        Request::EventsSubscribe => {
            unreachable!("EventsSubscribe switches modes before dispatch")
        }
        Request::TraceSubscribe { .. } => {
            unreachable!("TraceSubscribe switches modes before dispatch")
        }

        // ---- governance ----
        Request::GovernanceState { network } => match state.registry.get(&network) {
            Some(net) => match net.governance_state().await {
                Ok(s) => {
                    // The devices the signed logs have **removed** (evicted, or a
                    // member-tier revoke) — the authoritative "no longer in the
                    // fleet" set, projected from the same member log membership
                    // rides. Surfaced alongside the state so a client can prune
                    // its own local bookkeeping for a device *another* owner
                    // evicted: that eviction converges the signed roster but never
                    // touches the evicting-from-afar owner's local claimed-list,
                    // which would otherwise re-admit the device on the next
                    // re-assertion.
                    let evicted: Vec<String> = myownmesh_core::network_state::member_log_removed(
                        &s,
                        &s.member_log,
                        &network,
                    )
                    .into_iter()
                    .collect();
                    Response::ok(serde_json::json!({ "state": s, "evicted": evicted }))
                }
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeKindChange {
            network,
            to,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::KindChange { to },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeRoleGrant {
            network,
            target,
            role,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::RoleGrant { target, role },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeRoleRevoke {
            network,
            target,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::RoleRevoke { target },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeEvict {
            network,
            target,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::Evict { target },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeTopology {
            network,
            topology,
            hub,
            mfa_code,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => match net
                    .propose_transition(
                        myownmesh_core::TransitionVariant::TopologyChange { to: mode },
                        mfa_code,
                    )
                    .await
                {
                    Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                    Err(e) => Response::err(e.to_string()),
                },
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::GovernanceSign {
            network,
            proposal_id,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net.sign_proposal(&proposal_id, mfa_code).await {
                Ok(_) => Response::ok(serde_json::json!({ "signed": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceDeny {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.deny_proposal(&proposal_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "denied": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceWithdraw {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.withdraw_proposal(&proposal_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "withdrawn": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceSpawnSplit {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.spawn_split(&proposal_id).await {
                Ok(new_id) => Response::ok(serde_json::json!({ "new_network_id": new_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        // ---- custody MFA (per-device, local to this daemon) ----------
        // These act on this daemon's secrets store keyed by network id; they
        // do not require the network to be live in the registry.
        Request::GovernanceMfaEnroll { network } => {
            match myownmesh_core::custody::enroll(&network, &network) {
                Ok(e) => Response::ok(serde_json::json!({
                    "secret": e.secret_b32,
                    "otpauth_uri": e.otpauth_uri,
                    "recovery_codes": e.recovery_codes,
                })),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::GovernanceMfaStatus { .. } => {
            unreachable!("GovernanceMfaStatus is encoded from scalar state before dispatch")
        }
        Request::GovernanceMfaDisable { .. } => {
            unreachable!("GovernanceMfaDisable is completed at the prepared reply boundary")
        }

        // ---- RPC handler claims --------------------------------------
        Request::RpcRegister { .. } => {
            unreachable!("RpcRegister commits and encodes at the prepared reply boundary")
        }

        Request::RpcUnregister { .. } => {
            unreachable!("RpcUnregister commits and encodes at the prepared reply boundary")
        }

        // ---- inbound-RPC responses (from IPC handler back to daemon)
        Request::RpcRespond { .. } => {
            unreachable!("RpcRespond commits and encodes at the prepared reply boundary")
        }

        Request::RpcStreamChunk { .. } => {
            unreachable!("RpcStreamChunk commits and encodes at the prepared reply boundary")
        }

        Request::RpcStreamEnd { .. } => {
            unreachable!("RpcStreamEnd commits and encodes at the prepared reply boundary")
        }

        // ---- outbound RPC --------------------------------------------
        Request::RpcCall {
            network,
            peer,
            method,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let rpc = net.rpc();
            let result = tokio::select! {
                biased;
                () = cancel.cancelled() => return Response::err("control connection closing"),
                result = rpc.call(&peer, &method, payload) => result,
            };
            match result {
                Ok(resp) => Response::ok(serde_json::json!({ "response": resp.body })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::RpcCallStream {
            client_id,
            client_capability,
            network,
            peer,
            method,
            payload,
        } => {
            let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
                return Response::err("invalid local client authority");
            };
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            // The lib's `call_stream` allocates a request_id
            // internally but doesn't expose it; we mirror its
            // shape and tag chunks on the wire with a fresh
            // daemon-side id so the IPC client can correlate
            // its in-flight calls.
            let request_id = match state.clients.next_call_stream_id() {
                Ok(id) => format!("ipc-stream-{id}"),
                Err(refusal) => {
                    return Response::err(format!("rpc call stream refused: {refusal}"))
                }
            };
            // Funded before the call is placed, not after. The forwarding task
            // is the only thing that will ever drain the receiver this call
            // returns, so a refusal discovered afterwards would leave a stream
            // open on the peer with nothing on this side reading it — the peer
            // would keep producing into a queue that never empties. Refusing
            // first means the only thing that did not happen is the call.
            //
            // The claim covers the task *and* the copy of `request_id` the task
            // keeps: the id is re-sent on every chunk and on the terminal frame,
            // so the clone below lives exactly as long as the task does. A bare
            // task claim would have called that string free, and its length is
            // not fixed — it is a decimal counter that grows with the number of
            // streams this daemon has opened, so it is charged rather than
            // waved through as small.
            let task = match state.clients.lease_task_retaining(request_id.len()) {
                Ok(task) => task,
                Err(refusal) => {
                    return Response::err(format!("rpc call stream refused: {refusal}"))
                }
            };
            let rpc = net.rpc();
            let call = tokio::select! {
                biased;
                () = cancel.cancelled() => return Response::err("control connection closing"),
                result = rpc.call_stream(&peer, &method, payload) => result,
            };
            let rx = match call {
                Ok(rx) => rx,
                Err(e) => return Response::err(e.to_string()),
            };
            let writer_tx = client.writer_tx.clone();
            let stream_owner = client.clone();
            // Past the admission above, so the bytes are funded before they exist.
            let req_id_for_task = request_id.clone();
            tokio::spawn(async move {
                // Moved in, so the lease is released exactly when this task
                // stops — including on every early `return` below.
                let _task = task;
                let mut rx = rx;
                loop {
                    let chunk = tokio::select! {
                        () = stream_owner.wait_disconnected() => return,
                        chunk = rx.recv() => chunk,
                    };
                    let Some(chunk) = chunk else { break };
                    match chunk {
                        Ok(payload) => {
                            // A chunk this client's mailbox will not admit ends
                            // the stream rather than being skipped. A skipped
                            // chunk would reach the client as a gap it cannot
                            // see — the frames carry no sequence — so the
                            // stream would appear to have completed with a hole
                            // in it. Terminating says what happened instead.
                            if let Err(refusal) =
                                writer_tx.send(crate::ipc::ServerOut::RpcCallStreamChunk {
                                    request_id: req_id_for_task.clone(),
                                    payload: payload.into_value(),
                                })
                            {
                                let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                                    request_id: req_id_for_task.clone(),
                                    error: Some(format!(
                                        "local stream chunk was refused: {}",
                                        refusal.into_admission_error()
                                    )),
                                });
                                return;
                            }
                        }
                        Err(err) => {
                            let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                                request_id: req_id_for_task.clone(),
                                error: Some(err),
                            });
                            return;
                        }
                    }
                }
                // The two terminal sends above and this one are the last frame
                // on this stream either way, so a refusal here has nowhere left
                // to be reported: the client is gone or its mailbox is closed.
                let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                    request_id: req_id_for_task,
                    error: None,
                });
            });
            Response::ok(serde_json::json!({ "request_id": request_id }))
        }

        // ---- typed channels ------------------------------------------
        Request::ChannelSubscribe { .. } => {
            unreachable!("ChannelSubscribe commits and encodes at the prepared reply boundary")
        }

        Request::ChannelUnsubscribe { .. } => {
            unreachable!("ChannelUnsubscribe commits and encodes at the prepared reply boundary")
        }

        Request::ChannelSendTo { .. } => {
            unreachable!("ChannelSendTo sends and encodes at the prepared reply boundary")
        }

        Request::ChannelSendReliable { .. } => {
            unreachable!("ChannelSendReliable waits and encodes at the prepared reply boundary")
        }

        Request::ChannelSendAll { .. } => {
            unreachable!("ChannelSendAll sends and encodes at the prepared reply boundary")
        }

        Request::CapabilitiesSet { .. } => {
            unreachable!("CapabilitiesSet commits and encodes at the prepared reply boundary")
        }

        // Handled in `handle_client` (it converts the whole connection); never
        // reaches the per-request dispatcher.
        Request::RealtimePipe { .. } => {
            unreachable!("RealtimePipe switches framing modes before dispatch")
        }
    }
}
