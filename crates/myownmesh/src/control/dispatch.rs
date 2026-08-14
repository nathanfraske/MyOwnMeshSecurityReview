//! The control protocol's request router.
//!
//! One exhaustive `match` over [`Request`], and nothing else: a new request
//! variant is a compile error here rather than a silent fallthrough, which is
//! why the match was not split into per-domain sub-matches with catch-alls.
//! The work behind an arm lives in the domain module named for it.

use std::sync::Arc;

use myownmesh_core::{realtime::RealtimeRefusal, transport as core_webrtc};

pub(super) mod network;
pub(super) mod services;

use super::{ConnectionCancel, ControlState, Request, Response};
use crate::control::framing::{FundedVariableReply, OperationReplyData, VariableOperationPlan};

fn realtime_refusal(plan: VariableOperationPlan, refusal: RealtimeRefusal) -> FundedVariableReply {
    plan.finish(Ok(OperationReplyData::RealtimeRefused {
        error: refusal.to_string(),
        code: refusal.code().to_owned(),
    }))
}

pub(super) async fn dispatch_realtime_funded(
    state: &Arc<ControlState>,
    request: Request,
    plan: VariableOperationPlan,
) -> FundedVariableReply {
    match request {
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
            let Some(owner) = state.clients.authenticate(client_id, &client_capability) else {
                return plan.finish(Err("invalid local client authority".to_owned()));
            };
            let Some(net) = state.registry.get(&network) else {
                return plan.finish(Err(format!("unknown network: {network}")));
            };
            let chosen = flow_label.clone();
            let open = core_webrtc::WebRtcRealtimeFlowOpen {
                label: flow_label.into_bytes(),
                direction,
                kind: rtp_kind,
                mime,
                clock_rate,
                channels,
            };
            match net.open_webrtc_realtime(&peer, open).await {
                Ok(flow) => match state.clients.install_realtime_flow(&owner, network, flow) {
                    Ok(capability) => plan.finish(Ok(OperationReplyData::RealtimeOpened {
                        flow_label: chosen,
                        capability: capability.expose().to_owned(),
                    })),
                    Err(rejected) => {
                        let reason = rejected.reason.to_string();
                        let _ = net.close_realtime(rejected.flow).await;
                        plan.finish(Err(format!("realtime flow open refused: {reason}")))
                    }
                },
                Err(refusal) => realtime_refusal(plan, refusal),
            }
        }
        Request::RealtimeFlowClose {
            client_id,
            client_capability,
            flow_capability,
        } => {
            let Some(owner) = state.clients.authenticate(client_id, &client_capability) else {
                return plan.finish(Err("invalid local client authority".to_owned()));
            };
            let Some(flow) = owner.take_realtime_flow(&flow_capability) else {
                return plan.finish(Err("unknown flow_capability: it was never issued to this client, or the flow it named has already been closed".to_owned()));
            };
            let Some(net) = state.registry.get(flow.network()) else {
                return plan.finish(Err(format!("unknown network: {}", flow.network())));
            };
            match flow.close_through(&net).await {
                Ok(()) => plan.finish(Ok(OperationReplyData::Closed)),
                Err(refusal) => realtime_refusal(plan, refusal),
            }
        }
        _ => unreachable!("funded realtime dispatcher receives only realtime requests"),
    }
}

pub(super) async fn dispatch_rpc_stream_funded(
    state: &Arc<ControlState>,
    cancel: &ConnectionCancel,
    request: Request,
    plan: VariableOperationPlan,
) -> FundedVariableReply {
    let Request::RpcCallStream {
        client_id,
        client_capability,
        network,
        peer,
        method,
        payload,
    } = request
    else {
        unreachable!("funded stream dispatcher receives only RpcCallStream")
    };
    let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
        return plan.finish(Err("invalid local client authority".to_owned()));
    };
    let Some(net) = state.registry.get(&network) else {
        return plan.finish(Err(format!("unknown network: {network}")));
    };
    let request_id = match state.clients.next_call_stream_id() {
        Ok(id) => format!("ipc-stream-{id}"),
        Err(refusal) => return plan.finish(Err(format!("rpc call stream refused: {refusal}"))),
    };
    let task = match state.clients.lease_task_retaining(request_id.len()) {
        Ok(task) => task,
        Err(refusal) => return plan.finish(Err(format!("rpc call stream refused: {refusal}"))),
    };
    let rpc = net.rpc();
    let call = tokio::select! {
        biased;
        () = cancel.cancelled() => return plan.finish(Err("control connection closing".to_owned())),
        result = rpc.call_stream(&peer, &method, payload) => result,
    };
    let mut rx = match call {
        Ok(rx) => rx,
        Err(error) => return plan.finish(Err(error.to_string())),
    };
    let writer_tx = client.writer_tx.clone();
    let stream_owner = client.clone();
    let req_id_for_task = request_id.clone();
    tokio::spawn(async move {
        let _task = task;
        loop {
            let chunk = tokio::select! {
                () = stream_owner.wait_disconnected() => return,
                chunk = rx.recv() => chunk,
            };
            let Some(chunk) = chunk else { break };
            match chunk {
                Ok(payload) => {
                    if let Err(refusal) =
                        writer_tx.send(crate::ipc::ServerOut::RpcCallStreamChunk {
                            request_id: req_id_for_task.clone(),
                            payload,
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
                Err(error) => {
                    let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                        request_id: req_id_for_task.clone(),
                        error: Some(error),
                    });
                    return;
                }
            }
        }
        let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
            request_id: req_id_for_task,
            error: None,
        });
    });
    plan.finish(Ok(OperationReplyData::RpcStreamStarted(request_id)))
}

pub(super) async fn dispatch(
    _state: &Arc<ControlState>,
    _cancel: &ConnectionCancel,
    req: Request,
) -> Response {
    match req {
        Request::Status => {
            unreachable!("Status commits and encodes at the prepared reply boundary")
        }
        Request::IdentityShow | Request::IdentitySetLabel { .. } => {
            unreachable!("identity replies retain their funded owner through write")
        }
        Request::NetworksList => {
            unreachable!("NetworksList commits and encodes at the prepared reply boundary")
        }
        Request::PeersList { .. } => {
            unreachable!("PeersList commits and encodes at the prepared reply boundary")
        }
        Request::RosterList { .. } => {
            unreachable!("RosterList commits and encodes at the prepared reply boundary")
        }
        Request::RosterApprove {
            network: _,
            device_id: _,
            label: _,
        }
        | Request::RosterRemove { .. } => {
            unreachable!("roster mutations retain their funded result through write")
        }
        Request::TopologySet { .. } => {
            unreachable!("topology mutation retains its funded result through write")
        }
        Request::NetworkIdGenerate | Request::NetworkIdNormalize { .. } => {
            unreachable!("network ids commit and encode at the prepared reply boundary")
        }
        Request::ConfigShow => {
            unreachable!("ConfigShow loads and encodes at the prepared reply boundary")
        }
        Request::NetworkAdd { .. } => {
            unreachable!("network add retains its funded result through write")
        }
        Request::NetworkRemove { .. } => {
            unreachable!("network remove retains its funded result through write")
        }
        Request::ForgetAllNetworks | Request::FactoryReset => {
            unreachable!("network reset results retain their funded owner through write")
        }
        Request::NetworkUpdate { .. } => {
            unreachable!("network update retains its funded result through write")
        }
        Request::NetworkReconnect { .. } | Request::NetworkConnectPeer { .. } => {
            unreachable!("network connection results retain their funded owner through write")
        }

        // ---- realtime flows ----
        Request::RealtimeFlowOpen { .. } | Request::RealtimeFlowClose { .. } => {
            unreachable!("realtime flow results retain their funded owner through write")
        }

        // ---- self-update ----
        Request::UpdateStatus | Request::UpdateCheck | Request::UpdateSetPrefs { .. } => {
            unreachable!("variable updater results commit and encode before dispatch")
        }
        Request::UpdateApply => {
            unreachable!("updater apply retains its funded result through write")
        }
        Request::ServicesStatus => {
            unreachable!("ServicesStatus commits and encodes at the prepared reply boundary")
        }
        Request::ServicesSet { .. } => {
            unreachable!("services-set retains its funded result through write")
        }
        Request::EventsSubscribe => {
            unreachable!("EventsSubscribe switches modes before dispatch")
        }
        Request::TraceSubscribe { .. } => {
            unreachable!("TraceSubscribe switches modes before dispatch")
        }

        // ---- governance ----
        Request::GovernanceState { .. } => {
            unreachable!("GovernanceState commits and encodes at the prepared reply boundary")
        }
        Request::GovernanceProposeKindChange { .. }
        | Request::GovernanceProposeRoleGrant { .. } => {
            unreachable!("governance proposals retain their funded result through write")
        }
        Request::GovernanceProposeRoleRevoke { .. } | Request::GovernanceProposeEvict { .. } => {
            unreachable!("governance proposals retain their funded result through write")
        }
        Request::GovernanceProposeTopology { .. } => {
            unreachable!("governance topology proposals retain their funded result through write")
        }
        Request::GovernanceSign { .. }
        | Request::GovernanceDeny { .. }
        | Request::GovernanceWithdraw { .. }
        | Request::GovernanceSpawnSplit { .. } => {
            unreachable!("governance mutations retain their funded result through write")
        }
        // ---- custody MFA (per-device, local to this daemon) ----------
        // These act on this daemon's secrets store keyed by network id; they
        // do not require the network to be live in the registry.
        Request::GovernanceMfaEnroll { .. } => {
            unreachable!("MFA enrollment retains its funded result through the prepared write")
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
        Request::RpcCall { .. } => {
            unreachable!("RpcCall retains its funded result through the prepared write boundary")
        }

        Request::RpcCallStream { .. } => {
            unreachable!("RPC stream setup retains its funded identity through write")
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
