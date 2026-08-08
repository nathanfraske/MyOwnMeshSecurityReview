//! Connection engine — the runtime that turns the protocol +
//! transport + topology primitives into a working mesh.
//!
//! Each joined network spins up one engine task graph:
//!
//! - **Driver** loop (`run_driver`) — owns the
//!   [`state::NetworkState`] and processes the per-network
//!   command queue, signaling events, and per-peer transport
//!   events serially.
//! - **Scheduler** ticks ([`scheduler`]) — heartbeat, offline
//!   check, reconnect prune, ICE poll. Each tick is named so the
//!   wake detector can attribute a tick gap to the right timer.
//! - **Per-peer transport pumps** — one task per active peer
//!   draining the transport mpsc into the driver via the command
//!   queue.
//!
//! Constants are mirrored from MyOwnLLM's `mesh-client.svelte.ts`
//! and are documented in `CONNECTION-ENGINE-FIELD-NOTES.md`. Do not relax them
//! without understanding the corresponding field-discovered bug.

pub mod conn_trace;
pub mod connection;
pub mod governance;
pub mod handshake;
pub mod heartbeat;
pub mod ice_watchdog;
pub mod ladder;
pub mod network_watch;
pub mod phase;
pub mod reconcile;
pub mod reliable;
pub mod scheduler;
pub mod signaling_bridge;
pub(crate) mod state;
pub mod tick;
pub mod traffic;
pub mod wake;

pub use signaling_bridge::{
    attach_local, attach_mdns, attach_nostr, attach_signaling, SignalingDrivers,
};

/// Minimum gap between announces we publish in response to a peer's
/// announce. The engine fires one reflected announce per inbound
/// announce; this floor coalesces a burst of inbound announces (a
/// new joiner triggering N existing peers to all react at once)
/// into a single outbound publish per N-peer wave so we don't put
/// quadratic load on the relay pool.
const REACTIVE_ANNOUNCE_MIN_INTERVAL_MS: u64 = 1_000;

/// Minimum gap between re-offers we send to the same peer while
/// their session is stuck at `Sighted` (PC created, data channel
/// never opened). Coalesces REQ-replay announce bursts into one
/// re-offer per window so we don't pile up SDP renegotiations on
/// the remote PC. Sized small enough that two restart-aligned
/// peers converge inside a handful of seconds.
const REOFFER_MIN_INTERVAL_MS: u64 = 2_000;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;

use crate::config::NetworkConfig;
use crate::error::{Error, Result};
use crate::events::{DropReason, MeshEvent, PeerEvent};
use crate::identity::Identity;
use crate::protocol::{
    rpc::{
        CapabilitiesUpdateMessage, RpcRequestMessage, RpcResponseMessage, RpcStreamChunkMessage,
        RpcStreamEndMessage,
    },
    topology::ShelveMessage,
    CapabilityAdvert, MeshMessage,
};
use crate::resource::{MeshRuntimeResourceScope, ProcessResourceRoot};
use crate::transport::{
    DataChannelOpenOwnership, RemoteCandidateDisposition, Role, Transport, TransportEvent,
    WebRtcConnectorEvent,
};

use connection::{PeerConnection, PeerStatus};
use ladder::ConnectionTier;
#[cfg(feature = "legacy-media")]
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264 and Opus compatibility surface"
)]
pub use state::{InboundAudioSample, InboundVideoSample};
pub use state::{NetworkCmd, NetworkState, SignalingInbound, SignalingOutbound};

/// Spawn the engine for a single joined network. Returns the
/// shared [`NetworkState`] handle plus the join handle of the
/// driver task (waitable for clean shutdown).
pub async fn spawn_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    spawn_network_in_mesh_scope(config, identity, transport, &mesh_scope).await
}

pub(crate) async fn spawn_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let (state, signaling_inbound_rx, cmd_rx) =
        NetworkState::new_in_mesh_scope(config, identity, transport, mesh_scope)?;
    let driver_state = state.clone();
    let handle = tokio::spawn(async move {
        run_driver(driver_state, signaling_inbound_rx, cmd_rx).await;
    });
    Ok((state, handle))
}

/// The engine's main loop. Owns the per-network state and the
/// fan-in mpsc that consolidates signaling, transport, and
/// command events.
pub async fn run_driver(
    state: Arc<NetworkState>,
    mut signaling_inbound: mpsc::UnboundedReceiver<SignalingInbound>,
    mut cmd_rx: mpsc::UnboundedReceiver<NetworkCmd>,
) {
    state.log_diag(crate::events::DiagLevel::Info, "engine", "driver starting");
    // Settle the signed-eviction verdict from the persisted governance
    // state before anything announces or dials: a device evicted in a
    // previous run must come up stood-down (and re-emit the event so an
    // embedding app that missed it can clean up), not spend another
    // session redialing into denials.
    governance::refresh_self_evicted(&state);
    // Surface the ICE-server configuration so users can confirm at
    // a glance whether they have any relay coverage. Mirrors
    // MyOwnLLM's pattern: when peers get stuck at ICE-checking with
    // 0 relay candidates, this line is the first thing to point at.
    {
        let cfg = state.config.read();
        let stun_count: usize = cfg.stun_servers.iter().map(|s| s.urls.len()).sum();
        let turn_count: usize = cfg.turn_servers.iter().map(|s| s.urls.len()).sum();
        let turn_summary = if turn_count == 0 {
            "no TURN configured (CGNAT / phone-hotspot will fail to connect)".to_string()
        } else {
            format!("{turn_count} TURN URL(s)")
        };
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "engine",
            format!("ICE servers: {stun_count} STUN URL(s), {turn_summary}"),
            serde_json::json!({
                "stun_count": stun_count,
                "turn_count": turn_count,
                "auto_approve": cfg.auto_approve,
            }),
        );
        drop(cfg);
    }

    // Top-level interval ticks. We hold them across the loop so
    // sleeping happens inside `tokio::select!` — no separate
    // task means a wake-event after a long-sleep tick gap is
    // observable here without coordination.
    let mut heartbeat =
        tokio::time::interval(Duration::from_millis(scheduler::HEARTBEAT_INTERVAL_MS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // One periodic pass replaces the old separate ICE-watchdog and
    // network-watch intervals. Recovery is event-driven first; this is the
    // secondary safety-net tick (see `scheduler::STATE_WATCH_INTERVAL_MS`)
    // that confirms state and handles the inherently time-based conditions.
    let mut state_watch =
        tokio::time::interval(Duration::from_millis(scheduler::STATE_WATCH_INTERVAL_MS));
    state_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The secondary control path: a registry of time-based subsystems run on
    // each state-watch tick. Events drive state; these confirm and repair the
    // conditions no event can signal. New network-intelligence systems plug in
    // here — see `engine::tick`.
    let mut tick_registry = tick::TickRegistry::new()
        .register(tick::IceWatchdogTicker)
        .register(tick::NetworkWatchTicker::new().await)
        .register(tick::ReconnectSupervisor)
        .register(tick::ReliableSendTicker)
        .register(tick::TopologyShapeTicker)
        .register(tick::MediaRenegotiationTicker);
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "engine",
        format!("state-watch tick registry: {:?}", tick_registry.names()),
        serde_json::json!({ "tickers": tick_registry.names() }),
    );
    let mut wake_detector = wake::WakeDetector::new();
    // Phase-0 connection tracer. Observes per-peer connection-state
    // transitions after each driver-loop iteration. Zero cost unless a
    // `ctl trace` subscriber is attached or `MYOWNMESH_CONN_TRACE` is
    // set — see `engine::conn_trace`.
    let mut conn_tracer = conn_trace::ConnTracer::new();

    // Why the loop below exits — surfaced in the "driver stopping" line so a
    // restart's *cause* is greppable. A network re-join (leave + re-join) is
    // the only way a fresh `run_driver`/Nostr driver appears mid-run, and
    // chasing one in the field is otherwise guesswork: "shutdown command" is a
    // deliberate leave/`network_update`/`network_remove`, "command channel
    // closed" is the registry dropping us, "signaling channel closed" is the
    // relay/signaling feed dying.
    let stop_reason: &str = loop {
        tokio::select! {
            biased;

            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break "command channel closed" };
                if !handle_command(&state, cmd).await {
                    break "shutdown command";
                }
            }

            sig = signaling_inbound.recv() => {
                let Some(sig) = sig else {
                    warn!(network = %state.network_id, "signaling channel closed");
                    break "signaling channel closed";
                };
                handle_signaling_inbound(&state, sig).await;
            }

            _ = heartbeat.tick() => {
                wake_detector.observe(Instant::now(), scheduler::HEARTBEAT_INTERVAL_MS);
                heartbeat::tick(&state).await;
                if wake_detector.take_wake_event() {
                    debug!(network = %state.network_id, "wake event observed");
                    wake::on_wake(&state).await;
                }
            }

            _ = state_watch.tick() => {
                // Secondary safety net only — events drive recovery. Each
                // registered ticker confirms its slice of state and repairs the
                // time-based conditions no event can signal. The trace doubles
                // as the driver's liveness heartbeat in debug captures: when
                // the driver wedges, this is the line that stops.
                trace!(network = %state.network_id, "driver: state-watch tick");
                tick_registry.run(&state).await;
            }
        }

        // Observe the post-event connection state. Cheap no-op unless
        // someone is watching; never holds a per-peer lock across an
        // await (the handler above has already returned).
        conn_tracer.sweep(&state);
    };

    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "engine",
        format!("driver stopping ({stop_reason})"),
        serde_json::json!({ "reason": stop_reason }),
    );
    state.shutdown().await;
}

async fn handle_command(state: &Arc<NetworkState>, cmd: NetworkCmd) -> bool {
    match cmd {
        NetworkCmd::Shutdown => return false,
        NetworkCmd::SetTopology(mode) => {
            // Backstop for the control-path check: once a ratified
            // TopologyChange owns the shape, a local set must not
            // fork this device off the governed topology.
            if state.governance_state.read().topology.is_some() {
                tracing::warn!(
                    network = %state.network_id,
                    "ignoring local topology set — this network's topology \
                     is governed by a signed owner transition"
                );
            } else {
                *state.topology.write() = mode.clone();
                *state.topology_impl.write() = crate::topology::from_mode(&mode);
                ladder::reevaluate_topology(state).await;
            }
        }
        NetworkCmd::ApproveRoster {
            device_id,
            label,
            reply,
        } => {
            let result = state.approve_roster(&device_id, &label).await;
            // A successful approval changed our roster — advertise the new
            // membership so other members converge (the same path the
            // mutual-confirmation handshake takes, here for the explicit
            // user-approve case).
            if result.is_ok() {
                governance::broadcast_roster_summary(state).await;
            }
            let _ = reply.send(result);
        }
        NetworkCmd::RemoveRoster { device_id, reply } => {
            let result = state.remove_roster(&device_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::DropPeer { device_id, reason } => {
            drop_peer(state, &device_id, reason).await;
        }
        NetworkCmd::Reconnect { peer } => match peer {
            Some(device_id) => network_watch::reconnect_peer_in_place(state, &device_id).await,
            None => network_watch::reconnect_all_in_place(state).await,
        },
        NetworkCmd::ConnectPeer {
            device_id,
            sticky,
            reply,
        } => connect_peer(state, &device_id, sticky, reply).await,
        #[cfg(feature = "legacy-media")]
        NetworkCmd::MediaLaneOpen { peer, kind, reply } => {
            let flow = admitted_realtime_operation(state, &peer);
            let result = match flow {
                Some(flow) => flow.open_media_lane(kind).await,
                None => Err(Error::Network(format!(
                    "peer real-time flow not admitted: {peer}"
                ))),
            };
            let _ = reply.send(result);
        }
        #[cfg(feature = "legacy-media")]
        NetworkCmd::MediaLaneClose {
            peer,
            kind,
            lane,
            reply,
        } => {
            let flow = admitted_realtime_operation(state, &peer);
            let result = match flow {
                Some(flow) => flow.close_media_lane(kind, lane).await,
                None => Ok(()), // no session, nothing open — close is idempotent
            };
            let _ = reply.send(result);
        }
        NetworkCmd::SendChannelReliable {
            peer,
            channel,
            payload,
            ttl_ms,
            reply,
        } => {
            reliable::enqueue(state, &peer, &channel, payload, ttl_ms, reply).await;
        }
        NetworkCmd::SendChannelFrame {
            peer,
            channel,
            payload,
            reply,
        } => {
            let result = send_channel_frame(state, &peer, &channel, payload).await;
            let _ = reply.send(result);
        }
        NetworkCmd::BroadcastChannelFrame {
            channel,
            payload,
            reply,
        } => {
            let count = broadcast_channel_frame(state, &channel, payload).await;
            let _ = reply.send(count);
        }
        NetworkCmd::SendRpcRequest {
            peer,
            request,
            reply,
        } => {
            let result = send_rpc_request(state, &peer, request).await;
            let _ = reply.send(result);
        }
        NetworkCmd::BroadcastCapabilities { caps, reply } => {
            let _ = reply.send(broadcast_capabilities(state, caps).await);
        }
        // ---- governance ops ----
        NetworkCmd::ProposeTransition {
            variant,
            mfa_code,
            reply,
        } => {
            let result = governance::propose(state, variant, mfa_code.as_deref()).await;
            let _ = reply.send(result);
        }
        NetworkCmd::SignProposal {
            proposal_id,
            mfa_code,
            reply,
        } => {
            let result = governance::sign_proposal(state, &proposal_id, mfa_code.as_deref()).await;
            let _ = reply.send(result);
        }
        NetworkCmd::DenyProposal { proposal_id, reply } => {
            let result = governance::deny_proposal(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::WithdrawProposal { proposal_id, reply } => {
            let result = governance::withdraw_proposal(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::SpawnSplit { proposal_id, reply } => {
            let result = governance::spawn_split(state, &proposal_id).await;
            let _ = reply.send(result);
        }
        NetworkCmd::GovernanceSnapshot { reply } => {
            let _ = reply.send(governance::snapshot(state));
        }
    }
    true
}

/// True when a session has been *connecting* (its data channel never
/// opened) for at least `grace_ms`. A fresh offer arriving on such a
/// session is better answered by a clean rebuild than by renegotiating
/// onto the stuck PC: re-applying `set_remote_description` only re-resets
/// ICE, and when both sides are stuck-and-re-offering it deadlocks (the
/// answerer keeps mis-applying the offerer's offers, the data channel
/// never opens — observed in the field as a peer pinned at Sighted over
/// TURN). The grace lets a legitimately-still-negotiating attempt finish
/// before a re-offer triggers a rebuild, so a burst of re-offers can't
/// churn it.
fn connecting_stuck_past_grace(data: &connection::PeerStateData, grace_ms: u64) -> bool {
    !data.data_channel_open
        && data
            .session_started_at
            .map(|t| t.elapsed() >= Duration::from_millis(grace_ms))
            .unwrap_or(false)
}

async fn handle_signaling_inbound(state: &Arc<NetworkState>, sig: SignalingInbound) {
    // Entry trace: signaling handlers run inline on the driver, so in a
    // debug capture the last of these lines names the message being handled
    // when the driver stopped.
    trace!(network = %state.network_id, kind = sig.kind_name(), "driver: signaling inbound");
    state
        .traffic
        .record_signaling_rx(matches!(sig, SignalingInbound::PeerAnnounced { .. }));
    match sig {
        SignalingInbound::PeerAnnounced { device_id } => {
            // A stood-down engine (this device is signed-evicted from the
            // network) ignores the mesh entirely: no reflect, no dial —
            // every member would deny us anyway, with proof.
            //
            // Deliberately NO symmetric gate for announces FROM an
            // evicted device: a session with it is the only channel the
            // eviction proof can travel down. One handshake → one deny
            // carrying the signed log → the device flips to stood-down
            // and stops announcing — the mesh converges to silence in a
            // single round trip, which no amount of ignoring achieves.
            if state.self_evicted.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            // Whoever holds the lex-lower id initiates so we don't
            // glare on simultaneous discovery. Symmetric across
            // peers because base32 ids sort the same on both ends.
            let me = state.identity.public_id().to_string();
            let role = if me < device_id {
                Role::Offerer
            } else {
                Role::Answerer
            };
            // Cross-relay dedup happens at the Nostr driver layer
            // (see `upstream.rs` item 6 + the driver's
            // `seen_event_ids`), so this fires once per actual
            // periodic re-announce — not once per relay-delivery
            // copy of the same announce. Every announce lands in
            // the log so the user can see signaling is alive even
            // for peers already in steady state; redundant work
            // (re-opening the peer slot) is short-circuited inside
            // `ensure_peer_session` without affecting the log.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "signaling",
                format!(
                    "peer announced: {} (we are {role:?})",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id, "role": format!("{role:?}") }),
            );
            // Reflect every inbound announce with one of our own.
            // The dense `ANNOUNCE_BACKOFF_MS` schedule covers fresh
            // joiners well enough on its own, but it doesn't help a
            // peer that's been in steady-state 60 s cadence for ten
            // minutes — when a new third peer arrives, that
            // steady-state peer's next announce could be up to 60 s
            // away, and meanwhile the joiner only sees whichever
            // existing peer happens to re-announce first (the
            // star-around-first-peer symptom). Reflecting on every
            // received announce guarantees the joiner sees every
            // existing peer in one round-trip, regardless of where
            // each existing peer sits on its announce schedule.
            // Rate-limited globally so N peers all reacting to a
            // join don't produce N^2 publishes.
            maybe_reactive_announce(state);
            // If we already have a session for this peer that's
            // stuck at Sighted (PC created but data channel never
            // opened) and we're the Offerer, re-poke the other
            // side with a fresh offer. webrtc-rs `create_offer`
            // calls `set_local_description` internally, which
            // kicks off a new ICE gathering cycle on the same PC
            // — no teardown needed, the remote handles the
            // renegotiation transparently. Rate-limited per-peer
            // via `last_offer_sent_at` so the announce burst from
            // a REQ replay (we've observed ~14 in one ms) doesn't
            // translate into a fan of fourteen offers. Only fires
            // for `Sighted` so once the channel opens and status
            // advances to `Handshaking` / `Active` / etc. we stop
            // re-offering automatically — no extra teardown
            // logic, no extra timer.
            let reoffer_session = if role == Role::Offerer {
                state.peers.get(&device_id).and_then(|p| {
                    let mut data = p.state.write();
                    if !matches!(data.status, PeerStatus::Sighted) {
                        return None;
                    }
                    let due = data
                        .last_offer_sent_at
                        .map(|prev| {
                            Instant::now().duration_since(prev)
                                >= Duration::from_millis(REOFFER_MIN_INTERVAL_MS)
                        })
                        .unwrap_or(true);
                    if !due {
                        return None;
                    }
                    data.last_offer_sent_at = Some(Instant::now());
                    p.session.lock().clone()
                })
            } else {
                None
            };
            if let Some(session) = reoffer_session {
                match session.create_offer().await {
                    Ok(desc) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Debug,
                            "signaling",
                            format!("re-offer to {} (stuck at Sighted)", short_peer(&device_id)),
                            serde_json::json!({
                                "peer": device_id,
                                "sdp_bytes": desc.sdp.len(),
                                "reason": "stuck-at-sighted",
                            }),
                        );
                        let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                            device_id: device_id.clone(),
                            sdp: desc.sdp,
                        });
                    }
                    Err(e) => {
                        warn!(peer = %device_id, "re-offer create_offer failed: {e}");
                    }
                }
            }
            // A live peer that re-announced while its ICE is down most
            // likely had its network move — the answerer side of a handoff
            // prods us this way (it re-gathered and can't send us a
            // competing offer). If we're its offerer, renegotiate now so it
            // recovers in place rather than waiting out our own consent
            // timer. Single-flighted inside `renegotiate_ice`.
            if role == Role::Offerer {
                let unhealthy = state
                    .peers
                    .get(&device_id)
                    .and_then(|p| {
                        let session = p.session.lock().clone()?;
                        let status = p.state.read().status;
                        Some(
                            matches!(status, PeerStatus::Active | PeerStatus::Shelved)
                                && !matches!(
                                    session.ice_connection_state(),
                                    RTCIceConnectionState::Connected
                                        | RTCIceConnectionState::Completed
                                ),
                        )
                    })
                    .unwrap_or(false);
                // A session silent past the stale-inbound window is a
                // wake/rebuild candidate, not a restart candidate: an ICE
                // restart at a peer that rebuilt its PeerConnection during
                // sleep can never converge, and its IceRestart tier
                // suppresses the fast confirm-rebuild below — turning an
                // instant wake reconnect into a 10-90s stall. Restart only
                // recently-alive sessions; leave corpses to the confirm
                // probe (~1.5s teardown + fresh dial).
                let recently_alive = state
                    .peers
                    .get(&device_id)
                    .and_then(|p| p.state.read().last_recv_at)
                    .is_some_and(|at| {
                        at.elapsed().as_millis() < scheduler::STALE_INBOUND_MS as u128
                    });
                if unhealthy && recently_alive {
                    renegotiate_ice(state, &device_id, false, "announce-unhealthy").await;
                }
            }
            clear_stale_session_if_zombie(state, &device_id).await;
            // `clear_stale_session_if_zombie` drops a stale session only when
            // ICE itself admits the link is dead; one whose ICE falsely
            // reports `Connected` survives it. Confirm *that* case with real
            // traffic so a peer that restarted without a `Leave` recovers
            // from its announce instead of stranding on the corpse.
            confirm_active_session_on_announce(state, &device_id).await;
            // On a Silent network the engine never dials just because a peer
            // announced — being co-present must not open a connection. Record
            // the peer as discovered (Sighted, no WebRTC session) so the app
            // can see it and later dial it deliberately via `connect_peer`;
            // everywhere else, auto-dial on presence exactly as before. An
            // inbound Offer is still honoured (that path is not gated), so a
            // peer someone deliberately dials still gets answered.
            if state.is_silent() {
                if state.is_sticky(&device_id) {
                    // The one exception to "Silent never auto-dials": a
                    // pinned peer (a standing support session) redials on
                    // its announce, always as the offerer — the far side
                    // has no pin and would wait forever on lex-order.
                    ensure_peer_session(state, device_id, Role::Offerer).await;
                } else {
                    note_sighted_without_dialing(state, &device_id, "silent network");
                }
            } else {
                // Under a shaped topology, dial only where the selector
                // says an edge exists — this is where ring/star/hubs stop
                // paying full-mesh connection costs. Non-edges are
                // recorded as Sighted so the member stays visible and a
                // later shape change (hub failover, ring re-sort) can
                // dial from the placeholder. Inbound offers are never
                // gated: if the other side computed an edge we didn't
                // (membership transient), answering keeps us connected
                // and the next reevaluation reconciles.
                // A pinned peer (a standing support session) outranks the
                // shape: under hubs a spoke↔spoke pin is a non-edge, and
                // gating its announce-dial parked wake reconnects forever
                // (the sticky reconnect intent parks after ~1 min and waits
                // for exactly this announce-dial). Pins dial as the offerer
                // — the far side has no pin and would wait on lex-order —
                // same rule as the Silent branch and the prune exemption.
                if state.is_sticky(&device_id) {
                    ensure_peer_session(state, device_id, Role::Offerer).await;
                    return;
                }
                let dial = {
                    let topo = state.topology_impl.read();
                    if topo.prunes() {
                        let me = state.identity.public_id().to_string();
                        let mut known = state.peers.device_ids_snapshot();
                        if !known.iter().any(|k| k == &device_id) {
                            known.push(device_id.clone());
                        }
                        known.push(me.clone());
                        topo.edge(&me, &device_id, &known)
                    } else {
                        true
                    }
                };
                if dial {
                    ensure_peer_session(state, device_id, role).await;
                } else {
                    note_sighted_without_dialing(state, &device_id, "no topology edge");
                }
            }
        }
        SignalingInbound::Offer { device_id, sdp } => {
            // If we didn't already start an answerer, do so now.
            let role = Role::Answerer;
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "signaling",
                format!("offer received from {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "sdp_bytes": sdp.len() }),
            );
            clear_stale_session_if_zombie(state, &device_id).await;
            // A *rebuild* offer — one carrying a different DTLS fingerprint
            // than the remote description we last applied — means the peer tore
            // its peer connection down and built a fresh one. Renegotiating our
            // existing PC onto it applies the offer to a corpse: no candidates
            // ever cross and the link wedges (the "0 remote candidates" stall,
            // and the answerer half of the post-handoff deadlock). Drop our
            // side so the fresh answerer PC built below matches theirs. A
            // *restart* offer (same fingerprint, new ufrag) has a matching
            // fingerprint and is left to renegotiate in place. Read the
            // session out of the map first so no DashMap ref is held across the
            // await.
            let existing_session = state
                .peers
                .get(&device_id)
                .and_then(|p| p.session.lock().clone());
            let rebuilt = match existing_session {
                Some(session) => match session.remote_fingerprint().await {
                    Some(prev) => crate::transport::webrtc::sdp_fingerprint(&sdp)
                        .map(|now| now != prev)
                        .unwrap_or(false),
                    // No remote applied yet (we offered, they're now offering —
                    // glare) — nothing to mismatch; fall through.
                    None => false,
                },
                None => false,
            };
            // If our session for this peer has been stuck connecting (data
            // channel never opened) past the grace, this fresh offer is the
            // mutual-renegotiation deadlock: re-applying it onto the stuck
            // PC just re-resets ICE and the channel never opens. Drop the
            // corpse so the offer below builds a clean fresh PC whose data
            // channel — created by the offerer in this very offer — can
            // actually open, aligning our generation to theirs. The grace
            // (via `connecting_stuck_past_grace`) keeps a burst of
            // re-offers from churning a still-negotiating attempt.
            let stuck = state
                .peers
                .get(&device_id)
                .map(|p| {
                    connecting_stuck_past_grace(
                        &p.state.read(),
                        scheduler::RESTART_TRAFFIC_GRACE_MS,
                    )
                })
                .unwrap_or(false);
            if rebuilt || stuck {
                let reason = if rebuilt {
                    "peer rebuilt (new DTLS fingerprint)"
                } else {
                    "stuck connecting"
                };
                state.log_diag_with(
                    crate::events::DiagLevel::Info,
                    "signaling",
                    format!(
                        "fresh offer from {} ({reason}) — rebuilding to answer cleanly",
                        short_peer(&device_id)
                    ),
                    serde_json::json!({
                        "peer": device_id,
                        "reason": if rebuilt { "peer_rebuilt" } else { "stuck_connecting" },
                    }),
                );
                drop_peer(state, &device_id, DropReason::IceFailed).await;
            }
            ensure_peer_session(state, device_id.clone(), role).await;
            apply_remote_sdp(state, &device_id, RTCSdpType::Offer, sdp).await;
            // Build the answer. Extract the session under the lock,
            // drop everything, then await — guards across awaits
            // would make the future non-Send.
            let session = {
                let peer = state.peers.get(&device_id);
                peer.and_then(|p| p.session.lock().clone())
            };
            if let Some(session) = session {
                match session.create_answer().await {
                    Ok(desc) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Debug,
                            "signaling",
                            format!("answer sent to {}", short_peer(&device_id)),
                            serde_json::json!({ "peer": device_id, "sdp_bytes": desc.sdp.len() }),
                        );
                        let _ = state.signaling_tx.send(SignalingOutbound::Answer {
                            device_id: device_id.clone(),
                            sdp: desc.sdp,
                        });
                    }
                    Err(e) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Error,
                            "signaling",
                            format!("create_answer failed for {}: {e}", short_peer(&device_id)),
                            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
                        );
                        warn!(peer = %device_id, "create_answer failed: {e}");
                    }
                }
            }
        }
        SignalingInbound::Answer { device_id, sdp } => {
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "signaling",
                format!("answer received from {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "sdp_bytes": sdp.len() }),
            );
            apply_remote_sdp(state, &device_id, RTCSdpType::Answer, sdp).await;
        }
        SignalingInbound::Candidate {
            device_id,
            candidate,
        } => {
            // The worker decides whether the remote description is ready and
            // owns either the retained queue value or the live application.
            let owner = state.peers.owner(&device_id);
            let worker = owner.as_ref().and_then(|owner| {
                state
                    .peers
                    .get_if_current(owner)
                    .and_then(|peer| peer.session.lock().clone())
            });
            if let (Some(owner), Some(worker)) = (owner, worker) {
                let report = match worker.add_remote_candidate_observed(candidate).await {
                    Ok(report) => report,
                    Err(e) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Warn,
                            "ice",
                            format!(
                                "remote candidate rejected by {}: {e}",
                                short_peer(&device_id)
                            ),
                            serde_json::json!({
                                "peer": device_id,
                                "error": e.to_string(),
                            }),
                        );
                        warn!(peer = %device_id, "add_ice_candidate failed: {e}");
                        return;
                    }
                };
                if report.disposition == RemoteCandidateDisposition::AttemptRetired {
                    return;
                }
                let Some(kind) = report.kind else {
                    return;
                };
                if state
                    .peers
                    .with_current(&owner, |peer| {
                        peer.state.write().diag.remote_candidates.record(kind);
                    })
                    .is_none()
                {
                    return;
                }
                match report.disposition {
                    RemoteCandidateDisposition::Applied => {}
                    RemoteCandidateDisposition::QueuedUntilRemoteDescription => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Debug,
                            "ice",
                            format!(
                                "queued remote {kind:?} candidate from {} (awaiting remote SDP)",
                                short_peer(&device_id)
                            ),
                            serde_json::json!({ "peer": device_id, "kind": format!("{kind:?}") }),
                        );
                    }
                    RemoteCandidateDisposition::DuplicateIgnored => {
                        trace!(peer = %device_id, "duplicate remote candidate ignored");
                    }
                    RemoteCandidateDisposition::AttemptRetired => {}
                    RemoteCandidateDisposition::InvalidBinding(error) => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Warn,
                            "ice",
                            format!(
                                "remote {kind:?} candidate from {} has an invalid ICE username-fragment binding: {}",
                                short_peer(&device_id),
                                error.description()
                            ),
                            serde_json::json!({
                                "peer": device_id,
                                "kind": format!("{kind:?}"),
                                "reason": error.description(),
                            }),
                        );
                    }
                    RemoteCandidateDisposition::RefusedByOwner => {
                        state.log_diag_with(
                            crate::events::DiagLevel::Warn,
                            "ice",
                            format!(
                                "remote {kind:?} candidate from {} reached an owner-selected candidate-attempt ceiling",
                                short_peer(&device_id)
                            ),
                            serde_json::json!({ "peer": device_id, "kind": format!("{kind:?}") }),
                        );
                    }
                }
            }
        }
        SignalingInbound::PeerLeft { device_id } => {
            state.log_diag_with(
                crate::events::DiagLevel::Info,
                "signaling",
                format!("peer left signaling: {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id }),
            );
            drop_peer(state, &device_id, DropReason::UserLeft).await;
        }
    }
}

/// First-and-last-N chars of a peer pubkey for log readability. Long
/// base32 ids drown out the actual message; the prefix + suffix
/// preserves visual identity (same peer always renders the same
/// snippet) without taking up the entire line. `pub(crate)` so the
/// handshake / ladder / watchdog modules render peer IDs in their
/// diag entries the same way.
pub(crate) fn short_peer(id: &str) -> String {
    if id.len() <= 12 {
        return id.to_string();
    }
    format!("{}…{}", &id[..6], &id[id.len() - 4..])
}

/// Emit a presence announce, but only if we haven't already emitted one
/// within `REACTIVE_ANNOUNCE_MIN_INTERVAL_MS`. Every reactive announce
/// — reflecting a peer's announce, re-seeding discovery after a
/// checking-timeout rebuild, kicking discovery on a network change —
/// goes through here so a burst of triggers (a REQ-replay wave, a
/// network handoff dropping several peers at once) can never fan out
/// into a storm of relay publishes. Returns whether the announce was
/// actually emitted. The driver's own steady-state announcer is
/// independent of this and unaffected.
pub(crate) fn maybe_reactive_announce(state: &Arc<NetworkState>) -> bool {
    let mut guard = state.last_reactive_announce_at.lock();
    let now = Instant::now();
    let due = guard
        .map(|prev| {
            now.duration_since(prev) >= Duration::from_millis(REACTIVE_ANNOUNCE_MIN_INTERVAL_MS)
        })
        .unwrap_or(true);
    if due {
        *guard = Some(now);
        drop(guard);
        let _ = state.signaling_tx.send(SignalingOutbound::Announce);
    }
    due
}

/// Re-offer to a peer we hold a reconnect intent for, when conditions allow:
/// we're online, we're the deterministic offerer, and no session is already
/// in flight. Best-effort — a no-op while offline (the relay-reconnect flush
/// and the tick pick it up once we're back) or when a session already exists
/// (its own lifecycle carries it). Nudges discovery first so the remote
/// answerer learns we're trying and reflects an announce, giving its side a
/// clean rebuild to meet our fresh offer. Shared by the event paths
/// (relay-reconnect flush) and the tick's backstop retry.
pub(crate) async fn try_reoffer(state: &Arc<NetworkState>, device_id: &str) {
    if state.is_offline() {
        return;
    }
    if state.peers.contains_key(device_id) {
        return;
    }
    // Only the deterministic offerer (lex-lower id) re-offers; the answerer
    // waits for that offer rather than sending a competing one. A sticky
    // (pinned) peer bypasses the gate: the pin lives on exactly one side —
    // the dialing side — and on a Silent network the other end will never
    // initiate, lex order or not.
    if state.identity.public_id() >= device_id && !state.is_sticky(device_id) {
        return;
    }
    maybe_reactive_announce(state);
    ensure_peer_session(state, device_id.to_string(), Role::Offerer).await;
}

/// Drive the media-lane renegotiations the transport flagged off the
/// driver task. The tick only selects peers with an explicit pending
/// lane-set change and spawns one task per peer. The webrtc-rs excursion
/// remove_track during finalization and ICE re-gather for the offer run
/// there, so the driver and every input frame queued behind it
/// never waits on SDP work. Glare-guarded: a peer whose signaling state
/// isn't Stable is skipped and retried next tick rather than wedging
/// webrtc-rs with a mid-negotiation offer. Single-flighted per peer via
/// `media_reneg_inflight`.
pub(crate) async fn service_media_renegotiations(state: &Arc<NetworkState>) {
    if state.is_offline() {
        return;
    }
    let candidates: Vec<String> = state.peers.collect_map(|peer| {
        let data = peer.state.read();
        (!data.media_reneg_inflight
            && data.data_channel_open
            && matches!(data.status, PeerStatus::Active | PeerStatus::Shelved))
        .then(|| peer.device_id.clone())
    });
    for device_id in candidates {
        // Through the fence: renegotiation is legacy real-time work, so it needs
        // the same admitted witness as every other real-time operation. There is
        // deliberately no separate `peers.get(&device_id)` here. Reading the
        // pending flag through one lookup and claiming it through another let
        // the read, the claim, and the connector belong to different
        // installations if a replacement landed between them; all three now come
        // from the peer this witness captured.
        let Some(realtime) = admitted_realtime_operation(state, &device_id) else {
            continue;
        };
        // Explicit finalization is the only operation that creates a pending
        // removal. Elapsed time never does so.
        if !realtime.media_reneg_pending() {
            continue;
        }
        // Consuming the witness is what claims the renegotiation: it revalidates
        // the captured connector/capability pair first, so a superseded
        // connector yields no session and nothing is claimed. Fail closed.
        // The claim yields one move-only operation carrying the connector *and*
        // the owner captured under the same fence. There is deliberately no
        // `peers.owner(&device_id)` here, and the completion call below takes
        // no owner argument, so a fresh one cannot be substituted without
        // abandoning the API entirely.
        let Some(renegotiation) = realtime.into_renegotiation() else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let outcome = if renegotiation.session().signaling_state()
                != webrtc::peer_connection::signaling_state::RTCSignalingState::Stable
            {
                // Mid-negotiation (glare, or our own earlier offer still
                // settling): do not stack an offer on it or touch the
                // session. The error below re-arms the explicit pending flag.
                Err("signaling not stable".to_string())
            } else {
                // Explicit finalization already changed the lane set. One
                // offer now carries the complete pending delta.
                match renegotiation.session().create_offer().await {
                    Ok(desc) => {
                        if !renegotiation.is_current(&state.peers) {
                            // Dropping the operation here is safe precisely
                            // because this installation is already gone:
                            // `complete` would find nothing current and write
                            // nothing, and the replacement carries its own
                            // in-flight guard.
                            return;
                        }
                        let device_id = renegotiation.device_id();
                        state.log_diag_with(
                            crate::events::DiagLevel::Debug,
                            "media",
                            format!(
                                "media renegotiation offer to {} (lane set changed)",
                                short_peer(device_id)
                            ),
                            serde_json::json!({
                                "peer": device_id,
                                "sdp_bytes": desc.sdp.len(),
                            }),
                        );
                        let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                            device_id: device_id.to_string(),
                            sdp: desc.sdp,
                        });
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            };
            renegotiation.complete(&state.peers, outcome);
        });
    }
}

/// The state-watch tick's backstop for offerer-side reconnects. Events
/// re-offer immediately (a relay reconnect flushes every intent; an inbound
/// announce rebuilds); this re-offers any intent whose backoff has come due
/// and that no event has resolved, while `due_reconnect_intents` expires the
/// ones past the reconnecting grace.
async fn service_reconnect_intents(state: &Arc<NetworkState>) {
    // Nothing to do while we have no interface — a re-offer can't bind a
    // socket, and burning the backoff schedule on no-op retries would leave
    // an intent over-backed-off when we return. The offline→online edge
    // flushes every intent at once (see `network_watch::fan_out_restart`).
    if state.is_offline() {
        return;
    }
    for device_id in state.due_reconnect_intents() {
        try_reoffer(state, &device_id).await;
    }
}

/// Re-establish ICE on a *live* peer by renegotiating the SDP — the half
/// `restart_ice()` leaves undone.
///
/// `restart_ice()` rotates our local ICE ufrag/pwd and re-gathers *our*
/// candidates, but on its own it never tells the peer: no fresh offer
/// goes out, so the peer keeps the old credentials, never re-answers, and
/// never sends candidates of its own. The link then sits with our new
/// candidates and zero remote ones and can only recover by a full
/// teardown + rebuild (which lands on TURN). This does the missing half —
/// `restart_ice()` *then* a fresh offer — so both ends re-gather against
/// the new ufrag and reconnect in place, usually within a second or two.
///
/// Glare- and flood-safe:
///   * Only the deterministic *offerer* (lex-lower device id) emits the
///     restart offer, so the two ends can't offer at once. The answerer
///     re-gathers implicitly when the offer lands; meanwhile it nudges the
///     offerer with the (globally rate-limited) reactive announce rather
///     than sending a competing offer.
///   * Single-flighted on `last_offer_sent_at` (`REOFFER_MIN_INTERVAL_MS`)
///     so the network-change watcher, the ICE watchdog, and an inbound
///     announce collapse into one offer per window instead of a storm.
///   * Skipped while a renegotiation is already in flight (ICE
///     `Checking`) — re-issuing `restart_ice()` mid-gather just burns the
///     cycle ("ICE Agent can not be restarted when gathering").
///
/// `force` is set by the network-change watcher: right after the OS swaps
/// the primary interface, ICE still *reads* `Connected` (its
/// consent-freshness timer hasn't fired — that's the whole reason the
/// watcher exists), so we must renegotiate despite the stale "healthy"
/// state. The watchdog / announce callers pass `force = false` and skip a
/// genuinely-connected link.
pub(crate) async fn renegotiate_ice(
    state: &Arc<NetworkState>,
    device_id: &str,
    force: bool,
    trigger: &'static str,
) {
    let Some(owner) = state.peers.owner(device_id) else {
        return;
    };
    renegotiate_ice_for_owner(state, &owner, force, trigger).await;
}

pub(crate) async fn renegotiate_ice_for_owner(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    force: bool,
    trigger: &'static str,
) {
    let device_id = owner.device_id();
    // No primary interface → a `restart_ice()` here can't bind a socket
    // and only feeds the `Network is unreachable` gather spam. Hold off;
    // the network-change handler drives a fresh restart fan-out the
    // instant the interface returns.
    if state.is_offline() {
        return;
    }
    let session = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let s = peer.session.lock().clone();
        s
    };
    let Some(session) = session else { return };

    // Snapshot the ICE state we're firing from — together with `trigger`
    // this is the instrumentation that answers "what kicked a link that
    // was fine?". A restart from `Connected` (consent-freshness still
    // green) attributed to `network-change` points at a spurious
    // primary-IP flip; one from `Disconnected` attributed to
    // `ice-disconnected-watchdog` is a genuine drop. Without the
    // attribution every restart looks the same in the log.
    let ice_before = session.ice_connection_state();

    match session.ice_connection_state() {
        // Healthy. Unless the caller knows the network just moved
        // (`force`), leave it alone — and opportunistically settle the
        // tier back to Steady if a prior restart has since recovered.
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed if !force => {
            state.peers.with_current(owner, |peer| {
                let mut data = peer.state.write();
                data.ice_disconnected_since = None;
                if matches!(
                    data.tier,
                    ConnectionTier::IceRestart { .. } | ConnectionTier::IceWatchdog { .. }
                ) {
                    data.tier = ConnectionTier::Steady;
                }
            });
            return;
        }
        // A gather/connectivity check is already in flight — don't
        // interrupt it, even on a forced network-change pass.
        RTCIceConnectionState::Checking => return,
        _ => {}
    }

    // Single-flight: collapse overlapping triggers into one offer/window.
    let offerer = {
        let Some(offerer) = state.peers.with_current(owner, |peer| {
            let mut data = peer.state.write();
            let due = data
                .last_offer_sent_at
                .map(|t| {
                    Instant::now().duration_since(t)
                        >= Duration::from_millis(REOFFER_MIN_INTERVAL_MS)
                })
                .unwrap_or(true);
            if !due {
                return None;
            }
            data.last_offer_sent_at = Some(Instant::now());
            data.tier = ConnectionTier::IceRestart {
                started: Instant::now(),
            };
            data.diag.ice_restarts += 1;
            Some(state.identity.public_id() < device_id)
        }) else {
            return;
        };
        let Some(offerer) = offerer else {
            return;
        };
        offerer
    };

    // One line per *committed* restart (past single-flight), carrying the
    // trigger, the role, whether it was forced, the ICE state it fired
    // from, and the running restart count. This is the primary instrument
    // for the flapping investigation: tail the log and every renegotiation
    // names its cause. A burst of `trigger=network-change` from
    // `ice_before=Connected` on a healthy box is the signature of the
    // network watcher mis-firing on a multi-homed host.
    let Some(restarts) = state
        .peers
        .with_current(owner, |peer| peer.state.read().diag.ice_restarts)
    else {
        return;
    };
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "ice",
        format!(
            "ICE renegotiation for {} — trigger={trigger}, role={}, forced={force}, from={ice_before:?} (#{restarts})",
            short_peer(device_id),
            if offerer { "offerer" } else { "answerer" },
        ),
        serde_json::json!({
            "peer": device_id,
            "trigger": trigger,
            "role": if offerer { "offerer" } else { "answerer" },
            "forced": force,
            "ice_before": format!("{ice_before:?}"),
            "ice_restarts": restarts,
        }),
    );

    if offerer {
        // Re-gather *our* candidates against a fresh ufrag, then offer them.
        // Only the offerer restarts ICE here. If the answerer also called
        // `restart_ice()` it would put its own agent into gathering, and
        // applying this restart offer on its side then fails with "ICE Agent
        // can not be restarted when gathering" — the glare both ends hit when
        // a network change fires `force_ice_restart_all` on each of them at
        // once. The answerer re-gathers implicitly when it applies this offer
        // (the design this function's header already describes).
        if let Err(e) = session.restart_ice().await {
            // Benign when a gather from a previous trigger is still in flight;
            // the next watchdog poll picks it up once that settles.
            debug!(peer = %device_id, "restart_ice during renegotiate: {e}");
        }
        if state.peers.get_if_current(owner).is_none() {
            return;
        }
        // create_offer runs INLINE on the single driver task, so an unbounded
        // await here starves every command, timer, and other peer on this
        // network until it returns — the same NanoKVM single-slow-core wedge
        // the *initial* offer path is bounded against (see `ensure_peer_session`
        // and `OFFER_BUILD_TIMEOUT_MS`). A network change fans this out across
        // every peer at once, so a stuck offer must cost this one attempt (the
        // watchdog retries next poll), never the engine. This is the path that
        // froze the bridge's control socket for ~45 s when a USB gadget toggle
        // mis-fired a full network-change fan-out. (restart_ice above is a quick
        // ufrag/pwd flip, not a gather, so it isn't wrapped — and timing it out
        // would cancel it mid-flight, which we don't know to be safe.)
        let built = tokio::time::timeout(
            Duration::from_millis(scheduler::OFFER_BUILD_TIMEOUT_MS),
            session.create_offer(),
        )
        .await;
        match built {
            Ok(Ok(desc)) => {
                if state.peers.get_if_current(owner).is_none() {
                    return;
                }
                // The single INFO line for this restart is the `trigger=…`
                // line above; the offer/nudge mechanics ride at DEBUG so a
                // renegotiation is one line in the default stream.
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "ice",
                    format!(
                        "renegotiating ICE with {} — restart offer",
                        short_peer(device_id)
                    ),
                    serde_json::json!({
                        "peer": device_id,
                        "role": "offerer",
                        "sdp_bytes": desc.sdp.len(),
                    }),
                );
                state.peers.with_current(owner, |_| {
                    let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                        device_id: device_id.to_string(),
                        sdp: desc.sdp,
                    });
                });
            }
            Ok(Err(e)) => warn!(peer = %device_id, "renegotiate create_offer failed: {e}"),
            Err(_) => warn!(
                peer = %device_id,
                "renegotiate create_offer timed out on the driver — retrying next poll"
            ),
        }
    } else {
        // Answerer: avoid glare. Deliberately do NOT restart our own ICE —
        // applying the offerer's restart offer is what re-gathers us, and
        // self-gathering here is exactly what makes that offer bounce off our
        // side with "can not be restarted when gathering". Just nudge the
        // offerer to send the restart offer; the reactive announce is globally
        // rate-limited so this can't add signaling load.
        if state.peers.get_if_current(owner).is_none() {
            return;
        }
        state.log_diag_with(
            crate::events::DiagLevel::Debug,
            "ice",
            format!(
                "ICE renegotiate with {} — nudging offerer",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "role": "answerer" }),
        );
        maybe_reactive_announce(state);
    }
}

/// Record a signaling-discovered peer as `Sighted` **without** opening a
/// WebRTC session — the Silent-network discovery path. Inserts a session-less
/// [`PeerConnection`] placeholder (default status `Sighted`) so the peer shows
/// up in [`NetworkState::peer_snapshot`] / `JoinedNetwork::peers()` and emits a
/// one-time [`PeerEvent::Sighted`], but no ICE/DTLS/handshake happens. The
/// placeholder is upgraded to a real session later by [`connect_peer`] or by
/// answering the peer's inbound offer (both go through `ensure_peer_session`,
/// which replaces the placeholder). Idempotent: a re-announce for an
/// already-tracked (or already-connected) peer is a no-op, so `Sighted` fires
/// once per discovery, not once per announce.
fn note_sighted_without_dialing(state: &Arc<NetworkState>, device_id: &str, why: &str) {
    if state.peers.contains_key(device_id) {
        return;
    }
    install_peer(
        &state.peers,
        Arc::new(PeerConnection::new(device_id.to_string(), None)),
    );
    state.emit(MeshEvent::Peer(PeerEvent::Sighted {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
    }));
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "peer",
        format!(
            "{} sighted on signaling ({why} — not dialing)",
            short_peer(device_id)
        ),
        serde_json::json!({ "peer": device_id, "reason": why }),
    );
    // Recompute the rollup so a network that has only discovered (but not
    // connected) peers reads as `Discovering`, not `Alone`.
    phase::recompute(state);
}

/// Deliberately dial exactly one peer as the offerer — the manual-connect
/// primitive behind [`crate::JoinedNetwork::connect_peer`] and the way a
/// `Silent` network ever opens a connection. Always initiates as the offerer
/// (rather than the lex-order role the announce path would pick) so the local
/// side sends the offer and a Silent peer — which never auto-dials — is reached
/// and answers via its (ungated) inbound-offer path. Idempotent: a no-op when a
/// live session already exists; otherwise `ensure_peer_session` builds the
/// session, upgrading any discovery-only `Sighted` placeholder in place.
async fn connect_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    sticky: bool,
    reply: Option<tokio::sync::oneshot::Sender<Result<()>>>,
) {
    if sticky {
        state.add_sticky(device_id);
    }
    if let Some(reply) = reply {
        // Already carrying app traffic? Resolve now — the waiter contract
        // is "the link is ACTIVE", not "a fresh dial happened".
        let already_active = state
            .peers
            .get(device_id)
            .map(|p| matches!(p.state.read().status, PeerStatus::Active))
            .unwrap_or(false);
        if already_active {
            let _ = reply.send(Ok(()));
        } else {
            state.register_connect_waiter(device_id, reply);
        }
    }
    ensure_peer_session(state, device_id.to_string(), Role::Offerer).await;
    // Nudge presence so the relays are warm and the remote sees us promptly;
    // globally rate-limited, so this can't add signaling load.
    maybe_reactive_announce(state);
}

async fn ensure_peer_session(state: &Arc<NetworkState>, device_id: String, role: Role) {
    // Return only if we already hold a live *session* for this peer. A
    // session-less discovery placeholder — what a Silent network records for a
    // co-present peer it hasn't dialed (see `note_sighted_without_dialing`) —
    // must be upgraded to a real session here (by a deliberate `connect_peer`
    // or by answering that peer's inbound offer), not short-circuited. On every
    // non-Silent network no session-less entry ever exists, so this is exactly
    // the previous `contains_key` guard.
    if state
        .peers
        .get(&device_id)
        .is_some_and(|p| p.session.lock().is_some())
    {
        return;
    }
    // Per-peer negotiation stage, same reasoning as the webrtc.rs stage logs:
    // one line per peer per attempt is fine when connects are rare and a flood
    // when they aren't. Restored by `MYOWNMESH_LOG_EXTRA=myownmesh_core=debug`.
    debug!(peer = %short_peer(&device_id), ?role, "ensure_peer_session: opening transport session");
    let cfg = state.config.read().clone();
    let construction = tokio::time::timeout(
        Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS),
        state.transport.open_connector_peer(
            role,
            &cfg.stun_servers,
            &cfg.turn_servers,
            state.peer_connection_resource_scope(),
        ),
    )
    .await;
    let (session, mut rx) = match construction {
        Ok(Ok(peer)) => peer,
        Ok(Err(e)) => {
            state.log_diag_with(
                crate::events::DiagLevel::Error,
                "transport",
                format!("open_peer failed for {}: {e}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "error": e.to_string() }),
            );
            warn!(peer = %device_id, "open_peer failed: {e}");
            return;
        }
        Err(_) => {
            state.log_diag_with(
                crate::events::DiagLevel::Error,
                "transport",
                format!(
                    "open_peer for {} did not complete within the existing {} ms connection-attempt window",
                    short_peer(&device_id),
                    scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS
                ),
                serde_json::json!({
                    "peer": device_id,
                    "timeout_ms": scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS,
                }),
            );
            return;
        }
    };
    let session = Arc::new(session);
    let peer = Arc::new(PeerConnection::new(
        device_id.clone(),
        Some(session.clone()),
    ));
    // Start the connect-timeout clock the moment the session exists: if the
    // data channel hasn't opened within DATA_CHANNEL_OPEN_TIMEOUT_MS of
    // now, the attempt is reclaimed and rebuilt (see
    // `ice_watchdog::poll_all`).
    peer.state.write().session_started_at = Some(Instant::now());
    install_peer(&state.peers, peer.clone());

    state.emit(MeshEvent::Peer(PeerEvent::Sighted {
        network_id: state.network_id.clone(),
        device_id: device_id.clone(),
    }));
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "peer",
        format!("{} connecting (we are {role:?})", short_peer(&device_id)),
        serde_json::json!({ "peer": device_id, "role": format!("{role:?}") }),
    );

    // For offerer, kick off SDP exchange immediately. The offer build is
    // bounded: it runs INLINE on the driver task, so if it never returned,
    // every command, timer, and other peer on this network would die with it
    // — exactly the wedge observed on the NanoKVM's single slow core, where
    // the daemon sat with one worker spinning and the driver parked here
    // forever while the control socket timed out op after op. A stuck offer
    // now costs this one attempt (the watchdog rebuilds it), not the engine.
    debug!(peer = %short_peer(&device_id), "ensure_peer_session: building offer");
    if role == Role::Offerer {
        let built = tokio::time::timeout(
            Duration::from_millis(scheduler::OFFER_BUILD_TIMEOUT_MS),
            session.create_offer(),
        )
        .await;
        match built {
            Ok(Ok(desc)) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "signaling",
                    format!("offer sent to {}", short_peer(&device_id)),
                    serde_json::json!({ "peer": device_id, "sdp_bytes": desc.sdp.len() }),
                );
                let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                    device_id: device_id.clone(),
                    sdp: desc.sdp,
                });
                if let Some(p) = state.peers.get(&device_id) {
                    p.state.write().last_offer_sent_at = Some(Instant::now());
                }
            }
            Ok(Err(e)) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Error,
                    "signaling",
                    format!("create_offer failed for {}: {e}", short_peer(&device_id)),
                    serde_json::json!({ "peer": device_id, "error": e.to_string() }),
                );
                warn!(peer = %device_id, "create_offer failed: {e}");
            }
            Err(_) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Error,
                    "signaling",
                    format!(
                        "create_offer for {} did not complete within {} ms — abandoning this attempt (the connect watchdog will rebuild it)",
                        short_peer(&device_id),
                        scheduler::OFFER_BUILD_TIMEOUT_MS
                    ),
                    serde_json::json!({ "peer": device_id }),
                );
                warn!(peer = %device_id, "create_offer timed out — engine driver kept alive");
            }
        }
    }

    // Per-peer transport-event pump. It handles one event at a time from the
    // worker's bounded mailbox. Connector events never enter the unbounded
    // general command queue. The receiver stamps each value with the exact
    // connector worker identity that owns its callback source.
    let connector_state = Arc::clone(state);
    let peer_id_for_pump = device_id.clone();
    let task_observation = session.observe_owned_task();
    tokio::spawn(async move {
        let _task_observation = task_observation;
        while let Some(ev) = rx.recv().await {
            if handle_transport_event(&connector_state, peer_id_for_pump.clone(), ev).await {
                rx.commit_data_channel_open();
            }
        }
    });
}

async fn apply_remote_sdp(
    state: &Arc<NetworkState>,
    device_id: &str,
    sdp_type: RTCSdpType,
    sdp: String,
) {
    let session = {
        let peer = state.peers.get(device_id);
        peer.and_then(|p| p.session.lock().clone())
    };
    let Some(session) = session else {
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "signaling",
            format!(
                "remote {sdp_type:?} for {} ignored — no session",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "sdp_type": format!("{sdp_type:?}") }),
        );
        // A late Answer that lost its session: drive a fresh offer instead
        // of waiting out the next announce-driven re-offer.
        if sdp_type == RTCSdpType::Answer {
            reoffer_after_failed_answer(state, device_id).await;
        }
        return;
    };
    // A stale Answer — one that arrives when we're not holding a local offer
    // (a duplicate from relay redundancy, or the answer to an offer we've since
    // superseded by a restart/rebuild) — can't be applied: webrtc-rs rejects it
    // ("invalid proposed signaling state transition from stable") and the failed
    // apply wedges the PC. Drop it and let a throttled re-offer re-open
    // negotiation cleanly instead of logging an error and churning.
    if sdp_type == RTCSdpType::Answer && !session.awaiting_answer() {
        state.log_diag_with(
            crate::events::DiagLevel::Debug,
            "signaling",
            format!(
                "stale answer from {} ignored — not awaiting one",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "reason": "not_awaiting_answer" }),
        );
        reoffer_after_failed_answer(state, device_id).await;
        return;
    }
    if matches!(sdp_type, RTCSdpType::Offer | RTCSdpType::Answer) {
        match session.apply_remote_sdp(sdp_type, sdp).await {
            Err(e) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Error,
                    "signaling",
                    format!(
                        "set_remote_description({sdp_type:?}) failed for {}: {e}",
                        short_peer(device_id)
                    ),
                    serde_json::json!({
                        "peer": device_id,
                        "sdp_type": format!("{sdp_type:?}"),
                        "error": e.to_string(),
                    }),
                );
                warn!(peer = %device_id, "set_remote_description failed: {e}");
                // The common failure here is an Answer arriving when our
                // signaling state has already raced back to `stable` (no
                // pending local offer) — "invalid proposed signaling state
                // transition from stable". A fresh offer re-opens the
                // negotiation cleanly rather than leaving the link wedged
                // until the next announce.
                if sdp_type == RTCSdpType::Answer {
                    reoffer_after_failed_answer(state, device_id).await;
                }
            }
            Ok(report) => {
                // Drain any ICE candidates that arrived ahead of the
                // SDP. The lock comes off before any await — we pull
                // the pending vec out, then apply each candidate
                // outside the guard so the per-peer state lock isn't
                // held across the webrtc-rs add_ice_candidate await.
                if report.queued_candidate_count != 0 {
                    state.log_diag_with(
                        crate::events::DiagLevel::Debug,
                        "ice",
                        format!(
                            "applying {} queued remote candidate(s) for {}",
                            report.queued_candidate_count,
                            short_peer(device_id)
                        ),
                        serde_json::json!({
                            "peer": device_id,
                            "count": report.queued_candidate_count,
                            "failure_count": report.candidate_failure_count,
                        }),
                    );
                    if report.candidate_failure_count != 0 {
                        warn!(
                            peer = %device_id,
                            failure_count = report.candidate_failure_count,
                            "queued remote-candidate application failures were retained only as a count"
                        );
                    }
                }
            }
        }
    } else {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "signaling",
            format!(
                "remote SDP from {} unparseable as {sdp_type:?}",
                short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "sdp_type": format!("{sdp_type:?}") }),
        );
    }
}

/// An inbound Answer that can't be applied — it arrived after we tore the
/// session down ("no session"), or it raced our signaling state back to
/// `stable` ("invalid proposed signaling state transition from stable") —
/// means our last offer never completed the handshake. Discarding it and
/// waiting for the announce-driven "stuck at Sighted" re-offer costs a full
/// ~15-30 s lap; on a flapping wake that stacks into the multi-lap loop the
/// logs showed. Instead we drive a fresh offer right now: rebuild the
/// session if it's gone, otherwise re-offer in place. Only the offerer
/// sends offers (an Answer is addressed to us as the offerer, but we guard
/// on the same id comparison the rest of the engine uses), it's held off
/// while offline, and it's throttled by `last_offer_sent_at` so a burst of
/// stale answers collapses to a single offer.
async fn reoffer_after_failed_answer(state: &Arc<NetworkState>, device_id: &str) {
    if state.identity.public_id() >= device_id || state.is_offline() {
        return;
    }
    // Resolve the throttle + session under the peer lock, then act
    // outside it (the create_offer / open_peer awaits must not hold it).
    let session = match state.peers.get(device_id) {
        None => None,
        Some(peer) => {
            let due = {
                let mut data = peer.state.write();
                let due = data
                    .last_offer_sent_at
                    .map(|t| {
                        Instant::now().duration_since(t)
                            >= Duration::from_millis(REOFFER_MIN_INTERVAL_MS)
                    })
                    .unwrap_or(true);
                if due {
                    data.last_offer_sent_at = Some(Instant::now());
                }
                due
            };
            if !due {
                return;
            }
            peer.session.lock().clone()
        }
    };
    match session {
        Some(session) => match session.create_offer().await {
            Ok(desc) => {
                state.log_diag_with(
                    crate::events::DiagLevel::Debug,
                    "signaling",
                    format!(
                        "re-offer to {} (answer could not be applied)",
                        short_peer(device_id)
                    ),
                    serde_json::json!({
                        "peer": device_id,
                        "sdp_bytes": desc.sdp.len(),
                        "reason": "failed-answer",
                    }),
                );
                let _ = state.signaling_tx.send(SignalingOutbound::Offer {
                    device_id: device_id.to_string(),
                    sdp: desc.sdp,
                });
            }
            Err(e) => warn!(peer = %device_id, "re-offer create_offer failed: {e}"),
        },
        // Peer gone (or session-less) — rebuild as offerer; that path
        // sends a fresh offer as part of setup.
        None => ensure_peer_session(state, device_id.to_string(), Role::Offerer).await,
    }
}

async fn handle_transport_event(
    state: &Arc<NetworkState>,
    device_id: String,
    event: WebRtcConnectorEvent,
) -> bool {
    // The callback stamp must match the exact active worker. A delayed event
    // from a replaced worker cannot act on the replacement peer.
    let owner = state.peers.owner(&device_id);
    let worker = owner
        .as_ref()
        .and_then(|owner| state.peers.get_if_current(owner))
        .and_then(|peer| peer.session.lock().clone());
    let (Some(owner), Some(worker)) = (owner, worker) else {
        trace!(peer = %device_id, "ignoring transport event from stale/absent connector worker");
        return false;
    };
    let Some(event) = worker.accept_event(event) else {
        trace!(peer = %device_id, "ignoring transport event from stale/absent connector worker");
        return false;
    };
    let (event, _callback_resources) = event.into_parts();
    match event {
        TransportEvent::RenegotiationNeeded => {
            // A lane opened/closed. Don't offer inline — a burst of lane
            // changes (a screen share starting video + audio together)
            // must collapse into one offer, and glare with the remote's
            // own changes is least likely on the paced tick.
            state.peers.with_current(&owner, |peer| {
                peer.state.write().media_reneg_pending = true;
            });
        }
        TransportEvent::LocalIceCandidate(Some(cand)) => {
            // Classify before moving `cand` into the signaling
            // message so the no-TURN diagnostic
            // (`ice_watchdog::maybe_emit_no_turn_diag`) has accurate
            // host/srflx/relay counts to report.
            let kind = crate::transport::classify_candidate_sdp(&cand.candidate);
            let accepted = state
                .peers
                .with_current(&owner, |peer| {
                    peer.state.write().diag.local_candidates.record(kind);
                    state.signaling_tx.send(SignalingOutbound::Candidate {
                        device_id: device_id.clone(),
                        candidate: cand.clone(),
                    })
                })
                .is_some();
            if !accepted {
                return false;
            }
            // Debug-level: candidates are noisy (one per
            // host/srflx/relay), so the per-candidate detail lands
            // here and gets summarised when ICE eventually settles.
            // Surfacing them at info would drown out the higher-level
            // state transitions the user actually cares about.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "ice",
                format!(
                    "local {kind:?} candidate → {}: {}",
                    short_peer(&device_id),
                    cand.candidate
                ),
                serde_json::json!({ "peer": device_id, "kind": format!("{kind:?}") }),
            );
        }
        TransportEvent::LocalIceCandidate(None) => {
            // Gathering complete sentinel. Surface as a single info
            // line with a summary of what we ended up offering — if
            // the peer never connects we want the user to see at a
            // glance "we sent 3 host, 1 srflx, 0 relay candidates"
            // so the TURN-needed diagnosis is one read away.
            let Some((h, s, r)) = state.peers.with_current(&owner, |peer| {
                let data = peer.state.read();
                (
                    data.diag.local_candidates.host,
                    data.diag.local_candidates.server_reflexive,
                    data.diag.local_candidates.relay,
                )
            }) else {
                return false;
            };
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "ice",
                format!(
                    "local gathering complete for {} — {h} host · {s} srflx · {r} relay",
                    short_peer(&device_id)
                ),
                serde_json::json!({
                    "peer": device_id,
                    "host": h,
                    "srflx": s,
                    "relay": r,
                }),
            );
        }
        TransportEvent::IceConnectionStateChanged(ice_state) => {
            // Every ICE state lands in the log — these are the
            // single biggest signal of whether NAT traversal is
            // working. "checking → connected" is the happy path;
            // "checking → disconnected → failed" is the no-TURN
            // signature; "new" never advancing means the signaling
            // layer never delivered candidates.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "ice",
                format!("ICE → {ice_state:?} for {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "state": format!("{ice_state:?}") }),
            );
            handle_ice_state_change(state, &owner, ice_state).await;
        }
        TransportEvent::PeerConnectionStateChanged(pc_state) => {
            // Peer connection state is the higher-level view of the
            // same NAT traversal — useful when ICE reports Connected
            // but PC sticks at Connecting (DTLS handshake issue)
            // or vice versa.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "transport",
                format!("PC → {pc_state:?} for {}", short_peer(&device_id)),
                serde_json::json!({ "peer": device_id, "state": format!("{pc_state:?}") }),
            );
            handle_pc_state_change(state, &owner, pc_state).await;
        }
        TransportEvent::DataChannelOpen => {
            if state.peers.get_if_current(&owner).is_none() {
                return false;
            }
            // The connector states what it can prove about this channel while
            // its retirement-aware operation is still live, and before the
            // handoff moves. Fail closed: without both components there is no
            // binding, and an unbound endpoint-authentication attempt would
            // prove nothing about the channel it ran over.
            let Some(binding) = worker.endpoint_auth_binding().await else {
                warn!(peer = %device_id, "no connector channel binding at DataChannelOpen — retiring rather than authenticating unbound");
                worker.retire();
                return false;
            };
            // The await above can lose the registry race, so the current owner
            // is rechecked before anything is confirmed or installed.
            if state.peers.get_if_current(&owner).is_none() {
                worker.retire();
                return false;
            }
            let connected = match worker.confirm_data_channel_open() {
                DataChannelOpenOwnership::Rejected => {
                    trace!(peer = %device_id, "ignoring DataChannelOpen without a live connector owner");
                    return false;
                }
                DataChannelOpenOwnership::AlreadyConnected => {
                    trace!(peer = %device_id, "ignoring duplicate DataChannelOpen for the exact connector owner");
                    return true;
                }
                DataChannelOpenOwnership::Connected(connected) => connected,
            };
            // The whole handoff moves into its transport-independent form, so
            // the close owner and the retained connected claim travel with it.
            let Some(handoff) = connected.into_generic() else {
                warn!(peer = %device_id, "connected handoff carried no capability — retiring");
                worker.retire();
                return false;
            };
            // Every fact this task will ever authenticate under is fixed here,
            // once: the mesh, this endpoint's Device ID, the exact remote
            // Device ID already in scope, and the connector's binding. The
            // profile is derived from that binding inside endpoint
            // authentication; the engine selects no profile semantics.
            let remote_device_id = crate::signing::pubkey_part(&device_id).to_string();
            let Ok(context) = crate::endpoint_auth::EndpointAuthContext::new(
                &state.network_id,
                state.identity.public_id(),
                &remote_device_id,
                binding,
            ) else {
                warn!(peer = %device_id, "endpoint-auth context refused its own identifiers — retiring");
                worker.retire();
                return false;
            };
            // Signing moves into the task. From here the engine translates wire
            // values and never signs. The identity is handed over as the shared
            // handle it already is, so the task borrows the one Device key
            // rather than taking a copy of it per channel.
            let auth_task = Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(
                context,
                handoff,
                crate::endpoint_auth::LocalIdentitySigner::for_identity(Arc::clone(
                    &state.identity,
                )),
            ));
            // The reliable "transport is up" milestone — record it so the
            // connect-timeout watchdog knows this session made it, and stops
            // counting it as a connecting peer that might need rebuilding.
            let accepted = state.peers.with_current(&owner, |peer| {
                if !peer.install_endpoint_auth(Arc::clone(&auth_task)) {
                    return false;
                }
                peer.state.write().data_channel_open = true;
                state.clear_reconnect_intent(&device_id);
                true
            });
            if accepted != Some(true) {
                // The connector capability was already promoted, but the
                // exact registry owner lost its install race. Fence this
                // connector now so it cannot retain connected ownership or
                // later release queued endpoint protocol without an installed
                // Endpoint Auth Task.
                worker.retire();
                return false;
            }
            // The link is back — retire any reconnect intent we were driving
            // for this peer so the tick stops re-offering it.
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "transport",
                format!(
                    "data channel open with {} — starting handshake",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id }),
            );
            handshake::initiate(state, &owner, auth_task).await;
            return true;
        }
        TransportEvent::DataChannelClosed => {
            // A channel that closes right after we hand an evicted peer its
            // deny-with-proof is that device standing down, not an ICE failure.
            // Label it `Denied` so the diag reads truthfully (an evicted peer
            // dropping as "IceFailed" is exactly what made this loop hard to
            // read) and so it lands in the non-recoverable bucket — no redial.
            let reason = if governance::log_evicted(state, &device_id) {
                DropReason::Denied
            } else {
                DropReason::IceFailed
            };
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "transport",
                format!(
                    "data channel closed with {} — dropping peer",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id, "reason": format!("{reason:?}") }),
            );
            drop_peer_if_current(state, &owner, reason).await;
        }
        TransportEvent::Message(bytes) => {
            handle_inbound_frame_from(state, &owner, bytes).await;
        }
        // Both real-time arms delegate, and do nothing else. See
        // `dispatch_admitted_video` for why the gate lives in a function of its
        // own rather than inline here.
        TransportEvent::VideoSample(sample) => dispatch_admitted_video(state, &owner, sample),
        TransportEvent::AudioSample(sample) => dispatch_admitted_audio(state, &owner, sample),
    }
    false
}

/// Deliver one inbound video access unit, or refuse it, at the promotion fence.
///
/// Inbound real-time units are application delivery and are gated here, at the
/// engine boundary, on the same witness as every other legacy application
/// operation. The previous reasoning — that an unadmitted peer cannot establish
/// a media route, so the embedder's route matching suffices — is not an
/// authority boundary: a native track can produce units independently of
/// whether route metadata was ever accepted, so the basal core must not hand
/// units to subscribers before promotion.
///
/// A pre-authentication unit is dropped. It is already bounded by the
/// connector's own quarantine, and retaining it here would create a second
/// owner for data that may never become deliverable.
///
/// This is a function rather than an inline arm so the shipped gate is directly
/// callable. `handle_transport_event` additionally requires a live connector
/// worker on the exact current peer before it reaches any arm, which this gate
/// does not — so a control forced in through the event path would be exercising
/// connector wiring, and could pass while the admission conjunction itself was
/// wrong. Taking the owner token rather than a device id keeps the exact-current
/// check where the event path has it.
fn dispatch_admitted_video(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    sample: crate::transport::webrtc::VideoSample,
) {
    state.peers.with_admitted_current_or_refused(
        owner,
        |admitted| state.dispatch_video(admitted.device_id(), sample),
        record_refused_media_unit,
    );
}

/// The audio twin of [`dispatch_admitted_video`], with the same fence, the same
/// exact-owner dispatch, and the same refusal record.
fn dispatch_admitted_audio(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    sample: crate::transport::webrtc::AudioSample,
) {
    state.peers.with_admitted_current_or_refused(
        owner,
        |admitted| state.dispatch_audio(admitted.device_id(), sample),
        record_refused_media_unit,
    );
}

/// Count one inbound real-time unit refused at the media gate.
///
/// Deliberately the same `admission_rejected` evidence the inbound frame gate
/// uses, not a second counter: a unit dropped here is dropped for exactly the
/// reason a frame is, and no new semantics are introduced. It exists because a
/// silent drop is indistinguishable from a unit that never arrived, so a
/// negative media control could pass without the stimulus ever reaching this
/// boundary.
fn record_refused_media_unit(peer: &Arc<PeerConnection>) {
    let mut data = peer.state.write();
    data.admission_rejected = data.admission_rejected.saturating_add(1);
}

async fn handle_ice_state_change(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    ice: RTCIceConnectionState,
) {
    let device_id = owner.device_id();
    // Instrumentation: a breadcrumb on every ICE transition so the log
    // carries the full state trail per peer, not just the headline
    // "connected"/"stuck" lines. `Disconnected` is the one that was
    // invisible before and matters most — it's a consent-freshness drop on
    // a previously-live link (the trigger the disconnected-watchdog then
    // acts on), so it's logged at INFO. `Failed` is left at DEBUG here
    // because `ice_watchdog::on_failed` already emits a WARN for it — no
    // need for two lines on the same event. The other churn states stay at
    // DEBUG to keep the stream readable.
    let level = match ice {
        RTCIceConnectionState::Disconnected => crate::events::DiagLevel::Info,
        _ => crate::events::DiagLevel::Debug,
    };
    state.log_diag_with(
        level,
        "ice",
        format!("{} ICE → {ice:?}", short_peer(device_id)),
        serde_json::json!({ "peer": device_id, "ice_state": format!("{ice:?}") }),
    );

    // Resolve the state transition under the lock, return what the
    // caller should do, then drop the lock before any await.
    let mut confirm_ping = false;
    let Some(escalate_failed) = state.peers.with_current(owner, |peer| {
        let mut data = peer.state.write();
        data.diag.ice_transitions += 1;
        // ICE state never tears a peer down — it only clears or schedules
        // the in-place restart. Teardown is the data channel's job: a
        // connecting peer whose channel never opens hits the
        // data-channel-open timeout; an open peer that goes silent is
        // reclaimed by the heartbeat; a real close fires DataChannelClosed.
        // We trust webrtc-rs's ICE state here only to *drive recovery*,
        // never to decide a link is dead — it has been observed reporting
        // Failed/Disconnected on links carrying traffic and Connected on
        // links whose channel never came up.
        match ice {
            RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
                data.ice_disconnected_since = None;
                // ICE reaching Connected is NOT proof the link carries
                // traffic — webrtc-rs reports Connected on dead TURN paths
                // (a network handoff left three peers "Connected" with zero
                // frames for 90 s). So a peer recovering from a restart does
                // not go Steady here; it stays in the restart tier with the
                // clock re-stamped to now, and we fire one confirm-ping.
                // Only actual inbound traffic — the pong, or any app frame —
                // promotes it to Steady (see `handle_inbound_frame`); if
                // none arrives within the grace, the restart-verify watchdog
                // rebuilds it. Initial connects (tier already Steady) are
                // untouched — they confirm via the handshake.
                if matches!(
                    data.tier,
                    ConnectionTier::IceWatchdog { .. }
                        | ConnectionTier::IceRestart { .. }
                        | ConnectionTier::WakeProbe
                ) {
                    data.tier = ConnectionTier::IceRestart {
                        started: Instant::now(),
                    };
                    confirm_ping = true;
                }
                false
            }
            RTCIceConnectionState::Disconnected => {
                // A consent-freshness drop on a previously-live link. Latch
                // the timestamp + tier so the disconnected-watchdog drives
                // an in-place `renegotiate_ice` (the data channel survives
                // a restart). No teardown.
                if data.ice_disconnected_since.is_none() {
                    data.ice_disconnected_since = Some(Instant::now());
                    data.tier = ConnectionTier::IceWatchdog {
                        since: Instant::now(),
                    };
                }
                false
            }
            RTCIceConnectionState::Failed => {
                // webrtc-rs fires `Failed` even while a nominated candidate
                // pair is succeeding and the path is delivering frames — seen
                // in the field as "ICE failed: a pair is nominated and
                // succeeded — the path is up". Acting on that lie tears down a
                // working link: the renegotiate disrupts it, then the
                // restart-verify watchdog can't confirm traffic and rebuilds.
                // Trust inbound traffic over the ICE state — only escalate when
                // the path isn't actually carrying anything. A genuinely dead
                // link has no recent inbound (escalated here, or reclaimed by
                // the heartbeat); a network move is driven by the
                // network-change handler regardless of this.
                let carrying_traffic = data
                    .last_recv_at
                    .map(|t| t.elapsed() < Duration::from_millis(scheduler::HEARTBEAT_TIMEOUT_MS))
                    .unwrap_or(false);
                !carrying_traffic
            }
            _ => false,
        }
    }) else {
        return;
    };
    if escalate_failed {
        // Dump the full connectivity-check snapshot *before* the ladder
        // tears the session down — this is the "why did it fail"
        // record: every candidate pair, every STUN check counter, and a
        // plain-language diagnosis the user can act on.
        log_ice_check_snapshot_for_owner(state, owner, "ICE failed", true).await;
        if state.peers.get_if_current(owner).is_none() {
            return;
        }
        ice_watchdog::on_failed(state, owner).await;
    }
    if confirm_ping {
        // Probe the restarted path with traffic right now instead of
        // waiting up to a heartbeat interval: a live path pongs within an
        // RTT and gets promoted to Steady; a dead one stays unconfirmed for
        // the restart-verify watchdog to rebuild.
        heartbeat::send_ping_to_owner(state, owner).await;
    }
    // Once ICE settles, ask the agent which candidate pair it
    // actually chose so the GUI can paint the link type from real
    // data instead of guessing from gathered-candidate counts. We
    // also clear it on Disconnected/Failed/Closed so a stale
    // selection doesn't claim "LAN" while the connection is dead.
    match ice {
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
            record_selected_pair_for_owner(state, owner).await;
        }
        RTCIceConnectionState::Disconnected => {
            // A drop on a previously-checking/active pair: log a concise
            // breadcrumb of the check counters so a flap leaves a trail
            // (was the path ever two-way?) before we clear the pair.
            log_ice_check_snapshot_for_owner(state, owner, "ICE disconnected", false).await;
            state.peers.with_current(owner, |peer| {
                peer.state.write().selected_pair = None;
            });
        }
        RTCIceConnectionState::Failed | RTCIceConnectionState::Closed => {
            state.peers.with_current(owner, |peer| {
                peer.state.write().selected_pair = None;
            });
        }
        _ => {}
    }
}

/// Ask the peer's ICE agent for its nominated candidate pair and
/// stash it on the peer state. Quiet on `None` — the agent is
/// allowed not to know yet (renegotiation in flight, agent torn
/// down, etc.) and the next state change or the ICE poll will
/// re-query.
pub(crate) async fn record_selected_pair(state: &Arc<NetworkState>, device_id: &str) {
    let Some(owner) = state.peers.owner(device_id) else {
        return;
    };
    record_selected_pair_for_owner(state, &owner).await;
}

async fn record_selected_pair_for_owner(state: &Arc<NetworkState>, owner: &state::PeerOwnerToken) {
    let device_id = owner.device_id();
    // Same DashMap-Ref + MutexGuard scoping pattern as the watchdog:
    // pull the cloned `Arc<PeerSession>` into a named local before
    // the inner block returns so the guard drops before the `Ref`
    // does. Without the named binding Rust 2021's trailing-
    // expression scoping keeps the guard alive across the outer
    // borrow check.
    let session = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let session = peer.session.lock().clone();
        session
    };
    let Some(session) = session else { return };
    // Bounded: reading the selected pair contends with the ICE agent's own
    // lock, so on a single slow core mid-gather it can park the driver. This
    // is a GUI/diagnostic read that drives no recovery, so skip it this pass
    // rather than freeze command + signaling handling (see
    // `scheduler::ICE_INTROSPECT_TIMEOUT_MS`).
    let pair = match tokio::time::timeout(
        Duration::from_millis(scheduler::ICE_INTROSPECT_TIMEOUT_MS),
        session.selected_candidate_pair(),
    )
    .await
    {
        Ok(pair) => pair,
        Err(_) => {
            debug!(peer = %device_id, "selected_candidate_pair introspection timed out — skipping this tick");
            return;
        }
    };
    let Some(pair) = pair else { return };
    let committed = state.peers.with_current(owner, |peer| {
        peer.state.write().selected_pair = Some(pair);
    });
    if committed.is_none() {
        return;
    }
    // Summarize the chosen path as a transport word so a glance tells you
    // whether you're going direct or through STUN/TURN — the detail keeps
    // the raw candidate types for the GUI / DEBUG.
    let local = format!("{:?}", pair.local);
    let remote = format!("{:?}", pair.remote);
    let transport = if local.contains("Relay") || remote.contains("Relay") {
        "relayed (TURN)"
    } else if local.contains("Srflx")
        || local.contains("Prflx")
        || remote.contains("Srflx")
        || remote.contains("Prflx")
    {
        "reflexive (STUN)"
    } else {
        "direct"
    };
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "ice",
        format!("{} connected · {transport}", short_peer(device_id)),
        serde_json::json!({
            "peer": device_id,
            "local": local,
            "remote": remote,
            "transport": transport,
        }),
    );
}

/// Pull a live ICE connectivity-check snapshot for `device_id` and log
/// it. This is the core instrument for diagnosing why a peer won't
/// connect: it surfaces every candidate pair the agent formed and,
/// crucially, whether our STUN checks are getting responses — the
/// difference between "signaling never delivered candidates" and "the
/// network is silently dropping our UDP". `full` controls verbosity: a
/// terminal event (ICE failed) dumps every pair plus a plain-language
/// diagnosis at WARN; a periodic progress tick logs a single aggregate
/// line at INFO so it can be watched live without flooding the log.
///
/// The webrtc-rs sibling crates are silenced to ERROR in the default
/// log filter (see `myownmesh/src/main.rs`), so these counters would
/// otherwise be invisible. This lifts the load-bearing ones into our
/// own diag stream where the user — and the GUI Activity tab — see them
/// by default, no `MYOWNMESH_LOG` override required.
pub(crate) async fn log_ice_check_snapshot(
    state: &Arc<NetworkState>,
    device_id: &str,
    context: &str,
    full: bool,
) {
    let Some(owner) = state.peers.owner(device_id) else {
        return;
    };
    log_ice_check_snapshot_for_owner(state, &owner, context, full).await;
}

async fn log_ice_check_snapshot_for_owner(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    context: &str,
    full: bool,
) {
    let device_id = owner.device_id();
    // Same Ref + MutexGuard scoping dance as record_selected_pair:
    // clone the session out, drop every guard, then await.
    let session = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let session = peer.session.lock().clone();
        session
    };
    let Some(session) = session else { return };
    // Bounded for the same reason as `record_selected_pair`: the snapshot walks
    // the agent's candidate pairs under its lock, which a mid-gather agent on a
    // single slow core can hold long enough to wedge the driver. Diagnostic
    // only, so a timed-out pass just drops one log line (see
    // `scheduler::ICE_INTROSPECT_TIMEOUT_MS`).
    let snap = match tokio::time::timeout(
        Duration::from_millis(scheduler::ICE_INTROSPECT_TIMEOUT_MS),
        session.ice_check_snapshot(),
    )
    .await
    {
        Ok(snap) => snap,
        Err(_) => {
            debug!(peer = %device_id, "ice_check_snapshot introspection timed out — skipping this tick");
            return;
        }
    };
    if state.peers.get_if_current(owner).is_none() {
        return;
    }
    if snap.is_empty() {
        return;
    }
    let detail = serde_json::json!({
        "peer": device_id,
        "context": context,
        "snapshot": snap,
    });
    if full {
        // Concise one-liner at WARN — counts plus the plain-language
        // diagnosis (e.g. "no remote candidates arrived"). This is the part
        // worth seeing on the default stream; the per-candidate / per-pair
        // dump below is deep instrumentation kept behind debug.
        let header = format!(
            "ICE check for {} ({context}): {} local · {} remote · {} pairs · {} succeeded — {}",
            short_peer(device_id),
            snap.local_candidates.len(),
            snap.remote_candidates.len(),
            snap.pairs.len(),
            snap.succeeded_pairs(),
            snap.diagnosis(),
        );
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "ice",
            header,
            detail.clone(),
        );

        // Skip building the (potentially long) candidate/pair dump unless
        // debug logging is actually on — it only ever rendered at debug now.
        if tracing::enabled!(tracing::Level::DEBUG) {
            let mut msg = format!(
                "ICE detail for {} ({context}):\n  local : {}\n  remote: {}",
                short_peer(device_id),
                render_candidate_list(&snap.local_candidates),
                render_candidate_list(&snap.remote_candidates),
            );
            // Per-pair: only `state` and `nominated` are real — webrtc-ice
            // 0.13 leaves the STUN/byte counters at zero (see
            // `diag::IcePairSnapshot`), so printing them was pure noise. Cap
            // the dump: a churning agent can form 150+ pairs. The pairs are
            // pre-sorted nominated→succeeded→active, so the capped head is the
            // informative part; the tail is summarized.
            const MAX_PAIRS_LOGGED: usize = 12;
            for p in snap.pairs.iter().take(MAX_PAIRS_LOGGED) {
                msg.push_str(&format!(
                    "\n  {} ⇄ {} [{}{}]",
                    p.local,
                    p.remote,
                    p.state,
                    if p.nominated { " NOMINATED" } else { "" },
                ));
            }
            if snap.pairs.len() > MAX_PAIRS_LOGGED {
                let hidden = snap.pairs.len() - MAX_PAIRS_LOGGED;
                let failed = snap.pairs.iter().filter(|p| p.state == "failed").count();
                msg.push_str(&format!(
                    "\n  (… and {hidden} more pairs not shown · {failed} failed of {} total)",
                    snap.pairs.len(),
                ));
            }
            state.log_diag_with(crate::events::DiagLevel::Debug, "ice", msg, detail);
        }
    } else {
        let msg = format!(
            "ICE checking {} — {}/{} pairs succeeded · {}",
            short_peer(device_id),
            snap.succeeded_pairs(),
            snap.pairs.len(),
            snap.diagnosis(),
        );
        state.log_diag_with(crate::events::DiagLevel::Debug, "ice", msg, detail);
    }
}

/// Comma-join a candidate list for the snapshot log, or `(none)` when
/// empty so an absent side reads unambiguously rather than as a blank.
fn render_candidate_list(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

async fn handle_pc_state_change(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    pc: RTCPeerConnectionState,
) {
    // A closed connection is a real teardown — drop and let discovery
    // rebuild. Every other PC state, `Failed` included, is a no-op:
    // ICE-`Failed` (`handle_ice_state_change`) already kicks the in-place
    // restart, and teardown of a still-connecting peer comes from the
    // data-channel-open timeout while an already-open peer is reclaimed by
    // inbound silence. (`Failed` used to arm the old checking-timeout; that
    // machinery is gone — ICE/PC state no longer tears anyone down.)
    if pc == RTCPeerConnectionState::Closed {
        drop_peer_if_current(state, owner, DropReason::IceFailed).await;
    }
}

/// The largest inbound frame we'll even attempt to decode (MOM-04). A peer
/// can't drive memory growth by sending a giant JSON frame: anything past this
/// is dropped *before* `serde_json` allocates the (potentially far larger)
/// parsed value — the opaque user-channel payloads are `serde_json::Value`,
/// which a crafted frame can amplify well beyond its wire size. Generous — far
/// above any real handshake / roster / governance / RPC / user-channel frame —
/// so it only ever bites a pathological one. (Per-peer byte-rate budgets are a
/// deeper follow-up; this is the hard per-frame ceiling.)
pub const MAX_ENDPOINT_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Whether an inbound frame is small enough to decode. Split out so the
/// [`MAX_ENDPOINT_FRAME_BYTES`] boundary is unit-tested.
fn frame_within_cap(len: usize) -> bool {
    len <= MAX_ENDPOINT_FRAME_BYTES
}

/// Which admission phase an inbound frame requires before it may move peer
/// state or reach a handler. Enforced by the gate in [`handle_inbound_frame`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Handshake + approval protocol frames (`Hello`, `AuthResponse`,
    /// `Approve`, `Deny`). Always processed: they only advance or tear down the
    /// handshake and grant no application access. Reaching `Active` still
    /// requires `authenticated` (see [`handshake::on_approve`]), so an early
    /// `Approve` cannot promote an unauthenticated peer.
    Protocol,
    /// Application, RPC, reliable, governance/roster, capabilities, shelve, and
    /// keepalive traffic — processed only once the peer is admitted.
    Application,
}

/// Classify an inbound frame's admission phase. Only the four handshake/
/// approval frames are `Protocol`; everything else — including any future
/// variant — is `Application` and requires an admitted peer (fail closed).
fn message_admission(msg: &MeshMessage) -> Admission {
    match msg {
        MeshMessage::Hello(_)
        | MeshMessage::AuthResponse(_)
        | MeshMessage::Approve(_)
        | MeshMessage::Deny(_) => Admission::Protocol,
        _ => Admission::Application,
    }
}

#[cfg(test)]
async fn handle_inbound_frame(state: &Arc<NetworkState>, device_id: &str, bytes: Bytes) {
    let Some(owner) = state.peers.owner(device_id) else {
        return;
    };
    handle_inbound_frame_from(state, &owner, bytes).await;
}

async fn handle_inbound_frame_from(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    bytes: Bytes,
) {
    let device_id = owner.device_id();
    // Reject an oversize frame before the deserializer allocates for it.
    if !frame_within_cap(bytes.len()) {
        warn!(
            peer = %device_id,
            len = bytes.len(),
            "dropping oversize inbound endpoint frame (> {MAX_ENDPOINT_FRAME_BYTES} bytes)"
        );
        return;
    }
    let msg: MeshMessage = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            warn!(peer = %device_id, "discarding undeserializable frame: {e}");
            return;
        }
    };
    // Admission gate, folded into the per-frame liveness touch below so it
    // costs no extra lookup or lock. Admission is a per-connection property
    // that flips only at the handshake/approval (and topology-shelve)
    // transitions — each frame just reads it. An endpoint with a live data
    // channel but an unfinished handshake + approval may drive only the
    // handshake protocol itself (`Hello`/`AuthResponse`/`Approve`/`Deny`);
    // application, RPC, reliable, governance/roster, capabilities, shelve, and
    // keepalive frames are dropped here — before liveness, recovery-tier, or
    // traffic state moves — so a pre-admission frame is a true no-op it can't
    // use to fake liveness, clear a recovery, or reach a handler. Reaching
    // `Active` itself additionally requires `authenticated` (see
    // `handshake::on_approve`). This check is synchronous, not swept: a
    // never-admitted peer must get *zero* application processing, so there is
    // no grace window a periodic revalidation could open.
    let application = matches!(message_admission(&msg), Admission::Application);
    // The liveness commit for an inbound frame. Protocol frames take the plain
    // owner fence, because they are what *establishes* admission and must not
    // require it. An application frame takes the admission fence instead, so the
    // decision to accept it and the state it moves happen at one linearization
    // point under the registry mutation lock, rather than reading a boolean and
    // acting on it afterwards.
    let commit = |peer: &Arc<PeerConnection>| {
        let mut data = peer.state.write();
        data.last_recv_at = Some(Instant::now());
        data.diag.bytes_in += bytes.len() as u64;
        data.diag.frames_in += 1;
        // Inbound traffic is the proof a restart actually worked — ICE
        // state isn't (see `handle_ice_state_change`). A frame here
        // promotes a recovering peer back to Steady and clears the ICE
        // disconnect marker, so the restart-verify watchdog leaves it
        // alone. This is the single signal that says "the link is really
        // carrying frames again."
        if matches!(
            data.tier,
            ConnectionTier::IceWatchdog { .. }
                | ConnectionTier::IceRestart { .. }
                | ConnectionTier::WakeProbe
        ) {
            data.tier = ConnectionTier::Steady;
            data.ice_disconnected_since = None;
        }
    };
    if !application {
        // Protocol frames take the plain owner fence and dispatch on the owner
        // token they arrived with. They establish admission rather than
        // requiring it, and every handler below is already owner-bound.
        if state.peers.with_current(owner, commit).is_none() {
            return;
        }
        state
            .traffic
            .record_rx(traffic::class_of(&msg), bytes.len());
        match msg {
            MeshMessage::Hello(hello) => handshake::on_hello(state, owner, hello).await,
            MeshMessage::AuthResponse(resp) => {
                handshake::on_auth_response(state, owner, resp).await
            }
            MeshMessage::Approve(_) => handshake::on_approve(state, owner).await,
            MeshMessage::Deny(d) => handshake::on_deny(state, owner, d).await,
            // `message_admission` classifies exactly those four as `Protocol`
            // and everything else — including any future variant — as
            // `Application`, so nothing else reaches here. Dropped rather than
            // panicked on: this is peer-supplied input.
            _ => trace!(peer = %device_id, "discarding misclassified protocol frame"),
        }
        return;
    }

    // The admission answer never becomes a value. The fence either yields an
    // authority that already binds the exact owner, the exact captured peer,
    // and the one parsed frame, or it yields nothing — and a caller holding
    // nothing has nothing to dispatch. This is the whole of E1: what used to
    // escape here was an `Option<bool>`, after which every arm below
    // re-resolved the peer by device id and a replacement answered.
    //
    // The reliable *outbox* is the one effect that cannot wait for the
    // dispatch: it is keyed by device id and shared across installations, so an
    // ack applied after replacement would drain entries the next installation
    // owns. It is drained inside the fence, atomically with the admission that
    // authorized it; only the caller waits it owes travel out. The receive-side
    // high-water mark is *not* settled here — it moves together with the
    // delivery, under the dispatch's own fence, in `on_channel_seq_admitted`.
    let mut reliable = reliable::InboundReliableAdmission::Nothing;
    let admitted = state
        .peers
        .with_admitted_current_or_refused(
            owner,
            |admitted| {
                admitted.record_inbound(commit);
                reliable = reliable::admit_inbound_reliable(state, owner.device_id(), &msg);
                Some(admitted.inbound_application_operation(msg))
            },
            |peer| {
                // Counted under the same acquisition that refused it, so the
                // count cannot be attributed to a replacement that landed
                // between the refusal and the bookkeeping.
                let mut data = peer.state.write();
                data.admission_rejected = data.admission_rejected.saturating_add(1);
                let count = data.admission_rejected;
                drop(data);
                // Power-of-two throttle so a pre-admission flood can't be turned
                // into a log-amplification primitive; the running total stays
                // visible for diagnostics.
                if count.is_power_of_two() {
                    warn!(
                        peer = %device_id,
                        count,
                        "dropping pre-admission frame from a peer that has not finished authenticating and approving"
                    );
                }
                None
            },
        )
        // A stale owner and a refusal collapse to the same `None`: an admission
        // answer that could be told apart out here would be exactly the
        // transient boolean this replaces.
        .flatten();
    let Some(operation) = admitted else {
        return;
    };
    let (msg, dispatch) = operation.into_dispatch();
    state
        .traffic
        .record_rx(traffic::class_of(&msg), bytes.len());
    // From here on `device_id` is never a dispatch key: every arm names the
    // captured installation, through the witness or through its owner token.
    let owner = dispatch.owner();
    match msg {
        MeshMessage::Ping(p) => heartbeat::on_ping(state, &dispatch, p).await,
        MeshMessage::Pong(p) => heartbeat::on_pong(state, &dispatch, p).await,
        MeshMessage::Shelve(s) => on_shelve(state, &dispatch, s).await,
        MeshMessage::Unshelve(_) => on_unshelve(state, &dispatch).await,
        MeshMessage::CapabilitiesUpdate(u) => on_capabilities_update(state, &dispatch, u).await,
        MeshMessage::RpcRequest(req) => on_rpc_request(state, &dispatch, req).await,
        // The three response arms settle *our own* pending outbound calls,
        // resolved by `request_id` against a table the local requester owns.
        // They move no peer state, send nothing, and deliver nothing under a
        // device id, so there is no installation for a replacement to be
        // confused with — but they take the witness rather than a device id so
        // no re-resolution key is in scope for them either.
        MeshMessage::RpcResponse(resp) => on_rpc_response(state, &dispatch, resp).await,
        MeshMessage::RpcStreamChunk(c) => on_rpc_stream_chunk(state, &dispatch, c).await,
        MeshMessage::RpcStreamEnd(e) => on_rpc_stream_end(state, &dispatch, e).await,
        MeshMessage::Channel { channel, payload } => {
            on_channel_frame(state, &dispatch, channel, payload).await
        }
        // The high-water mark and the delivery move together, under one fence,
        // inside the handler. Nothing about this frame was decided above: the
        // admission fence carried the payload out, not a verdict about it.
        MeshMessage::ChannelSeq {
            stream,
            seq,
            channel,
            payload,
        } => {
            reliable::on_channel_seq_admitted(state, &dispatch, stream, seq, channel, payload).await
        }
        // The outbox was already settled inside the fence, against the entries
        // as they stood at admission — nothing out here can drain a
        // replacement's. All that is left is resolving the local caller waits
        // it owes, which is not peer state and not anything a replacement can
        // observe. See `InboundReliableAdmission::settle`.
        MeshMessage::ChannelAck { .. } => reliable.settle(),
        MeshMessage::NetworkState(b) => governance::on_state_broadcast(state, owner, b).await,
        // The four arms below mutate durable, pubkey-keyed governance and
        // roster facts. They resolve no peer entry, send nothing to the sender,
        // and so have no installation-scoped effect a replacement could
        // receive; their sender-directed follow-ups (the roster pull and reply)
        // are the owner-bound arms above and below. They take the attributed
        // device id, which is mesh identity here, not a registry key.
        MeshMessage::NetworkStatePropose(m) => {
            governance::on_propose(state, owner.device_id(), m).await
        }
        MeshMessage::NetworkStateAck(m) => governance::on_ack(state, owner.device_id(), m).await,
        MeshMessage::NetworkStateSplit(m) => {
            governance::on_split(state, owner.device_id(), m).await
        }
        MeshMessage::RosterSummary(m) => governance::on_roster_summary(state, owner, m).await,
        MeshMessage::RosterRequest(m) => governance::on_roster_request(state, owner, m).await,
        MeshMessage::RosterEntries(m) => {
            governance::on_roster_entries(state, owner.device_id(), m).await
        }
        // Unreachable at runtime: `message_admission` classifies exactly these
        // four as `Protocol`, and the protocol branch above returns before this
        // match. They are listed explicitly rather than swept up by a `_` arm
        // so that a *new* `MeshMessage` variant — which `message_admission`
        // classifies as `Application` by its fail-closed default — still breaks
        // this match at compile time and has to be handled deliberately.
        // Discarded rather than panicked on: this is peer-supplied input.
        MeshMessage::Hello(_)
        | MeshMessage::AuthResponse(_)
        | MeshMessage::Approve(_)
        | MeshMessage::Deny(_) => {
            trace!(peer = %device_id, "discarding misclassified protocol frame");
        }
        MeshMessage::Unknown => {
            trace!(peer = %device_id, "discarding unknown frame variant");
        }
    }
}

async fn on_shelve(
    state: &Arc<NetworkState>,
    dispatch: &state::AdmittedInboundDispatch,
    msg: ShelveMessage,
) {
    // Transition and announcement are one step, taken inside the registry
    // fence. Deciding under the fence and emitting after it would put a bool
    // back on the outside — and the event would then describe a peer that a
    // replacement had already superseded.
    // The refusal needs no handling here: a superseded installation simply has
    // no shelve state left to move, and nothing is owed to anyone. Discarded
    // explicitly so that stays a decision rather than an oversight.
    let _ = dispatch.with_captured_peer(&state.peers, |peer| {
        let mut data = peer.state.write();
        if data.remote_shelved {
            return;
        }
        data.remote_shelved = true;
        drop(data);
        state.emit(MeshEvent::Peer(PeerEvent::Shelved {
            network_id: state.network_id.clone(),
            device_id: dispatch.owner().device_id().to_string(),
            reason: msg.reason,
            by_us: false,
        }));
    });
}

async fn on_unshelve(state: &Arc<NetworkState>, dispatch: &state::AdmittedInboundDispatch) {
    let _ = dispatch.with_captured_peer(&state.peers, |peer| {
        let mut data = peer.state.write();
        if !data.remote_shelved {
            return;
        }
        data.remote_shelved = false;
        drop(data);
        state.emit(MeshEvent::Peer(PeerEvent::Unshelved {
            network_id: state.network_id.clone(),
            device_id: dispatch.owner().device_id().to_string(),
            by_us: false,
        }));
    });
}

async fn on_capabilities_update(
    state: &Arc<NetworkState>,
    dispatch: &state::AdmittedInboundDispatch,
    msg: CapabilitiesUpdateMessage,
) {
    // The capability set and the event announcing it are applied as one step
    // inside the fence. The event used to be emitted unconditionally, so a
    // peer that had already been replaced still announced a capability change
    // no live installation held.
    let _ = dispatch.with_captured_peer(&state.peers, |peer| {
        peer.state.write().capabilities = Some(msg.capabilities.clone());
        state.emit(MeshEvent::Peer(PeerEvent::CapabilitiesChanged {
            network_id: state.network_id.clone(),
            device_id: dispatch.owner().device_id().to_string(),
            capabilities: msg.capabilities,
        }));
    });
}

/// One RPC handler lifted out of the map, so the registry fence is never taken
/// while a DashMap shard guard is held.
enum PreparedRpcHandler {
    Single(crate::rpc::RpcHandler),
    Stream(crate::rpc::RpcStreamHandler),
}

/// Move-only authority to run exactly one RPC handler on behalf of one exact
/// peer installation.
///
/// Minted **inside** the registry fence, so possessing one is unforgeable proof
/// that the captured installation was the installed one at a single
/// linearization point.
///
/// Minting is all that happens under the lock: the closure that produces this
/// builds a value and calls nothing. The handler is deliberately *not* invoked
/// there. Invoking it would run arbitrary embedder code under
/// `PeerRegistry::mutation`, and a handler that called back into the mesh would
/// deadlock outright, since that lock is not reentrant.
///
/// **What this does and does not guarantee.** A replacement that lands *before*
/// the mint refuses the authority outright, and the handler never runs. A
/// replacement that lands *after* the mint does **not** cancel it: the handler
/// was already authorized and will run to completion. What the capture buys is
/// that the run is attributable and its results cannot escape — the owner is
/// taken at mint time and travels with the call, so every reply goes through
/// `send_to_peer_owner` against *that* installation and fails closed once it is
/// superseded, rather than being delivered to whoever holds the device id by
/// then. Authorization is atomic; execution is not fenced, and nothing here
/// pretends otherwise.
#[must_use = "an admitted RPC call authorizes exactly one handler run and must be consumed"]
struct AdmittedRpcCall {
    handler: PreparedRpcHandler,
    call: crate::rpc::RpcCall,
    owner: state::PeerOwnerToken,
}

async fn on_rpc_request(
    state: &Arc<NetworkState>,
    dispatch: &state::AdmittedInboundDispatch,
    req: RpcRequestMessage,
) {
    let owner = dispatch.owner();
    let device_id = owner.device_id();
    let Some(rpc) = state.rpc.read().clone() else {
        // No RPC bound yet — send a transient error so the peer
        // doesn't hang on the oneshot.
        let _ = send_to_peer_owner(
            state,
            owner,
            &MeshMessage::RpcResponse(RpcResponseMessage {
                request_id: req.request_id,
                ok: None,
                error: Some("rpc not bound".into()),
            }),
        )
        .await;
        return;
    };
    let call = crate::rpc::RpcCall {
        from: device_id.to_string(),
        request_id: req.request_id.clone(),
        method: req.method.clone(),
        payload: req.payload.clone(),
        streaming: req.streaming,
    };
    let handler = rpc.handlers.get(&req.method);
    let Some(handler) = handler else {
        let _ = send_to_peer_owner(
            state,
            owner,
            &MeshMessage::RpcResponse(RpcResponseMessage {
                request_id: req.request_id,
                ok: None,
                error: Some(format!("no handler for '{}'", req.method)),
            }),
        )
        .await;
        return;
    };
    // A user handler is an application effect, and the heaviest one here: it
    // runs embedder code and can do anything. Invoking it is therefore claimed
    // *inside* the fence rather than after a currency check — a check would
    // leave a window in which the installation is replaced before the handler
    // is entered, which is the same escape in a smaller form.
    //
    // What is taken under the lock is the *authority* to run it, not the run
    // itself: the fenced closure builds an `AdmittedRpcCall` and calls nothing,
    // so no embedder code executes under `PeerRegistry::mutation` and a handler
    // that calls back into the mesh cannot deadlock against it. The handler is
    // invoked only after the lock is released.
    //
    // The two replacement cases differ, and the difference is deliberate. A
    // replacement *before* the mint refuses the authority and the handler never
    // runs — that is the request lost to a fast reconnect, covered by the
    // caller's own timeout. A replacement *after* the mint does not cancel
    // anything: the handler was already authorized and runs to completion. It
    // stays harmless because its replies are owner-bound, so they fail closed
    // against the superseded installation instead of being delivered to
    // whoever holds the device id by then.
    //
    // The handler is cloned out of the RPC map and the map guard dropped before
    // the fence, so the registry lock is never taken while holding a DashMap
    // shard guard.
    let prepared = match &*handler {
        crate::rpc::HandlerEntry::Single(h) => PreparedRpcHandler::Single(h.clone()),
        crate::rpc::HandlerEntry::Stream(h) => PreparedRpcHandler::Stream(h.clone()),
    };
    drop(handler);
    let Some(admitted) = dispatch.with_captured_peer(&state.peers, move |_peer| AdmittedRpcCall {
        handler: prepared,
        call,
        owner: owner.clone(),
    }) else {
        return;
    };
    // Lock released. Consume the authority exactly once.
    let AdmittedRpcCall {
        handler,
        call,
        owner,
    } = admitted;
    let request_id = req.request_id;
    let state = state.clone();
    match handler {
        PreparedRpcHandler::Single(h) => {
            let fut = h(call);
            tokio::spawn(async move {
                let resp = fut.await;
                let frame = match resp {
                    Ok(r) => RpcResponseMessage {
                        request_id,
                        ok: Some(r.body),
                        error: None,
                    },
                    Err(e) => RpcResponseMessage {
                        request_id,
                        ok: None,
                        error: Some(e),
                    },
                };
                let _ = send_to_peer_owner(&state, &owner, &MeshMessage::RpcResponse(frame)).await;
            });
        }
        PreparedRpcHandler::Stream(h) => {
            let fut = h(call);
            tokio::spawn(async move {
                let mut rx = match fut.await {
                    Ok(rx) => rx,
                    Err(e) => {
                        let _ = send_to_peer_owner(
                            &state,
                            &owner,
                            &MeshMessage::RpcStreamEnd(RpcStreamEndMessage {
                                request_id,
                                error: Some(e),
                            }),
                        )
                        .await;
                        return;
                    }
                };
                let mut seq = 0u64;
                while let Some(payload) = rx.recv().await {
                    seq += 1;
                    let _ = send_to_peer_owner(
                        &state,
                        &owner,
                        &MeshMessage::RpcStreamChunk(RpcStreamChunkMessage {
                            request_id: request_id.clone(),
                            seq,
                            payload,
                        }),
                    )
                    .await;
                }
                let _ = send_to_peer_owner(
                    &state,
                    &owner,
                    &MeshMessage::RpcStreamEnd(RpcStreamEndMessage {
                        request_id,
                        error: None,
                    }),
                )
                .await;
            });
        }
    }
}

async fn on_rpc_response(
    state: &Arc<NetworkState>,
    _dispatch: &state::AdmittedInboundDispatch,
    resp: RpcResponseMessage,
) {
    let rpc = match state.rpc.read().clone() {
        Some(r) => r,
        None => return,
    };
    let Some((_, entry)) = rpc.pending.remove(&resp.request_id) else {
        return;
    };
    if let crate::rpc::PendingEntry::Single(tx) = entry {
        let result = if let Some(err) = resp.error {
            Err(err)
        } else {
            Ok(crate::rpc::RpcResponse {
                body: resp.ok.unwrap_or(serde_json::Value::Null),
            })
        };
        let _ = tx.send(result);
    }
}

async fn on_rpc_stream_chunk(
    state: &Arc<NetworkState>,
    _dispatch: &state::AdmittedInboundDispatch,
    chunk: RpcStreamChunkMessage,
) {
    let rpc = match state.rpc.read().clone() {
        Some(r) => r,
        None => return,
    };
    // Pull the sender out under the DashMap shard lock, drop the
    // ref, then send — sender clone is cheap and avoids holding
    // the ref across the send.
    let sender = rpc
        .pending
        .get(&chunk.request_id)
        .and_then(|entry| match &*entry {
            crate::rpc::PendingEntry::Stream(tx) => Some(tx.clone()),
            crate::rpc::PendingEntry::Single(_) => None,
        });
    if let Some(tx) = sender {
        let _ = tx.send(Ok(chunk.payload));
    }
}

async fn on_rpc_stream_end(
    state: &Arc<NetworkState>,
    _dispatch: &state::AdmittedInboundDispatch,
    end: RpcStreamEndMessage,
) {
    let rpc = match state.rpc.read().clone() {
        Some(r) => r,
        None => return,
    };
    if let Some((_, crate::rpc::PendingEntry::Stream(tx))) = rpc.pending.remove(&end.request_id) {
        if let Some(err) = end.error {
            let _ = tx.send(Err(err));
        }
        // Drop the sender so the receiver's loop exits.
        drop(tx);
    }
}

async fn on_channel_frame(
    state: &Arc<NetworkState>,
    dispatch: &state::AdmittedInboundDispatch,
    channel: String,
    payload: serde_json::Value,
) {
    // Delivery is an application effect, and the one whose escape is visible
    // outside the engine: a subscriber reads `from` as a device identity, so a
    // payload admitted for one installation, delivered after that installation
    // was replaced, is attributed to whoever holds the id now. The delivery
    // therefore happens *inside* the fence, not after a currency check —
    // replacement takes the same lock, so it lands strictly before or after
    // this send and never in the middle of it.
    //
    // `dispatch_channel_frame` is a broadcast hand-off: it never blocks on a
    // subscriber and never re-enters the registry, so it is safe under the
    // mutation lock.
    // Refusal is the intended outcome for a superseded installation: the
    // payload is dropped rather than delivered under an id someone else now
    // holds, and no subscriber is owed a notification of that.
    let _ = dispatch.with_captured_peer(&state.peers, |_peer| {
        // Arc 03 never interprets an endpoint frame as an ordinary-member
        // routing envelope. The legacy routing module remains tracked by
        // RTM-001, but the V4 inbound path does not dispatch into it.
        state.dispatch_channel_frame(&channel, dispatch.owner().device_id(), payload);
    });
}

/// Send a single MeshMessage to one peer. Best-effort: returns an
/// error if the peer is unknown or the data channel isn't open
/// yet. Engine paths use this directly; user-facing channels call
/// the [`NetworkState::send_channel_frame`] wrapper.
/// Resolve one admitted real-time operation for `device_id`.
///
/// One owner resolution, then the admission fence. The wrapper it returns keeps
/// the connector worker and the flow capability paired for the await that
/// follows, so neither can be re-paired with another peer's half.
fn admitted_realtime_operation(
    state: &Arc<NetworkState>,
    device_id: &str,
) -> Option<state::AdmittedRealtimeOperation> {
    let owner = state.peers.owner(device_id)?;
    state
        .peers
        .with_admitted_current(&owner, |admitted| admitted.realtime_operation())
        .flatten()
}

/// Resolve the exact current owner once, then send through it.
///
/// The device id is used for exactly one lookup and never again: everything
/// after this point is keyed to the installation that lookup found. The old
/// shape looked the peer up a second time *after* the await to record the
/// send, which attributed those bytes to whatever entry was current by then —
/// a replacement included.
pub(crate) async fn send_to_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    msg: &MeshMessage,
) -> Result<()> {
    let Some(owner) = state.peers.owner(device_id) else {
        return Err(Error::Network(format!("peer not found: {device_id}")));
    };
    send_to_peer_owner(state, &owner, msg).await
}

/// The one outbound send.
///
/// An application frame is authorized by an owned witness minted under the
/// registry fence, and both the write and its accounting go through the exact
/// worker and peer that witness captured. Bounded: this runs inline on the
/// driver task (reachable via the heartbeat ping and the state-watch tick's
/// shelve-unshelve), so a data-channel write that parks on a slow core mid-gather
/// would wedge the whole driver. Best-effort by contract, so a timed-out control
/// frame is just dropped and re-sent next cycle.
pub(crate) async fn send_to_peer_owner(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    msg: &MeshMessage,
) -> Result<()> {
    let serialized = serde_json::to_vec(msg).map_err(Error::Serde)?;
    let class = traffic::class_of(msg);
    let timeout = Duration::from_millis(scheduler::PEER_SEND_TIMEOUT_MS);
    let sent = if matches!(message_admission(msg), Admission::Application) {
        state
            .peers
            .admit_application_operation(owner)
            .ok_or_else(|| {
                Error::Network(format!(
                    "peer owner is not admitted for application traffic: {}",
                    owner.device_id()
                ))
            })?
            .send_frame(Bytes::from(serialized), timeout)
            .await?
    } else {
        // Protocol admission traffic — Hello, AuthResponse, Approve, Deny — is
        // deliberately ungated: it is what establishes the capability the gate
        // above requires. It still sends only through the exact current owner.
        let peer = state
            .peers
            .get_if_current(owner)
            .ok_or_else(|| Error::Network(format!("peer owner is stale: {}", owner.device_id())))?;
        let session = peer
            .session
            .lock()
            .clone()
            .ok_or_else(|| Error::Transport("session not yet established".into()))?;
        let sent = tokio::time::timeout(timeout, session.send_owned(Bytes::from(serialized)))
            .await
            .map_err(|_| Error::Transport("peer send timed out".into()))??;
        let mut data = peer.state.write();
        data.diag.bytes_out += sent as u64;
        data.diag.frames_out += 1;
        sent
    };
    state.traffic.record_tx(class, sent);
    Ok(())
}

async fn send_channel_frame(
    state: &Arc<NetworkState>,
    peer: &str,
    channel: &str,
    payload: serde_json::Value,
) -> Result<()> {
    // No pre-check. A channel frame is application class, so `send_to_peer`
    // already refuses it unless the fence mints a witness — and a pre-check
    // here would be a second, earlier read whose answer could have changed by
    // the time the send ran.
    send_to_peer(
        state,
        peer,
        &MeshMessage::Channel {
            channel: channel.to_string(),
            payload,
        },
    )
    .await
}

async fn broadcast_channel_frame(
    state: &Arc<NetworkState>,
    channel: &str,
    payload: serde_json::Value,
) -> usize {
    // V4 broadcast is one direct send per connected endpoint. It never asks
    // an ordinary member to forward application payload.
    let peers: Vec<String> = state.peers.collect_map(|peer| {
        let data = peer.state.read();
        (matches!(data.status, PeerStatus::Active) && !data.local_shelved && !data.remote_shelved)
            .then(|| peer.device_id.clone())
    });
    let mut delivered = 0usize;
    for peer in peers {
        if send_to_peer(
            state,
            &peer,
            &MeshMessage::Channel {
                channel: channel.to_string(),
                payload: payload.clone(),
            },
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }
    delivered
}

async fn send_rpc_request(
    state: &Arc<NetworkState>,
    peer: &str,
    request: RpcRequestMessage,
) -> Result<()> {
    send_to_peer(state, peer, &MeshMessage::RpcRequest(request)).await
}

async fn broadcast_capabilities(state: &Arc<NetworkState>, caps: CapabilityAdvert) -> usize {
    let peers: Vec<String> = state.peers.collect_map(|peer| {
        matches!(peer.state.read().status, PeerStatus::Active).then(|| peer.device_id.clone())
    });
    let mut delivered = 0usize;
    for peer in peers {
        if send_to_peer(
            state,
            &peer,
            &MeshMessage::CapabilitiesUpdate(CapabilitiesUpdateMessage {
                capabilities: caps.clone(),
            }),
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }
    delivered
}

/// Engine-side wiring of the documented inbound-recency zombie
/// clearing (`STALE_INBOUND_MS`). When a fresh announce/offer arrives
/// from a peer we still hold but haven't received anything from in
/// longer than the threshold, the existing peer connection is a
/// zombie: applying the new SDP onto it would wedge WebRTC, and
/// `ensure_peer_session` would short-circuit on the stale entry. Drop
/// it first so the inbound signal drives a clean rebuild.
///
/// This is the path that lets a node which was frozen (and torn down
/// by its peers) recover in seconds: once it re-announces on wake and
/// a neighbor's offer comes back, the woken node clears its own stale
/// session here instead of waiting for the next scheduled announce.
///
/// A peer with no recorded inbound yet (`last_recv_at == None`, e.g.
/// mid-first-handshake or stuck at `Sighted`) is left untouched — only
/// a peer that was receiving and then went silent is a zombie; the
/// Sighted-stuck case is handled by the re-offer path instead.
async fn clear_stale_session_if_zombie(state: &Arc<NetworkState>, device_id: &str) {
    let is_zombie = match state.peers.get(device_id) {
        Some(peer) => {
            let stale = match peer.state.read().last_recv_at {
                Some(last) => last.elapsed().as_millis() as u64 > scheduler::STALE_INBOUND_MS,
                None => false,
            };
            if !stale {
                false
            } else {
                // Stale inbound is necessary but not sufficient. A session
                // whose ICE is actively checking or connected — or that we
                // kicked an in-place restart on within the last checking
                // window — is mid-recovery, not a wedged zombie. Dropping it
                // here is exactly what guillotined the restart-before-drop
                // path after a wake: the restart had already re-gathered, but
                // inbound was still pre-wake-stale, so the next announce tore
                // it down and forced a full rebuild storm. Give recovery a
                // full window before the zombie path can reclaim the peer; a
                // genuinely dead session (Failed/Disconnected/New with no
                // restart in flight) still gets cleared as before.
                let recovering = {
                    let restart_in_flight = {
                        let data = peer.state.read();
                        match data.tier {
                            ConnectionTier::IceRestart { started } => {
                                started.elapsed()
                                    < Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS)
                            }
                            ConnectionTier::IceWatchdog { since } => {
                                since.elapsed()
                                    < Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS)
                            }
                            _ => false,
                        }
                    };
                    let ice_live = peer
                        .session
                        .lock()
                        .as_ref()
                        .map(|s| {
                            matches!(
                                s.ice_connection_state(),
                                RTCIceConnectionState::Checking
                                    | RTCIceConnectionState::Connected
                                    | RTCIceConnectionState::Completed
                            )
                        })
                        .unwrap_or(false);
                    restart_in_flight || ice_live
                };
                !recovering
            }
        }
        None => false,
    };
    if is_zombie {
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "signaling",
            format!(
                "clearing stale session for {} before rebuild (no inbound > {} ms)",
                short_peer(device_id),
                scheduler::STALE_INBOUND_MS
            ),
            serde_json::json!({
                "peer": device_id,
                "stale_inbound_ms": scheduler::STALE_INBOUND_MS,
            }),
        );
        drop_peer(state, device_id, DropReason::HeartbeatTimeout).await;
    }
}

/// Confirm an *established* peer session is really carrying traffic when the
/// peer re-announces — instead of trusting webrtc-rs's ICE state, which the
/// engine elsewhere treats as a liar. The announce path otherwise takes an
/// `Active`/`Shelved` session at face value: the re-offer only fires for a
/// `Sighted` session, the in-place renegotiate only fires when ICE reports
/// *not* connected, and `clear_stale_session_if_zombie` bails the moment ICE
/// claims `Connected`. So a session whose ICE falsely reports `Connected`
/// while it carries no frames — exactly the corpse a peer that restarted (or
/// crashed, or lost power) leaves on the other end — is invisible to all of
/// them, and only the ~90 s heartbeat backstop ever reclaims it. That
/// backstop is unreliable here: the rejoiner re-announces (so it *looks*
/// online) but, where it's the answerer, it waits for an offer its offerer —
/// still believing the link is up — never sends, a standoff that strands it
/// indefinitely. This is the "appears online, no connections, and even the
/// 90 s heartbeat doesn't fix it" report.
///
/// Drive recovery from the announce itself: if we hold the peer Active or
/// Shelved but haven't received a frame in `STALE_INBOUND_MS`, ping it and,
/// after `WAKE_PROBE_DELAY_MS`, rebuild it if it's still silent — the same
/// traffic-confirmed probe [`wake::on_wake`] runs, here triggered by the
/// peer's presence rather than an OS resume. The rebuild drops as
/// `HeartbeatTimeout` (a *recoverable* reason), so the offerer re-offers and
/// the answerer accepts a fresh offer and both ends realign — without
/// depending on the departing peer having managed to send a `Leave`. (The
/// `Leave` stays the instant fast-path for a *deliberate* exit; this is the
/// backstop that also covers crashes, power loss, and a lost `Leave`.)
///
/// Gated so a steady-state announce cadence can't churn healthy peers: only
/// established sessions, only past the inbound-silence threshold (a live
/// link's heartbeat pong keeps `last_recv_at` fresh), single-flighted via
/// `last_liveness_probe_at`, and skipped while an in-place restart owns the
/// recovery window. The teardown is still keyed off inbound traffic, never
/// ICE — the probe only decides *whether to ask*.
async fn confirm_active_session_on_announce(state: &Arc<NetworkState>, device_id: &str) {
    // Decide under the peer lock, stamping the single-flight marker so a
    // burst of announces produces at most one probe. Yields the exact worker
    // being probed, or `None` to skip.
    let probed = match state.peers.owner(device_id) {
        Some(owner) => {
            let Some(peer) = state.peers.get_if_current(&owner) else {
                return;
            };
            let mut data = peer.state.write();
            let established = matches!(data.status, PeerStatus::Active | PeerStatus::Shelved);
            let silent = data
                .last_recv_at
                .map(|t| t.elapsed().as_millis() as u64 > scheduler::STALE_INBOUND_MS)
                .unwrap_or(false);
            // An in-flight in-place restart is mid-recovery; let it own its
            // window rather than racing a rebuild against it (the same guard
            // the zombie clear uses).
            let restart_in_flight = match data.tier {
                ConnectionTier::IceRestart { started } => {
                    started.elapsed()
                        < Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS)
                }
                ConnectionTier::IceWatchdog { since } => {
                    since.elapsed() < Duration::from_millis(scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS)
                }
                _ => false,
            };
            let probed_recently = data
                .last_liveness_probe_at
                .map(|t| {
                    t.elapsed() < Duration::from_millis(scheduler::LIVENESS_PROBE_MIN_INTERVAL_MS)
                })
                .unwrap_or(false);
            if established && silent && !restart_in_flight && !probed_recently {
                data.last_liveness_probe_at = Some(Instant::now());
                drop(data);
                peer.session.lock().clone().map(|worker| (owner, worker))
            } else {
                None
            }
        }
        None => None,
    };
    let Some((owner, probed_worker)) = probed else {
        return;
    };

    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "signaling",
        format!(
            "{} re-announced but its session has been silent > {} ms — probing before trusting ICE",
            short_peer(device_id),
            scheduler::STALE_INBOUND_MS,
        ),
        serde_json::json!({
            "peer": device_id,
            "stale_inbound_ms": scheduler::STALE_INBOUND_MS,
        }),
    );
    heartbeat::send_ping_to_owner(state, &owner).await;

    // Confirm by inbound traffic after the probe delay. Pointer identity
    // ensures this task can reclaim only the exact worker it probed.
    let state = state.clone();
    let device_id = device_id.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(scheduler::WAKE_PROBE_DELAY_MS)).await;
        let still_silent = state.peers.get_if_current(&owner).is_some_and(|peer| {
            let current_worker = peer.session.lock().clone();
            current_worker
                .as_ref()
                .is_some_and(|worker| Arc::ptr_eq(worker, &probed_worker))
                && peer
                    .state
                    .read()
                    .last_recv_at
                    .map(|t| t.elapsed().as_millis() as u64 > scheduler::WAKE_PROBE_DELAY_MS)
                    .unwrap_or(true)
        });
        if still_silent {
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "signaling",
                format!(
                    "{} didn't answer the announce-driven probe — rebuilding",
                    short_peer(&device_id)
                ),
                serde_json::json!({ "peer": device_id }),
            );
            drop_peer_if_current(&state, &owner, crate::events::DropReason::HeartbeatTimeout).await;
            // Re-seed discovery so the rebuilt peer reconnects on the next
            // round-trip rather than waiting for its own announce schedule.
            maybe_reactive_announce(&state);
        }
    });
}

async fn finish_drop_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    reason: DropReason,
    removed: Option<Arc<PeerConnection>>,
) {
    if let Some(peer) = removed {
        let cleanup_peer = Arc::clone(&peer);
        tokio::spawn(async move {
            if let Err(error) = cleanup_peer.retire_and_close().await {
                warn!(%error, "peer cleanup did not complete successfully");
            }
        });
        state.emit(MeshEvent::Peer(PeerEvent::Dropped {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            reason: reason.clone(),
            grace_window_ms: scheduler::RECONNECTING_GRACE_MS,
        }));
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "peer",
            format!("{} dropped ({reason:?})", short_peer(device_id)),
            serde_json::json!({ "peer": device_id, "reason": format!("{reason:?}") }),
        );

        // Self-drive the reconnect for any peer we are the *offerer* for that
        // we lost to a recoverable transport failure — whether it was fully
        // connected (a network shift tore it down) or never completed its
        // first connect (a signaling race delivered zero remote candidates).
        // Either way the *answerer* side waits for our offer and won't
        // re-initiate, so without this an offerer-role peer only comes back on
        // its slow (~120 s) steady-state announce. Events drive the actual
        // re-offer (a relay reconnect flushes intents, an inbound announce
        // rebuilds); the reconnect-supervisor ticker is the backstop. The
        // intent is bounded by the reconnecting grace and is NOT extended by
        // repeated failed rebuilds (see `record_reconnect_intent`), so a peer
        // that genuinely went away ages out instead of spinning. Intentional
        // teardown (UserLeft / Denied / AuthFailed) must never be retried.
        let we_offer = state.identity.public_id() < device_id;
        let sticky = state.is_sticky(device_id);
        // A peer our own signed state has evicted is never reconnected back,
        // whatever the drop reason: the deny-with-proof exchange is a one-shot
        // handoff, not a session to keep alive. Its post-deny channel close
        // arrives as a "recoverable" IceFailed, and because we hold the
        // lex-lower id (so `we_offer`) that would re-arm a reconnect intent —
        // the 2 s connect/deny/drop/redial hot loop that never converges. Fold
        // eviction into the intentional-teardown bucket so we stop self-driving
        // the dial; the evicted device's own periodic announce is still
        // answered and re-denied with proof, so convergence keeps its channel
        // without the spin. Mirror of the `self_evicted` announce gate, which
        // already stands a stood-down engine down from dialing.
        let evicted = governance::log_evicted(state, device_id);
        let recoverable = !evicted
            && matches!(
                reason,
                DropReason::IceFailed
                    | DropReason::HeartbeatTimeout
                    | DropReason::TransportError { .. }
            );
        if recoverable && (we_offer || sticky) {
            state.record_reconnect_intent(device_id, sticky);
            // Whatever was on the wire for the dead session may or may not
            // have landed — queue it all for retransmit on the next ACTIVE;
            // the receiver's high-water mark absorbs any double.
            reliable::mark_unsent(state, device_id);
        } else if recoverable {
            reliable::mark_unsent(state, device_id);
        } else {
            // Intentional removal / leave / auth failure — stop retrying,
            // and tell every parked caller the truth rather than letting
            // them wait out a TTL on a peer that was deliberately ended.
            state.clear_reconnect_intent(device_id);
            let why = format!("{reason:?}");
            reliable::fail_peer(state, device_id, &why);
            state.resolve_connect_waiters(device_id, Some(&why));
        }
    }
    phase::recompute(state);
    ladder::reevaluate_topology(state).await;
}

pub(crate) async fn drop_peer(state: &Arc<NetworkState>, device_id: &str, reason: DropReason) {
    let removed = remove_peer(&state.peers, device_id);
    finish_drop_peer(state, device_id, reason, removed).await;
}

pub(crate) async fn drop_peer_if_current(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
    reason: DropReason,
) {
    let removed = state.peers.remove_if_current(owner);
    if removed.is_none() {
        return;
    }
    finish_drop_peer(state, owner.device_id(), reason, removed).await;
}

/// Install the current peer owner and retire any replaced compatibility queue.
/// Explicit retirement is required because other tasks may still hold an
/// `Arc` to the replaced peer object.
fn install_peer(peers: &state::PeerRegistry, peer: Arc<PeerConnection>) {
    let Some(replaced) = peers.install(peer) else {
        return;
    };
    tokio::spawn(async move {
        if let Err(error) = replaced.retire_and_close().await {
            warn!(%error, "replaced peer cleanup did not complete successfully");
        }
    });
}

/// Remove the current peer owner and retire its compatibility queue before the
/// returned `Arc` can outlive its place in the peer map.
fn remove_peer(peers: &state::PeerRegistry, device_id: &str) -> Option<Arc<PeerConnection>> {
    peers.remove(device_id)
}

/// Build a minimal `NetworkState` for unit tests. One process-wide
/// `MYOWNMESH_HOME` is set once (so parallel unit tests don't clobber
/// each other's env var) and each caller passes a unique suffix so
/// their on-disk roster / state files don't collide.
#[cfg(test)]
pub(crate) fn build_test_state(network_id_suffix: &str) -> Arc<NetworkState> {
    let (state, _cmd_rx) = build_test_state_parts(network_id_suffix);
    state
}

#[cfg(test)]
fn build_test_state_parts(
    network_id_suffix: &str,
) -> (Arc<NetworkState>, mpsc::UnboundedReceiver<NetworkCmd>) {
    build_test_state_parts_with(network_id_suffix, None)
}

/// The one fixture body. `profile_override` is `None` for every existing
/// caller, which keeps the exact data-only behaviour they were built against;
/// only the 04B-3 renegotiation control supplies a legacy-media profile, and it
/// does so through the same grant chain rather than a duplicate of it.
#[cfg(test)]
fn build_test_state_parts_with(
    network_id_suffix: &str,
    profile_override: Option<crate::WebRtcConnectorProfile>,
) -> (Arc<NetworkState>, mpsc::UnboundedReceiver<NetworkCmd>) {
    use std::sync::OnceLock;
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    let _ = HOME.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", dir.path());
        dir
    });

    let network_id = format!("unit-test-{network_id_suffix}");
    let config = crate::config::NetworkConfig {
        id: network_id.clone(),
        network_id,
        label: "test".into(),
        kind: Default::default(),
        topology: crate::config::TopologyMode::FullMesh,
        signaling: crate::config::SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    };
    let identity = Arc::new(crate::identity::Identity::ephemeral());
    let max_connectors = std::num::NonZeroUsize::new(2)
        .expect("engine fixture has two simultaneous connector slots");
    let callback_capacity =
        std::num::NonZeroUsize::new(16).expect("engine fixture callback capacity is nonzero");
    let webrtc_profile = profile_override.unwrap_or_else(|| {
        let callbacks = crate::runtime::attempt::ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(
                callback_capacity,
                callback_capacity,
            ),
            crate::runtime::attempt::ConnectorCallbackServiceWeights::data_only(
                callback_capacity,
                callback_capacity,
            ),
            crate::runtime::attempt::RealtimeConnectorPolicy::Disabled,
        )
        .expect("engine fixture data-only callback policy is valid");
        crate::WebRtcConnectorProfile::new(
            callbacks,
            crate::PendingRemoteCandidatePolicy::elastic(),
        )
    });
    let profiles = vec![webrtc_profile; max_connectors.get()];
    let connectors = std::num::NonZeroU64::new(max_connectors.get() as u64)
        .expect("engine fixture connector count is nonzero");
    let frame_bytes = std::num::NonZeroU64::new(
        u64::try_from(myownmesh_signaling::mdns::wire::MAX_FRAME_BYTES)
            .expect("the signaling frame limit fits u64"),
    )
    .expect("the signaling frame limit is nonzero");
    let candidate_content = std::num::NonZeroU64::new(
        frame_bytes
            .get()
            .checked_mul(connectors.get())
            .expect("engine fixture candidate content is representable"),
    )
    .expect("engine fixture candidate content is nonzero");
    let candidate_strings = std::num::NonZeroU64::new(
        candidate_content
            .get()
            .checked_mul(3)
            .expect("engine fixture candidate strings are representable"),
    )
    .expect("engine fixture candidate strings are nonzero");
    // Every candidate admitted by the fixture has at least one content byte.
    // Therefore the cumulative content envelope is also a conservative upper
    // bound on the number of distinct retained candidates.
    let max_unique_candidates = candidate_content;
    let candidate_grant = crate::transport::webrtc::transport_lab_remote_candidate_fixture_grant(
        max_unique_candidates,
        connectors,
        candidate_strings,
        candidate_content,
        frame_bytes,
    )
    .expect("engine fixture remote-candidate grant is mechanically representable");
    let remote_description_grant =
        crate::transport::webrtc::transport_lab_remote_description_fixture_grant(
            connectors,
            frame_bytes,
            std::num::NonZeroU64::new(1).expect("the data-only fixture has one media section"),
            std::num::NonZeroU64::new(1).expect("the data-only fixture has one active binding"),
            frame_bytes,
        )
        .expect("engine fixture remote-SDP grant is mechanically representable");
    let grant = crate::transport::webrtc::one_mesh_connector_fixture_grant(&profiles)
        .expect("engine fixture construction grant is mechanically representable");
    let grant = grant
        .checked_add(candidate_grant)
        .and_then(|claim| claim.checked_add(remote_description_grant))
        .expect("engine fixture connector and signaling grant is representable");
    let provider = crate::resource::ResourceProviderPort::new(
        crate::resource::FiniteResourceProvider::new(grant),
    )
    .expect("engine fixture provider admits its process scope");
    let owner = crate::runtime::attempt::ConnectorResourceOwnerPort::new(provider);
    let scope = owner
        .issue_mesh_scope()
        .expect("engine fixture process owner issues one explicit Mesh scope");
    let transport = crate::transport::Transport::new()
        .expect("transport")
        .with_connector_resource_scope(scope, webrtc_profile);
    let (state, _signaling_in_rx, cmd_rx) =
        NetworkState::new(config, identity, transport).expect("network state");
    (state, cmd_rx)
}

/// Test state whose connectors carry a legacy-media profile.
///
/// Needed only where a control must reach `realtime_enabled()`, which is
/// `legacy_media_profile.is_some() && realtime_flows.is_enabled()` — both, so a
/// data-only profile can never mint a real-time witness however the peer is
/// admitted.
///
/// Pre-provisioned lanes are deliberately 0/0: the control needs flow authority
/// and `realtime_enabled`, not audio or video m-lines. Media tracks are created
/// only in `for lane in 0..preprovisioned`, so nothing is added to the SDP and
/// the existing one-media-section / one-active-binding remote-description grant
/// stays correct. The connector grant itself auto-derives from the profile.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn build_test_state_with_legacy_media(network_id_suffix: &str) -> Arc<NetworkState> {
    use crate::runtime::attempt::{
        ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy,
        ConnectorCallbackServiceWeights, ConnectorRealtimeByteBudgets,
        ConnectorRealtimeFlowCapacities, ConnectorRealtimeFlowPolicy,
        ConnectorRealtimeInboundLimits, RealtimeConnectorPolicy, RealtimeQueueOverflowRule,
    };
    let nonzero = |value: usize, name: &str| {
        std::num::NonZeroUsize::new(value)
            .unwrap_or_else(|| panic!("engine legacy-media fixture {name} is nonzero"))
    };
    let capacity = nonzero(16, "callback capacity");
    let flows = ConnectorRealtimeFlowPolicy::new(
        // Two flow domains, video and audio.
        ConnectorRealtimeFlowCapacities::new(
            nonzero(2, "inbound flows"),
            nonzero(2, "outbound flows"),
            capacity,
        ),
        ConnectorRealtimeInboundLimits::new(
            nonzero(8, "fragment limit"),
            nonzero(16, "per-unit fragment count"),
            nonzero(1, "per-flow in-progress units"),
            nonzero(1, "pre-auth packet limit"),
            nonzero(16, "pre-auth content bytes"),
        ),
        ConnectorRealtimeByteBudgets::new(
            nonzero(16, "inbound bytes"),
            nonzero(16, "outbound bytes"),
        ),
        RealtimeQueueOverflowRule::DropNewest,
    );
    let realtime =
        RealtimeConnectorPolicy::enabled_with_local_ceiling(nonzero(8, "unit limit"), flows)
            .expect("engine legacy-media fixture real-time policy is structurally valid");
    let callbacks = ConnectorCallbackPolicy::new(
        ConnectorCallbackMailboxCapacities::new(capacity, capacity),
        ConnectorCallbackServiceWeights::new(
            nonzero(1, "control weight"),
            nonzero(1, "endpoint-data weight"),
            nonzero(1, "real-time weight"),
        ),
        realtime,
    )
    .expect("engine legacy-media fixture callback policy is valid");
    let profile = crate::WebRtcConnectorProfile::new(
        callbacks,
        crate::PendingRemoteCandidatePolicy::elastic(),
    )
    .with_legacy_webrtc_media(
        crate::transport::webrtc::LegacyWebRtcMediaProfile::h264_opus(
            nonzero(1, "lane ceiling"),
            0,
            0,
        )
        .expect("engine legacy-media fixture provider is structurally valid"),
    )
    .expect("engine legacy-media fixture real-time policy admits the legacy provider");
    let (state, _cmd_rx) = build_test_state_parts_with(network_id_suffix, Some(profile));
    state
}

/// Build test state with the same serialized command consumer that owns
/// delayed exact-peer mutations in the production driver.
#[cfg(test)]
pub(crate) fn build_test_state_with_command_driver(
    network_id_suffix: &str,
) -> (Arc<NetworkState>, tokio::task::JoinHandle<()>) {
    let (state, mut cmd_rx) = build_test_state_parts(network_id_suffix);
    let command_state = Arc::clone(&state);
    let command_driver = tokio::spawn(async move {
        while let Some(command) = cmd_rx.recv().await {
            if !handle_command(&command_state, command).await {
                break;
            }
        }
    });
    (state, command_driver)
}

/// Insert a peer with no WebRTC session and a chosen `last_recv_at`,
/// so a test can exercise the staleness predicate without standing up
/// a real transport.
#[cfg(test)]
pub(crate) fn insert_session_less_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    last_recv_at: Option<Instant>,
) {
    let peer = Arc::new(PeerConnection::new(device_id.to_string(), None));
    peer.state.write().last_recv_at = last_recv_at;
    install_peer(&state.peers, peer);
}

// Both admitted-peer helpers serve the LegacyV1 routing control, which now
// takes its native link fixture from `endpoint_auth::native_link`. They
// therefore need both features, so a `legacy-v1`-only build does not carry an
// unreachable helper.
#[cfg(all(test, feature = "legacy-v1", feature = "transport-lab"))]
pub(crate) fn insert_admitted_legacy_test_peer(
    state: &Arc<NetworkState>,
    device_id: &str,
    worker: Arc<crate::transport::WebRtcConnectorWorker>,
    auth_task: Arc<crate::endpoint_auth::EndpointAuthTask>,
) {
    let peer = insert_legacy_test_peer_pending_auth(state, device_id, worker, auth_task);
    // Arc 04: policy state alone no longer admits application traffic — every
    // application, reliable and real-time gate additionally requires a live
    // authenticated channel. A fixture that claims to be *admitted* must carry
    // one, or every relayed frame it sends or receives is correctly refused.
    peer.install_authenticated_channel_for_test();
}

/// Test-only: an installed peer with a live connector and endpoint-auth task,
/// approved by legacy policy but holding **no** authenticated channel.
///
/// This is the pre-promotion state, and it is deliberately separate from
/// `insert_admitted_legacy_test_peer` — named in plain code rather than as an
/// intra-doc link, because that helper additionally needs `legacy-v1` while
/// this one is reachable from a `transport-lab`-only build. Controls that must
/// observe a promotion succeed or fail have to start without a capability, or
/// a pre-installed one would mask the very outcome under test.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn insert_legacy_test_peer_pending_auth(
    state: &Arc<NetworkState>,
    device_id: &str,
    worker: Arc<crate::transport::WebRtcConnectorWorker>,
    auth_task: Arc<crate::endpoint_auth::EndpointAuthTask>,
) -> Arc<PeerConnection> {
    let peer = Arc::new(PeerConnection::new(device_id.to_string(), Some(worker)));
    assert!(peer.install_endpoint_auth(auth_task));
    {
        let mut data = peer.state.write();
        data.authenticated = true;
        data.status = PeerStatus::Active;
        data.data_channel_open = true;
    }
    install_peer(&state.peers, Arc::clone(&peer));
    peer
}

/// Test-only: the exact current owner token for an installed peer.
///
/// These helpers exist so the basal native endpoint-auth controls in
/// `endpoint_auth::native_link` can bind exact-current peer state without the
/// registry field being widened out of `engine`. Each one resolves through the
/// owner token, so a control cannot accidentally observe a superseded registry
/// entry.
///
/// There is deliberately no contribution seeder beside them. Both endpoint
/// contributions belong to the Endpoint Auth Task, which draws its own and
/// binds exactly one peer value, so a control drives `accept_peer_hello` rather
/// than writing a pair into peer state that the task would not agree with.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn legacy_test_owner(
    state: &Arc<NetworkState>,
    device_id: &str,
) -> Option<state::PeerOwnerToken> {
    state.peers.owner(device_id)
}

/// Test-only: whether the exact current peer holds a live authenticated
/// channel. A retired or superseded entry answers `false`.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn legacy_test_has_authenticated_channel(
    state: &Arc<NetworkState>,
    owner: &state::PeerOwnerToken,
) -> bool {
    state
        .peers
        .get_if_current(owner)
        .is_some_and(|peer| peer.has_authenticated_channel())
}

#[cfg(all(test, feature = "legacy-v1", feature = "transport-lab"))]
pub(crate) fn spawn_admitted_legacy_test_pump(
    state: Arc<NetworkState>,
    device_id: String,
    worker: Arc<crate::transport::WebRtcConnectorWorker>,
    mut events: crate::transport::webrtc::WebRtcConnectorEventReceiver,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let Some(event) = worker.accept_event(event) {
                let (event, _callback_resources) = event.into_parts();
                if let TransportEvent::Message(bytes) = event {
                    handle_inbound_frame(&state, &device_id, bytes).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{PreAuthResourceFamily, ResourceFamilyReport, ResourceUse};
    use std::time::{Duration, Instant};

    fn arc03_candidate_fixture() -> crate::transport::LocalIceCandidate {
        crate::transport::LocalIceCandidate {
            candidate: "candidate:arc03 1 udp host".to_string(),
            sdp_mid: Some("data".to_string()),
            sdp_mline_index: None,
            username_fragment: Some("arc03-fragment".to_string()),
        }
    }

    fn pre_auth_report(
        state: &NetworkState,
        family: PreAuthResourceFamily,
    ) -> ResourceFamilyReport<PreAuthResourceFamily> {
        state
            .resource_report()
            .pre_authentication
            .iter()
            .find(|report| report.family == family)
            .copied()
            .expect("pre-authentication family is present")
    }

    #[tokio::test]
    #[ignore = "opens a local WebRTC object; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_shutdown_retires_connector_while_external_peer_arc_survives() {
        let state = build_test_state("arc03-shutdown-external-peer");
        let device_id = "arc03-shutdown-peer";
        let (worker, mut events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("test connector opens");
        let worker = Arc::new(worker);
        let transport = pre_auth_report(&state, PreAuthResourceFamily::TransportObject);
        let callbacks = pre_auth_report(&state, PreAuthResourceFamily::Callback);
        let tasks = pre_auth_report(&state, PreAuthResourceFamily::Task);
        assert_eq!(transport.active.items(), 1, "one connector worker");
        assert_eq!(
            callbacks.active.items(),
            5,
            "five RTCPeerConnection callbacks"
        );
        println!(
            "arc03_connector_observation transport_items={} callback_items={} task_items={} task_count={} transport_inexact={} callback_inexact={} task_inexact={}",
            transport.active.items(),
            callbacks.active.items(),
            tasks.active.items(),
            tasks.active.tasks(),
            transport.measurement_inexact,
            callbacks.measurement_inexact,
            tasks.measurement_inexact,
        );
        assert_eq!(
            worker
                .add_remote_candidate(arc03_candidate_fixture())
                .await
                .expect("candidate enters the connector queue"),
            RemoteCandidateDisposition::QueuedUntilRemoteDescription
        );
        let retained = Arc::new(PeerConnection::new(
            device_id.to_string(),
            Some(Arc::clone(&worker)),
        ));
        install_peer(&state.peers, Arc::clone(&retained));
        assert_ne!(
            pre_auth_report(&state, PreAuthResourceFamily::CandidateObject).active,
            ResourceUse::ZERO
        );

        state.shutdown().await;

        assert!(
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .expect("retirement wakes the connector event receiver")
                .is_none(),
            "a retired connector cannot forward later callbacks"
        );
        assert_eq!(
            pre_auth_report(&state, PreAuthResourceFamily::CandidateObject).active,
            ResourceUse::ZERO
        );
        assert!(state.peers.is_empty());
        assert!(worker
            .add_remote_candidate(arc03_candidate_fixture())
            .await
            .is_err());
        assert_eq!(retained.device_id, device_id);
    }

    #[tokio::test]
    #[ignore = "opens a local WebRTC object; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_offerer_observes_data_channel_handlers() {
        let state = build_test_state("arc03-offerer-observation");
        let (worker, _events) = state
            .transport
            .open_connector_peer(
                Role::Offerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("test connector opens");
        let transport = pre_auth_report(&state, PreAuthResourceFamily::TransportObject);
        let callbacks = pre_auth_report(&state, PreAuthResourceFamily::Callback);
        let tasks = pre_auth_report(&state, PreAuthResourceFamily::Task);

        assert_eq!(transport.active.items(), 1, "one connector worker");
        assert_eq!(
            callbacks.active.items(),
            9,
            "five peer callbacks plus four data-channel callbacks"
        );
        assert_eq!(
            tasks.active.items(),
            0,
            "data-only construction creates no sender-drain tasks"
        );
        println!(
            "arc03_offerer_observation transport_items={} callback_items={} task_items={} task_count={} transport_inexact={} callback_inexact={} task_inexact={}",
            transport.active.items(),
            callbacks.active.items(),
            tasks.active.items(),
            tasks.active.tasks(),
            transport.measurement_inexact,
            callbacks.measurement_inexact,
            tasks.measurement_inexact,
        );
        worker.retire();
    }

    #[tokio::test]
    #[ignore = "opens local WebRTC objects; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_stale_transport_event_cannot_mutate_replacement_worker() {
        let state = build_test_state("arc03-stale-transport-event");
        let device_id = "arc03-stale-event-peer";
        let (first, _first_events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("first connector opens");
        let first = Arc::new(first);
        let stale_event = first.stamp_event_for_test(TransportEvent::DataChannelOpen);
        install_peer(
            &state.peers,
            Arc::new(PeerConnection::new(
                device_id.to_string(),
                Some(Arc::clone(&first)),
            )),
        );

        let (replacement, _replacement_events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("replacement connector opens");
        let replacement = Arc::new(replacement);
        install_peer(
            &state.peers,
            Arc::new(PeerConnection::new(
                device_id.to_string(),
                Some(Arc::clone(&replacement)),
            )),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if first.connection_state() == RTCPeerConnectionState::Closed {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement closes the displaced native peer");

        handle_transport_event(&state, device_id.to_string(), stale_event).await;

        let current = state.peers.get(device_id).expect("replacement remains");
        {
            let data = current.state.read();
            assert!(!data.data_channel_open);
            assert!(data.handshake_started_at.is_none());
        }
        let replacement_is_current = {
            let session = current.session.lock();
            Arc::ptr_eq(session.as_ref().expect("replacement session"), &replacement)
        };
        assert!(replacement_is_current);
        drop(current);
        state.shutdown().await;
    }

    fn stale_instant() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_millis(scheduler::STALE_INBOUND_MS + 5_000))
            .expect("test host monotonic clock has enough headroom")
    }

    fn pre_connect_timeout_instant() -> Instant {
        Instant::now()
            .checked_sub(Duration::from_millis(
                scheduler::DATA_CHANNEL_OPEN_TIMEOUT_MS + 5_000,
            ))
            .expect("test host monotonic clock has enough headroom")
    }

    #[tokio::test]
    async fn silent_network_records_sighted_without_opening_a_session() {
        // The load-bearing Silent behaviour: a peer announcing on signaling
        // must be surfaced as discovered (Sighted, visible in `peers()`) but
        // must NOT cause the engine to open a WebRTC session on its own.
        let state = build_test_state("silent-no-autodial");
        state.governance_state.write().kind = crate::network_state::NetworkKind::Silent;
        assert!(state.is_silent());

        let peer = "peerpubkeyzzz-customer";
        handle_signaling_inbound(
            &state,
            SignalingInbound::PeerAnnounced {
                device_id: peer.to_string(),
            },
        )
        .await;

        let entry = state
            .peers
            .get(peer)
            .expect("a Silent network must still record the announced peer as discovered");
        assert!(
            entry.session.lock().is_none(),
            "Silent must not open a WebRTC session just because a peer announced"
        );
        assert_eq!(entry.state.read().status, connection::PeerStatus::Sighted);
        assert!(
            !entry.state.read().authenticated,
            "no handshake should have run"
        );

        // A re-announce is idempotent — still no session, still Sighted.
        drop(entry);
        handle_signaling_inbound(
            &state,
            SignalingInbound::PeerAnnounced {
                device_id: peer.to_string(),
            },
        )
        .await;
        assert!(state.peers.get(peer).unwrap().session.lock().is_none());
    }

    #[tokio::test]
    async fn connect_peer_upgrades_a_silent_sighted_placeholder_to_a_session() {
        // The explicit dial: `connect_peer` opens the WebRTC session the Silent
        // announce path deliberately skipped, upgrading the discovery-only
        // placeholder in place (rather than short-circuiting on the stub).
        let state = build_test_state("silent-connect-peer");
        state.governance_state.write().kind = crate::network_state::NetworkKind::Silent;

        let peer = "peerpubkeyzzz-tech";
        // Discover first (session-less placeholder), as an announce would.
        note_sighted_without_dialing(&state, peer, "silent network");
        assert!(state.peers.get(peer).unwrap().session.lock().is_none());

        // Deliberate dial opens a real session on the same entry.
        connect_peer(&state, peer, false, None).await;
        assert!(
            state.peers.get(peer).unwrap().session.lock().is_some(),
            "connect_peer must open a session, upgrading the Sighted placeholder"
        );
    }

    #[tokio::test]
    async fn silent_network_suppresses_roster_gossip_predicate() {
        // The gossip gate: `broadcast_roster_summary` / `on_roster_request`
        // early-return on `!gossip_roster_enabled()`, which is exactly
        // "is this network Silent?".
        let state = build_test_state("silent-gossip-gate");
        assert!(
            state.gossip_roster_enabled(),
            "a non-silent network gossips its roster as before"
        );
        state.governance_state.write().kind = crate::network_state::NetworkKind::Silent;
        assert!(
            !state.gossip_roster_enabled(),
            "a silent network must suppress roster gossip"
        );
    }

    #[test]
    fn frame_cap_rejects_oversize_inbound_frames() {
        assert!(frame_within_cap(0));
        assert!(frame_within_cap(MAX_ENDPOINT_FRAME_BYTES));
        assert!(!frame_within_cap(MAX_ENDPOINT_FRAME_BYTES + 1));
        // The ceiling is generous (far above any real control frame) but
        // bounded — a regression that zeroed or ballooned it would trip here.
        assert!((1 << 20..=1 << 26).contains(&MAX_ENDPOINT_FRAME_BYTES));
    }

    #[tokio::test]
    async fn handle_inbound_frame_drops_an_oversize_frame() {
        // MOM-04: a giant frame short-circuits before the deserializer — no
        // parse attempt, no panic, and the peer's frame counter doesn't move.
        let state = build_test_state("oversize-frame");
        insert_session_less_peer(&state, "flooder", None);
        let huge = Bytes::from(vec![b' '; MAX_ENDPOINT_FRAME_BYTES + 1]);
        handle_inbound_frame(&state, "flooder", huge).await;
        let peer = state.peers.get("flooder").expect("peer present");
        assert_eq!(
            peer.state.read().diag.frames_in,
            0,
            "an oversize frame must be dropped before it counts as received"
        );
    }

    // ---- admission gate: pre-authentication application dispatch ----
    //
    // The bug these guard: an endpoint with a live DTLS data channel but an
    // unfinished ed25519 handshake + approval could drive application, RPC,
    // reliable, governance, and media handlers. The gate admits only handshake
    // protocol frames until the peer is authenticated + Active/Shelved.

    fn frame_bytes(msg: &MeshMessage) -> Bytes {
        Bytes::from(serde_json::to_vec(msg).expect("serialize test frame"))
    }

    fn set_admission(state: &NetworkState, peer: &str, authenticated: bool, status: PeerStatus) {
        let p = state.peers.get(peer).expect("peer present");
        let mut d = p.state.write();
        d.authenticated = authenticated;
        d.status = status;
    }

    #[test]
    fn is_admitted_only_authenticated_active_or_shelved() {
        use PeerStatus::*;
        for status in [
            Sighted,
            Handshaking,
            PendingApproval,
            Reconnecting,
            Offline,
            Error,
        ] {
            let d = connection::PeerStateData {
                authenticated: true,
                status,
                ..Default::default()
            };
            assert!(!d.is_admitted(), "{status:?} is not an admitted status");
        }
        for status in [Active, Shelved] {
            let ok = connection::PeerStateData {
                authenticated: true,
                status,
                ..Default::default()
            };
            assert!(
                ok.is_admitted(),
                "authenticated {status:?} must be admitted"
            );
            let no_auth = connection::PeerStateData {
                status,
                ..Default::default()
            };
            assert!(
                !no_auth.is_admitted(),
                "{status:?} without authentication is never admitted"
            );
        }
    }

    #[test]
    fn v4_arc03_relay_selection_is_not_authentication_or_session_admission() {
        let relay_pair = crate::transport::SelectedCandidatePair {
            local: crate::transport::IceCandidateKind::Relay,
            remote: crate::transport::IceCandidateKind::Relay,
        };
        let unauthenticated = connection::PeerStateData {
            authenticated: false,
            status: PeerStatus::Active,
            selected_pair: Some(relay_pair),
            ..Default::default()
        };
        assert!(!unauthenticated.is_admitted());

        let pending = connection::PeerStateData {
            authenticated: true,
            status: PeerStatus::PendingApproval,
            selected_pair: Some(relay_pair),
            ..Default::default()
        };
        assert!(!pending.is_admitted());

        // Asserted through the fence, which is where the real-time gate now
        // lives. Reading `realtime_flow_ports` directly would answer `None`
        // merely because this fixture has no connector, and would stop saying
        // anything about admission.
        let peer = PeerConnection::new("relay-negative".to_string(), None);
        *peer.state.write() = pending;
        let state = build_test_state("arc03-relay-negative");
        install_peer(&state.peers, Arc::new(peer));
        let owner = state
            .peers
            .owner("relay-negative")
            .expect("relay-negative peer is installed");
        assert!(
            state
                .peers
                .with_admitted_current(&owner, |admitted| admitted.realtime_operation())
                .is_none(),
            "a relay-selected but unadmitted peer yields no real-time operation"
        );
    }

    #[tokio::test]
    async fn v4_arc03_outbound_application_send_requires_current_session_admission() {
        let state = build_test_state("arc03-outbound-admission");
        insert_session_less_peer(&state, "pending-peer", None);
        set_admission(&state, "pending-peer", true, PeerStatus::PendingApproval);
        {
            // Transport readiness is made explicit, so the refusal below cannot
            // be explained by a link that was never up: the data channel is
            // open and the peer advertises the acked contract, which is
            // everything `reliable::link_ready` asks for.
            let peer = state.peers.get("pending-peer").expect("peer present");
            let mut data = peer.state.write();
            data.data_channel_open = true;
            data.features = vec![crate::protocol::features::Feature::RELIABLE_CHANNELS.to_string()];
        }
        assert_eq!(
            reliable::link_ready_for_test(&state, "pending-peer"),
            Some(true),
            "non-vacuity: the transport link is ready and speaks the acked contract"
        );

        let error = send_channel_frame(
            &state,
            "pending-peer",
            "negative-control",
            serde_json::json!("must-not-send"),
        )
        .await
        .expect_err("pending peer cannot receive outbound application data");

        // The exact refusal, not merely some error: a ready link that fell
        // through the fence would fail later and differently (no session, or a
        // transport write error), and asserting only `is_err` would accept that.
        assert!(
            error
                .to_string()
                .contains("not admitted for application traffic"),
            "the send must be refused by the admission fence, got: {error}"
        );
        assert_eq!(state.traffic.snapshot().app_tx.frames, 0);
    }

    // ---- Arc 04B-3b: the inbound real-time promotion fence ----
    //
    // Every control below drives the exact production functions the transport
    // event arms delegate to (`dispatch_admitted_video` /
    // `dispatch_admitted_audio`), so what is under test is the shipped gate
    // rather than a restatement of it, and a subscriber count is read from the
    // real broadcast the embedder subscribes to.

    /// Which real gate one parameterized control drives.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MediaUnitKind {
        Video,
        Audio,
    }

    impl MediaUnitKind {
        /// Both real gates. Controls iterate this rather than testing video and
        /// trusting audio to match: they are separate call sites, and a gate
        /// dropped from one of them is exactly the regression at issue.
        const BOTH: [MediaUnitKind; 2] = [MediaUnitKind::Video, MediaUnitKind::Audio];

        fn lane(self) -> &'static str {
            match self {
                Self::Video => "video",
                Self::Audio => "audio",
            }
        }
    }

    /// One installed peer, the exact owner token resolved for it, and a live
    /// subscriber on both real-time lanes.
    ///
    /// Both lanes are always subscribed, so "zero units delivered" means zero
    /// on either lane rather than zero on the one the control happened to look
    /// at, and a unit that leaked onto the wrong lane would still be counted.
    struct MediaGate {
        state: Arc<NetworkState>,
        device_id: String,
        owner: state::PeerOwnerToken,
        video: tokio::sync::broadcast::Receiver<state::InboundVideoSample>,
        audio: tokio::sync::broadcast::Receiver<state::InboundAudioSample>,
    }

    impl MediaGate {
        /// A session-less peer in its genuine pre-authentication state: no
        /// authenticated channel, and no retained policy either.
        fn pre_auth(suffix: &str) -> Self {
            let state = build_test_state(suffix);
            let device_id = "arc04c-media-peer".to_string();
            insert_session_less_peer(&state, &device_id, None);
            Self::over(state, device_id)
        }

        /// The same fixture over an already-installed peer, for the controls
        /// that need a real connector on it.
        fn over(state: Arc<NetworkState>, device_id: String) -> Self {
            let owner = state
                .peers
                .owner(&device_id)
                .expect("the media peer is installed");
            let video = state.video_subscribers.subscribe();
            let audio = state.audio_subscribers.subscribe();
            Self {
                state,
                device_id,
                owner,
                video,
                audio,
            }
        }

        /// The exact current peer under this device id.
        fn peer(&self) -> Arc<PeerConnection> {
            self.state
                .peers
                .get(&self.device_id)
                .expect("the media peer is installed")
        }

        /// The exact current owner token, which is *not* `self.owner` once a
        /// replacement has been installed.
        fn current_owner(&self) -> state::PeerOwnerToken {
            self.state
                .peers
                .owner(&self.device_id)
                .expect("the media peer is installed")
        }

        /// Grant the retained legacy policy conjunct only.
        fn grant_legacy_policy(&self) {
            set_admission(&self.state, &self.device_id, true, PeerStatus::Active);
        }

        /// Install a real authenticated-channel capability on the exact current
        /// peer. The capability is genuine; only connector provenance is
        /// bypassed, which the transport controls prove separately.
        fn grant_capability(&self) {
            self.peer().install_authenticated_channel_for_test();
        }

        /// Present one unit to the production gate for `kind`, as the exact
        /// `owner` given — which a replacement control deliberately makes stale.
        fn drive(&self, kind: MediaUnitKind, owner: &state::PeerOwnerToken, marker: u32) {
            let data = Bytes::from_static(b"arc04c-unit");
            match kind {
                MediaUnitKind::Video => dispatch_admitted_video(
                    &self.state,
                    owner,
                    crate::transport::webrtc::VideoSample::for_test(marker, true, 0, data),
                ),
                MediaUnitKind::Audio => dispatch_admitted_audio(
                    &self.state,
                    owner,
                    crate::transport::webrtc::AudioSample::for_test(marker, 0, data),
                ),
            }
        }

        /// Everything the subscribers have been handed since the last drain, as
        /// `(lane, sending peer, marker)`. The marker rides `rtp_timestamp`, so
        /// a delivered unit is attributable to the exact call that produced it.
        fn drained(&mut self) -> Vec<(&'static str, String, u32)> {
            let mut delivered = Vec::new();
            while let Ok(unit) = self.video.try_recv() {
                delivered.push(("video", unit.from, unit.sample.rtp_timestamp));
            }
            while let Ok(unit) = self.audio.try_recv() {
                delivered.push(("audio", unit.from, unit.sample.rtp_timestamp));
            }
            delivered
        }

        /// The exact current peer's refused-unit count.
        fn refused(&self) -> u64 {
            self.peer().state.read().admission_rejected
        }
    }

    #[tokio::test]
    async fn v4_arc04c_inbound_media_without_capability_delivers_zero_units() {
        for kind in MediaUnitKind::BOTH {
            let lane = kind.lane();
            let mut gate = MediaGate::pre_auth(&format!("arc04c-media-pre-auth-{lane}"));
            // Premise: genuinely pre-authentication. Neither conjunct holds, so
            // this is the state a native track can produce units in before any
            // endpoint proof has run — the case the old comment left to the
            // embedder's route matching.
            assert!(
                !gate.peer().has_authenticated_channel(),
                "{lane}: no authenticated channel"
            );
            assert!(
                !gate.peer().state.read().is_admitted(),
                "{lane}: no retained policy either"
            );

            gate.drive(kind, &gate.owner, 11);

            assert!(
                gate.drained().is_empty(),
                "{lane}: a pre-authentication unit must reach no subscriber"
            );
            // The refusal is counted at the boundary, so a passing negative
            // proves the stimulus arrived rather than never being produced.
            assert_eq!(gate.refused(), 1, "{lane}: the refusal is recorded once");
        }
    }

    #[tokio::test]
    async fn v4_arc04c_legacy_policy_alone_delivers_zero_media_units() {
        for kind in MediaUnitKind::BOTH {
            let lane = kind.lane();
            let mut gate = MediaGate::pre_auth(&format!("arc04c-media-policy-only-{lane}"));
            gate.grant_legacy_policy();
            // Differs from the control above in exactly one conjunct: legacy
            // policy now considers this peer fully admitted. A delivery here
            // would be attributable to the bool, which is the regression this
            // exists to catch.
            assert!(
                gate.peer().state.read().is_admitted(),
                "{lane}: non-vacuity — legacy policy really does admit this peer"
            );
            assert!(
                !gate.peer().has_authenticated_channel(),
                "{lane}: and still no authenticated channel"
            );

            gate.drive(kind, &gate.owner, 21);

            assert!(
                gate.drained().is_empty(),
                "{lane}: the retained policy bool alone must deliver nothing"
            );
            assert_eq!(gate.refused(), 1, "{lane}: the refusal is recorded once");
        }
    }

    #[tokio::test]
    async fn v4_arc04c_capability_plus_policy_delivers_exactly_one_media_unit() {
        for kind in MediaUnitKind::BOTH {
            let lane = kind.lane();
            let mut gate = MediaGate::pre_auth(&format!("arc04c-media-admitted-{lane}"));
            gate.grant_legacy_policy();
            // The one addition over the refusing fixture: the exact current
            // peer's authenticated channel. Nothing else about the fixture
            // moves, so delivery here is attributable to the capability.
            gate.grant_capability();
            assert!(
                gate.peer().has_authenticated_channel(),
                "{lane}: capability"
            );
            assert!(gate.peer().state.read().is_admitted(), "{lane}: policy");

            gate.drive(kind, &gate.owner, 31);

            let delivered = gate.drained();
            assert_eq!(
                delivered,
                vec![(lane, gate.device_id.clone(), 31)],
                "{lane}: the conjunction permits exactly one unit, attributed to the exact peer"
            );
            assert_eq!(
                gate.refused(),
                0,
                "{lane}: an admitted unit is not also counted as refused"
            );
        }
    }

    #[tokio::test]
    async fn v4_arc04c_capability_without_legacy_policy_delivers_zero_media_units() {
        for kind in MediaUnitKind::BOTH {
            let lane = kind.lane();
            let mut gate = MediaGate::pre_auth(&format!("arc04c-media-capability-only-{lane}"));
            // The fourth cell of the truth table, and the mirror of the
            // policy-only control: the Arc 04 conjunction is a conjunction in
            // both directions, so an authenticated channel whose peer has not
            // reached mutual approval delivers nothing either.
            gate.grant_capability();
            assert!(
                gate.peer().has_authenticated_channel(),
                "{lane}: non-vacuity — the authenticated channel really is installed"
            );
            assert!(
                !gate.peer().state.read().is_admitted(),
                "{lane}: and retained policy does not admit this peer"
            );

            gate.drive(kind, &gate.owner, 71);

            assert!(
                gate.drained().is_empty(),
                "{lane}: a capability without retained policy must deliver nothing"
            );
            assert_eq!(gate.refused(), 1, "{lane}: the refusal is recorded once");
        }
    }

    #[tokio::test]
    #[ignore = "opens local WebRTC objects; run explicitly in the isolated WSL harness"]
    async fn v4_arc04c_connector_replacement_blocks_later_media_from_the_old_incarnation() {
        let state = build_test_state("arc04c-media-connector-replacement");
        let device_id = "arc04c-replacement-peer".to_string();
        let (first, _first_events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("first connector opens");
        let first = Arc::new(first);
        let retired_peer = Arc::new(PeerConnection::new(
            device_id.clone(),
            Some(Arc::clone(&first)),
        ));
        install_peer(&state.peers, Arc::clone(&retired_peer));
        let mut gate = MediaGate::over(Arc::clone(&state), device_id.clone());
        gate.grant_legacy_policy();
        gate.grant_capability();
        let retired_owner = gate.owner.clone();

        // Baseline on this exact incarnation, before anything is replaced: the
        // fixture genuinely does deliver, so the refusals below are not an
        // artefact of a path that never worked.
        gate.drive(MediaUnitKind::Video, &retired_owner, 41);
        assert_eq!(
            gate.drained(),
            vec![("video", device_id.clone(), 41u32)],
            "the live incarnation delivers while it is current"
        );

        // The engine fixture grants exactly two simultaneous connectors per
        // Mesh scope, and this control deliberately saturates 2/2: replacement
        // is only meaningful with both incarnations alive at once, so the first
        // is still open here. A third open on this state would be refused by
        // the grant, which is the fixture's envelope and not a bug to route
        // around — no production grant is changed for this control.
        let (replacement_worker, _replacement_events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("replacement connector opens");
        let replacement_worker = Arc::new(replacement_worker);
        assert!(
            !Arc::ptr_eq(&first, &replacement_worker),
            "the replacement must be a genuinely distinct connector incarnation"
        );
        install_peer(
            &state.peers,
            Arc::new(PeerConnection::new(
                device_id.clone(),
                Some(Arc::clone(&replacement_worker)),
            )),
        );
        // The replacement is admitted in its own right, so a unit that escaped
        // through it would be a real escape rather than a refusal for some
        // unrelated reason.
        gate.grant_legacy_policy();
        gate.grant_capability();
        let replacement_owner = gate.current_owner();
        assert!(
            state.peers.get_if_current(&retired_owner).is_none(),
            "the retired incarnation is no longer the installed owner"
        );
        assert!(
            state.peers.get_if_current(&replacement_owner).is_some(),
            "the replacement is"
        );
        assert!(
            !Arc::ptr_eq(&retired_peer, &gate.peer()),
            "the two installations are distinct peer objects"
        );
        assert!(
            !retired_peer.has_authenticated_channel(),
            "replacement invalidated the retired incarnation's capability"
        );

        // Later units from the retired incarnation, on both lanes.
        gate.drive(MediaUnitKind::Video, &retired_owner, 42);
        gate.drive(MediaUnitKind::Audio, &retired_owner, 43);

        assert!(
            gate.drained().is_empty(),
            "no unit from the retired incarnation may dispatch"
        );
        assert_eq!(
            gate.refused(),
            0,
            "and the replacement's own counters are not mutated by it"
        );
        assert_eq!(
            retired_peer.state.read().admission_rejected,
            0,
            "the stale owner never reached either arm"
        );

        // Same-fixture positive baseline on the far side of the replacement.
        gate.drive(MediaUnitKind::Audio, &replacement_owner, 44);
        assert_eq!(
            gate.drained(),
            vec![("audio", device_id.clone(), 44u32)],
            "the replacement itself still delivers, so the refusal above is the fence"
        );

        drop(gate);
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_arc04c_pre_auth_unit_is_not_released_by_later_authentication() {
        for kind in MediaUnitKind::BOTH {
            let lane = kind.lane();
            let mut gate = MediaGate::pre_auth(&format!("arc04c-media-late-auth-{lane}"));

            // One genuinely pre-authentication unit, refused.
            gate.drive(kind, &gate.owner, 51);
            assert!(
                gate.drained().is_empty(),
                "{lane}: the pre-authentication unit is refused"
            );
            assert_eq!(gate.refused(), 1, "{lane}: and the refusal is recorded");

            // The same peer authenticates afterwards.
            gate.grant_legacy_policy();
            gate.grant_capability();

            gate.drive(kind, &gate.owner, 52);
            let delivered = gate.drained();
            assert_eq!(
                delivered,
                vec![(lane, gate.device_id.clone(), 52)],
                "{lane}: exactly the new unit is delivered, exactly once"
            );
            // The refused unit was dropped, not parked: promotion releases
            // nothing, now or on any later drain.
            assert!(
                gate.drained().is_empty(),
                "{lane}: the pre-authentication unit never replays"
            );
            assert_eq!(
                gate.refused(),
                1,
                "{lane}: promotion does not retroactively re-run the refused unit"
            );
        }
    }

    #[tokio::test]
    async fn v4_arc04c_replacement_before_admission_commit_delivers_nothing_through_the_replacement(
    ) {
        for kind in MediaUnitKind::BOTH {
            let lane = kind.lane();
            let mut gate = MediaGate::pre_auth(&format!("arc04c-media-commit-race-{lane}"));
            gate.grant_legacy_policy();
            gate.grant_capability();

            // The owner resolves successfully first — this is exactly the value
            // an event path holds on its way into the fence. No hook is needed
            // to open the window: resolving here and committing after the
            // replacement *is* the race, deterministically ordered.
            let stale = gate.owner.clone();
            assert!(
                gate.state.peers.get_if_current(&stale).is_some(),
                "{lane}: the owner resolves before the replacement"
            );
            let stale_peer = gate.peer();

            // A different installation under the same device id, admitted in
            // its own right.
            install_peer(
                &gate.state.peers,
                Arc::new(PeerConnection::new(gate.device_id.clone(), None)),
            );
            gate.grant_legacy_policy();
            gate.grant_capability();
            let replacement_owner = gate.current_owner();
            assert!(
                gate.state.peers.get_if_current(&stale).is_none(),
                "{lane}: the resolved owner is no longer installed"
            );
            assert!(
                !Arc::ptr_eq(&stale_peer, &gate.peer()),
                "{lane}: the replacement is a distinct installation"
            );

            gate.drive(kind, &stale, 61);

            assert!(
                gate.drained().is_empty(),
                "{lane}: the pre-replacement owner delivers nothing through the replacement"
            );
            assert_eq!(
                gate.refused(),
                0,
                "{lane}: and the refusal arm does not mutate the replacement either"
            );
            assert_eq!(
                stale_peer.state.read().admission_rejected,
                0,
                "{lane}: neither arm ran at all"
            );

            // Same-fixture positive: the replacement does deliver, so the
            // silence above is the owner fence and not a dead fixture.
            gate.drive(kind, &replacement_owner, 62);
            let delivered = gate.drained();
            assert_eq!(
                delivered,
                vec![(lane, gate.device_id.clone(), 62)],
                "{lane}: the replacement itself is admitted and delivers"
            );
        }
    }

    /// The outbound twin of the replacement controls, over a real link.
    ///
    /// A witness is minted under the fence, the peer is then replaced by a
    /// different installation on a different connector incarnation, and only
    /// then is the witness consumed. The send must write through the connector
    /// it captured and record against the peer it captured — never through or
    /// onto the replacement — which is what makes `AdmittedApplicationOperation`
    /// an authority rather than a boolean read that has since gone stale.
    ///
    /// This needs a genuinely connected connector: a positive baseline that
    /// could not have sent anything anyway would make the negative unfalsifiable,
    /// so the fixture is the live two-connector link, and the control is gated
    /// on `transport-lab` with it.
    /// 04B-3. Renegotiation completion must land on the installation the claim
    /// was made for, never on whatever installation holds the device id by the
    /// time the offer settles.
    ///
    /// This drives the real claim path — registry fence, `realtime_operation`,
    /// `into_renegotiation` — and completes through the operation's own
    /// `complete`, which takes no owner argument. A regression to
    /// `peers.owner(device_id)` after the claim would have to abandon that API,
    /// and the replacement assertions here are what it would break. Needs a
    /// live connector because `realtime_flow_ports` requires a real worker, so
    /// it is gated and ignored like its `transport-lab` neighbours.
    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    #[ignore = "opens a native WebRTC link; run explicitly in the isolated WSL harness"]
    async fn v4_arc04b_renegotiation_completion_follows_the_captured_owner() {
        // Legacy-media states on both sides: realtime_enabled() gates the whole
        // real-time witness path, and a data-only profile can never satisfy it.
        let state = build_test_state_with_legacy_media("arc04b-reneg-a");
        let peer_state = build_test_state_with_legacy_media("arc04b-reneg-b");
        let device_id = peer_state.identity.public_id().to_string();
        // Two distinct live links, held for the whole test. The replacement has
        // to own a *different* connector and endpoint-auth task: reusing the
        // first pair would mean claiming against a worker the replacement
        // itself retired, which is not what a real replacement looks like. Two
        // connectors per side is exactly the Mesh grant.
        let first_link = crate::endpoint_auth::native_link::connect(&state, &peer_state).await;
        let second_link = crate::endpoint_auth::native_link::connect(&state, &peer_state).await;

        // The exact worker/auth-task pair must travel together:
        // `install_legacy_realtime_flow` needs `session.zip(endpoint_auth)` and
        // asks the connector `owns_endpoint_auth(task)`, so a peer carrying a
        // session but no task can never mint a real-time witness.
        let install_live_peer =
            |worker: Arc<crate::transport::WebRtcConnectorWorker>,
             auth: Arc<crate::endpoint_auth::EndpointAuthTask>| {
                let peer = insert_legacy_test_peer_pending_auth(&state, &device_id, worker, auth);
                peer.install_authenticated_channel_for_test();
                peer
            };

        // Claim through the exact production sequence the tick uses.
        let claim = |owner: &state::PeerOwnerToken| {
            state
                .peers
                .with_admitted_current(owner, |admitted| {
                    admitted.install_legacy_realtime_flow();
                    admitted.realtime_operation()
                })
                .flatten()
                .and_then(|realtime| realtime.into_renegotiation())
        };

        let first_peer = install_live_peer(
            Arc::clone(&first_link.left),
            Arc::clone(&first_link.left_auth),
        );
        let first_owner = state
            .peers
            .owner(&device_id)
            .expect("the first installation is current");

        // POSITIVE BASELINE. Without it the negative could pass merely because
        // completion never writes anything at all.
        let baseline = claim(&first_owner).expect("the live connector claims a renegotiation");
        assert!(
            first_peer.state.read().media_reneg_inflight,
            "claiming latches the single-flight guard"
        );
        baseline.complete(&state.peers, Ok(()));
        {
            let data = first_peer.state.read();
            assert!(!data.media_reneg_inflight, "the claimed peer is cleared");
            assert!(
                data.last_offer_sent_at.is_some(),
                "the claimed peer records the offer"
            );
        }

        // Claim again, then replace the installation before completing — the
        // exact window the defect lived in.
        let superseded = claim(&first_owner).expect("the first installation claims again");
        let replacement = install_live_peer(
            Arc::clone(&second_link.left),
            Arc::clone(&second_link.left_auth),
        );
        assert!(
            state.peers.get_if_current(&first_owner).is_none(),
            "non-vacuity: the installations must be distinct, or this proves nothing"
        );
        {
            let mut data = replacement.state.write();
            data.media_reneg_inflight = true;
            data.media_reneg_pending = true;
            data.last_offer_sent_at = None;
        }

        // The superseded operation completes. It must not touch the replacement.
        superseded.complete(&state.peers, Ok(()));
        {
            let data = replacement.state.read();
            assert!(
                data.media_reneg_inflight,
                "a superseded renegotiation must not clear the replacement's in-flight guard"
            );
            assert!(
                data.media_reneg_pending,
                "nor consume the replacement's pending lane change"
            );
            assert!(
                data.last_offer_sent_at.is_none(),
                "nor stamp an offer the replacement never sent"
            );
        }

        // The replacement's own claim still completes, so the no-op above is
        // attribution and not a dead path.
        let replacement_owner = state
            .peers
            .owner(&device_id)
            .expect("the replacement is current");
        let own = claim(&replacement_owner).expect("the replacement claims its own renegotiation");
        own.complete(&state.peers, Ok(()));
        {
            let data = replacement.state.read();
            assert!(!data.media_reneg_inflight);
            assert!(data.last_offer_sent_at.is_some());
        }
    }

    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    #[ignore = "opens a native WebRTC link; run explicitly in the isolated WSL harness"]
    async fn v4_arc04c_send_uses_the_captured_session_and_records_only_the_captured_peer() {
        let state = build_test_state("arc04c-captured-send-a");
        let peer_state = build_test_state("arc04c-captured-send-b");
        let device_id = peer_state.identity.public_id().to_string();
        let link = crate::endpoint_auth::native_link::connect(&state, &peer_state).await;

        let captured_peer = Arc::new(PeerConnection::new(
            device_id.clone(),
            Some(Arc::clone(&link.left)),
        ));
        install_peer(&state.peers, Arc::clone(&captured_peer));
        {
            let mut data = captured_peer.state.write();
            data.authenticated = true;
            data.status = PeerStatus::Active;
            data.data_channel_open = true;
        }
        captured_peer.install_authenticated_channel_for_test();
        let captured_owner = state
            .peers
            .owner(&device_id)
            .expect("the captured peer is installed");
        let timeout = Duration::from_millis(scheduler::PEER_SEND_TIMEOUT_MS);

        // Same-fixture positive baseline: a witness minted under the fence
        // sends through the captured session and records on the captured peer.
        state
            .peers
            .admit_application_operation(&captured_owner)
            .expect("an admitted owner mints a witness")
            .send_frame(Bytes::from_static(b"arc04c-baseline"), timeout)
            .await
            .expect("the captured live session carries the send");
        assert_eq!(
            captured_peer.state.read().diag.frames_out,
            1,
            "the baseline send is recorded against the captured peer"
        );

        // Minted while the captured owner is still current; consumed after it
        // is not.
        let witness = state
            .peers
            .admit_application_operation(&captured_owner)
            .expect("the owner is still current at mint time");

        // Second connector on this state, alongside the live link's left half,
        // so this control also saturates the fixture's 2/2 simultaneous
        // connector grant (the right half belongs to the peer's own scope).
        // Both must be alive at once for the replacement to be real, and no
        // production grant is changed to allow it.
        let (replacement_worker, _replacement_events) = state
            .transport
            .open_connector_peer(
                Role::Offerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("replacement connector opens");
        let replacement_worker = Arc::new(replacement_worker);
        assert!(
            !Arc::ptr_eq(&link.left, &replacement_worker),
            "the replacement is a genuinely distinct connector incarnation"
        );
        let replacement = Arc::new(PeerConnection::new(
            device_id.clone(),
            Some(Arc::clone(&replacement_worker)),
        ));
        install_peer(&state.peers, Arc::clone(&replacement));
        {
            let mut data = replacement.state.write();
            data.authenticated = true;
            data.status = PeerStatus::Active;
            data.data_channel_open = true;
        }
        replacement.install_authenticated_channel_for_test();
        let replacement_owner = state
            .peers
            .owner(&device_id)
            .expect("the replacement is installed");
        assert!(
            state.peers.get_if_current(&captured_owner).is_none(),
            "the captured installation is superseded"
        );
        assert!(
            state.peers.get_if_current(&replacement_owner).is_some(),
            "the replacement is the installed owner"
        );
        assert!(
            !Arc::ptr_eq(&captured_peer, &replacement),
            "the two installations are distinct peer objects"
        );

        assert!(
            witness
                .send_frame(Bytes::from_static(b"arc04c-post-mint"), timeout)
                .await
                .is_err(),
            "the captured connector was retired by the replacement, so the post-mint send fails there rather than being redirected"
        );
        assert_eq!(
            replacement.state.read().diag.frames_out,
            0,
            "no frame is attributed to the replacement"
        );
        assert_eq!(
            replacement.state.read().diag.bytes_out,
            0,
            "and no bytes are either"
        );
        assert_eq!(
            captured_peer.state.read().diag.frames_out,
            1,
            "the failed send records nothing new on the captured peer either"
        );

        state.shutdown().await;
        peer_state.shutdown().await;
        for worker in [&link.left, &link.right, &replacement_worker] {
            let _ = worker.retire_and_close().await;
        }
    }

    /// What the open path must do when the connector cannot state its binding.
    ///
    /// Shared verbatim by all three open-path controls below, so the twins
    /// differ in exactly one value: which component the live connector is armed
    /// to withhold, or — for the positive — that it is never armed at all.
    /// Everything else is the same live link, the same registry installation,
    /// and the same genuine native callback.
    ///
    /// The observations are collected *after* the production arm has run,
    /// through the same reads the engine itself would use, so a control cannot
    /// pass by inspecting something the engine does not maintain.
    #[cfg(feature = "transport-lab")]
    struct OpenPathOutcome {
        handled: bool,
        owner_still_current: bool,
        has_auth_task: bool,
        data_channel_open: bool,
        handshake_started: bool,
        verification_code_sent: bool,
        hellos_sent: u32,
        handshaking: bool,
        has_authenticated_channel: bool,
        connector: DataChannelOpenOwnership,
    }

    /// Drive one real link through the production `DataChannelOpen` arm.
    ///
    /// `withhold` is the only thing the callers vary. The link is genuinely
    /// live — real ICE, real DTLS, real SCTP — and the event handed to the arm
    /// is the connector's own native open callback, not one a fixture stamped,
    /// so the arm is entered exactly as it is in production.
    ///
    /// The connector is armed *after* the channel is proved working and before
    /// the arm runs. That order is what makes the negatives statements about
    /// this boundary: the same connector stated both components a moment
    /// earlier, so the refusal is the withheld component and not an unusable
    /// fixture.
    #[cfg(feature = "transport-lab")]
    async fn drive_open_path(
        suffix_a: &str,
        suffix_b: &str,
        withhold: Option<crate::transport::WithheldBindingComponent>,
    ) -> OpenPathOutcome {
        let state = build_test_state(suffix_a);
        let peer_state = build_test_state(suffix_b);
        let device_id = peer_state.identity.public_id().to_string();
        // Held whole for the entire control. The fixture owns both connectors'
        // event receivers, and dropping either stops that connector's event
        // pump — so the link the assertions describe would stop being the link
        // that was up. Only the open callback is taken out of it.
        let mut link =
            crate::endpoint_auth::native_link::connect_before_engine_open(&state, &peer_state)
                .await;

        // The data channel really is working, not merely reported open: a byte
        // crosses it before anything is arranged. Without this the negatives
        // would also pass on a link that had died, and "fails closed" would be
        // indistinguishable from "never came up".
        link.left
            .send_owned(Bytes::from_static(b"arc04e-open-path"))
            .await
            .expect("the live data channel carries a frame before the open path runs");
        assert!(
            link.left.endpoint_auth_binding().await.is_some(),
            "non-vacuity: this connector states both binding components on this live link"
        );

        // The pre-open registry state the production arm expects: a current
        // peer carrying this exact worker, with no endpoint-auth task and no
        // channel-open milestone. Anything preinstalled here would satisfy the
        // very assertions the negatives make.
        let peer = Arc::new(PeerConnection::new(
            device_id.clone(),
            Some(Arc::clone(&link.left)),
        ));
        install_peer(&state.peers, Arc::clone(&peer));
        let owner = state
            .peers
            .owner(&device_id)
            .expect("the pre-open peer is installed");
        assert!(
            peer.endpoint_auth_task().is_none(),
            "non-vacuity: the arm is what installs a task, so it must start with none"
        );

        if let Some(component) = withhold {
            link.left.withhold_binding_component_for_test(component);
            assert!(
                link.left.endpoint_auth_binding().await.is_none(),
                "the armed connector can no longer state a complete binding"
            );
        }

        let open_event = link.take_open_event();
        let handled = handle_transport_event(&state, device_id.clone(), open_event).await;

        let owner_still_current = state.peers.get_if_current(&owner).is_some();
        let has_auth_task = state
            .peers
            .get_if_current(&owner)
            .and_then(|peer| peer.endpoint_auth_task())
            .is_some();
        let (
            data_channel_open,
            handshake_started,
            verification_code_sent,
            hellos_sent,
            handshaking,
        ) = {
            let data = peer.state.read();
            (
                data.data_channel_open,
                data.handshake_started_at.is_some(),
                data.verification_code_sent.is_some(),
                data.diag.hellos_sent,
                matches!(data.status, PeerStatus::Handshaking),
            )
        };
        let outcome = OpenPathOutcome {
            handled,
            owner_still_current,
            has_auth_task,
            data_channel_open,
            handshake_started,
            verification_code_sent,
            hellos_sent,
            handshaking,
            has_authenticated_channel: legacy_test_has_authenticated_channel(&state, &owner),
            // Asked last, because it is the fencing observation: a connector the
            // arm retired can no longer promote a connected claim at all, while
            // one the arm promoted answers that it already has.
            connector: link.left.confirm_data_channel_open(),
        };

        // Closed through the fixture's own path first, and only then are the
        // states shut down. Consuming the fixture here is what finally releases
        // both receivers, so they stay owned for every observation above; and
        // closing before shutdown means this is the one close, rather than a
        // second one racing whatever `shutdown` already retired.
        link.close().await;
        state.shutdown().await;
        peer_state.shutdown().await;
        outcome
    }

    /// A missing **local** binding component fails the whole open path closed.
    ///
    /// The existing missing-component controls assert that the binding
    /// constructor refuses half a pair. That is one boundary below this one, and
    /// it would still pass with the engine's fail-closed branch deleted. This
    /// drives the production `DataChannelOpen` arm over a genuinely working
    /// channel and asserts what that branch is actually for: no task, no
    /// handshake work, a fenced connector, no capability.
    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    #[ignore = "opens a native WebRTC link; run explicitly in the isolated WSL harness"]
    async fn v4_arc04e_absent_local_binding_component_fails_the_open_path_closed() {
        let outcome = drive_open_path(
            "arc04e-absent-local-a",
            "arc04e-absent-local-b",
            Some(crate::transport::WithheldBindingComponent::Local),
        )
        .await;

        assert!(!outcome.handled, "the arm refuses this open");
        // The entry survives, so every "nothing happened" assertion below is
        // about a peer that is still there rather than one that vanished.
        assert!(outcome.owner_still_current);
        assert!(
            !outcome.has_auth_task,
            "an unbound attempt must never be installed: it would authenticate nothing"
        );
        // No Hello and no proof work. `initiate` is what writes every one of
        // these, so all five staying empty is the statement that it never ran —
        // no contribution reached the wire and no transcript was ever built.
        assert!(!outcome.data_channel_open);
        assert!(!outcome.handshake_started);
        assert!(!outcome.verification_code_sent);
        assert_eq!(outcome.hellos_sent, 0);
        assert!(!outcome.handshaking);
        assert!(
            !outcome.has_authenticated_channel,
            "and nothing is promoted on a channel nothing could be proved about"
        );
        // Fenced, not merely unpromoted. `Rejected` here is the operation fence
        // refusing: the connector cannot later hand its connected claim to
        // anyone, so it cannot release queued endpoint protocol without a task.
        assert!(
            matches!(outcome.connector, DataChannelOpenOwnership::Rejected),
            "the exact connector is fenced by the refusal"
        );
    }

    /// The exact twin, with the other side of the pair withheld, so neither
    /// control can pass on a condition belonging to its sibling.
    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    #[ignore = "opens a native WebRTC link; run explicitly in the isolated WSL harness"]
    async fn v4_arc04e_absent_remote_binding_component_fails_the_open_path_closed() {
        let outcome = drive_open_path(
            "arc04e-absent-remote-a",
            "arc04e-absent-remote-b",
            Some(crate::transport::WithheldBindingComponent::Remote),
        )
        .await;

        assert!(!outcome.handled);
        assert!(outcome.owner_still_current);
        assert!(!outcome.has_auth_task);
        assert!(!outcome.data_channel_open);
        assert!(!outcome.handshake_started);
        assert!(!outcome.verification_code_sent);
        assert_eq!(outcome.hellos_sent, 0);
        assert!(!outcome.handshaking);
        assert!(!outcome.has_authenticated_channel);
        assert!(matches!(
            outcome.connector,
            DataChannelOpenOwnership::Rejected
        ));
    }

    /// The positive twin: the same fixture, never armed.
    ///
    /// This is what makes the two refusals attributable to the withheld
    /// component rather than to a fixture that could never have opened at all.
    /// Every assertion is the opposite of its counterpart above, and the last
    /// one is the sharpest: an unarmed connector answers `AlreadyConnected`,
    /// because the arm took its connected claim, where an armed one answers
    /// `Rejected`, because the arm fenced it without ever taking one.
    ///
    /// No authenticated channel here either. A Hello has been sent and nothing
    /// has been verified yet, so promotion is correctly still absent — which is
    /// why the negatives do not rest on that assertion alone.
    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    #[ignore = "opens a native WebRTC link; run explicitly in the isolated WSL harness"]
    async fn v4_arc04e_stated_binding_components_open_and_start_the_handshake() {
        let outcome = drive_open_path("arc04e-stated-a", "arc04e-stated-b", None).await;

        assert!(outcome.handled, "the arm accepts this open");
        assert!(outcome.owner_still_current);
        assert!(
            outcome.has_auth_task,
            "the same construction installs a task when the binding is complete"
        );
        assert!(outcome.data_channel_open);
        assert!(outcome.handshake_started);
        assert!(outcome.verification_code_sent);
        assert_eq!(outcome.hellos_sent, 1);
        assert!(outcome.handshaking);
        assert!(!outcome.has_authenticated_channel);
        assert!(
            matches!(
                outcome.connector,
                DataChannelOpenOwnership::AlreadyConnected
            ),
            "the connector was promoted, not fenced"
        );
    }

    #[tokio::test]
    async fn admission_gate_drops_application_traffic_before_authentication() {
        // Report cases 1,2,5,6: a Handshaking peer's application / reliable /
        // RPC / governance frame is dropped before it counts as received,
        // refreshes liveness, or reaches a handler.
        use crate::protocol::RosterRequestMessage;
        let cases: Vec<(&str, MeshMessage)> = vec![
            (
                "channel",
                MeshMessage::Channel {
                    channel: "secret".into(),
                    payload: serde_json::json!({ "steal": true }),
                },
            ),
            (
                "reliable",
                MeshMessage::ChannelSeq {
                    stream: 1,
                    seq: 1,
                    channel: "secret".into(),
                    payload: serde_json::json!(1),
                },
            ),
            (
                "rpc",
                MeshMessage::RpcRequest(RpcRequestMessage {
                    request_id: "r1".into(),
                    method: "drain".into(),
                    payload: serde_json::json!(1),
                    streaming: false,
                }),
            ),
            (
                "governance",
                MeshMessage::RosterRequest(RosterRequestMessage::default()),
            ),
        ];
        for (name, msg) in cases {
            let state = build_test_state(&format!("admit-drop-{name}"));
            insert_session_less_peer(&state, "attacker", None);
            set_admission(&state, "attacker", false, PeerStatus::Handshaking);

            handle_inbound_frame(&state, "attacker", frame_bytes(&msg)).await;

            let p = state.peers.get("attacker").expect("peer present");
            let d = p.state.read();
            assert_eq!(
                d.diag.frames_in, 0,
                "{name}: a pre-admission frame must not count as received"
            );
            assert!(
                d.last_recv_at.is_none(),
                "{name}: a pre-admission frame must not refresh liveness"
            );
            assert_eq!(
                d.admission_rejected, 1,
                "{name}: the pre-admission drop must be recorded"
            );
        }
    }

    #[tokio::test]
    async fn admission_gate_admits_application_traffic_from_active_peer() {
        // Report case 9: an admitted peer's application frame flows normally —
        // the gate must not break legitimate traffic.
        let state = build_test_state("admit-active-ok");
        insert_session_less_peer(&state, "member", None);
        set_admission(&state, "member", true, PeerStatus::Active);
        // Arc 04: policy state alone no longer admits. Install a real
        // authenticated-channel capability so this exercises the inbound
        // wiring rather than re-testing the gate's refusal.
        state
            .peers
            .get("member")
            .expect("peer present")
            .install_authenticated_channel_for_test();

        handle_inbound_frame(
            &state,
            "member",
            frame_bytes(&MeshMessage::Channel {
                channel: "chat".into(),
                payload: serde_json::json!("hi"),
            }),
        )
        .await;

        let p = state.peers.get("member").expect("peer present");
        let d = p.state.read();
        assert_eq!(d.diag.frames_in, 1, "an admitted peer's frame is processed");
        assert_eq!(d.admission_rejected, 0);
        assert!(d.last_recv_at.is_some());
    }

    #[tokio::test]
    async fn v4_arc04_admission_gate_refuses_application_traffic_without_a_capability() {
        // The bool-only negative, at the real inbound call site. `set_admission`
        // makes legacy policy consider this peer fully admitted; without an
        // installed authenticated channel the frame must still be rejected.
        // This is the case that regresses if any gate falls back to the bool.
        let state = build_test_state("admit-no-capability");
        insert_session_less_peer(&state, "member", None);
        set_admission(&state, "member", true, PeerStatus::Active);
        assert!(
            state
                .peers
                .get("member")
                .expect("peer present")
                .state
                .read()
                .is_admitted(),
            "non-vacuity: legacy policy really does consider this peer admitted"
        );

        handle_inbound_frame(
            &state,
            "member",
            frame_bytes(&MeshMessage::Channel {
                channel: "chat".into(),
                payload: serde_json::json!("hi"),
            }),
        )
        .await;

        let p = state.peers.get("member").expect("peer present");
        let d = p.state.read();
        assert_eq!(
            d.diag.frames_in, 0,
            "no application frame is processed without a live capability"
        );
        assert_eq!(d.admission_rejected, 1);
    }

    #[tokio::test]
    async fn admission_gate_lets_protocol_frames_through_while_handshaking() {
        // Report case 4: handshake/approval frames pass even while the peer is
        // unauthenticated, so the handshake can actually complete.
        let state = build_test_state("admit-protocol-pass");
        insert_session_less_peer(&state, "peer", None);
        set_admission(&state, "peer", false, PeerStatus::Handshaking);

        handle_inbound_frame(
            &state,
            "peer",
            frame_bytes(&MeshMessage::Approve(crate::protocol::ApproveMessage {})),
        )
        .await;

        let p = state.peers.get("peer").expect("peer present");
        assert_eq!(
            p.state.read().admission_rejected,
            0,
            "a handshake/approval frame must not be gated"
        );
    }

    #[tokio::test]
    async fn early_approve_cannot_activate_unauthenticated_peer() {
        // Report case 7: an `Approve` that arrives before authentication (and a
        // `roster_approve` that latched `local_approve_sent`) must NOT promote
        // the peer to Active. The latch is harmless; the transition now requires
        // `authenticated` (the full handshake→Active path is covered by the
        // two_peer_handshake / governance integration tests).
        let state = build_test_state("admit-early-approve");
        insert_session_less_peer(&state, "peer", None);
        set_admission(&state, "peer", false, PeerStatus::Handshaking);
        {
            let p = state.peers.get("peer").expect("peer present");
            p.state.write().local_approve_sent = true;
        }

        let owner = state.peers.owner("peer").expect("peer owner");
        handshake::on_approve(&state, &owner).await;

        let p = state.peers.get("peer").expect("peer present");
        let d = p.state.read();
        assert!(d.remote_approve_seen, "the approve is recorded");
        assert!(
            !matches!(d.status, PeerStatus::Active),
            "an unauthenticated peer must never reach Active"
        );
    }

    #[tokio::test]
    async fn v4_arc03_stale_message_owner_cannot_mutate_replacement_peer() {
        let state = build_test_state("arc03-stale-message-owner");
        insert_session_less_peer(&state, "peer", None);
        let stale_owner = state.peers.owner("peer").expect("first peer owner");
        insert_session_less_peer(&state, "peer", None);

        handle_inbound_frame_from(
            &state,
            &stale_owner,
            frame_bytes(&MeshMessage::Approve(crate::protocol::ApproveMessage {})),
        )
        .await;

        let replacement = state.peers.get("peer").expect("replacement peer");
        assert!(!replacement.state.read().remote_approve_seen);
    }

    // ---- Arc 04 E1: no inbound application effect escapes the fence -------
    //
    // The old inbound path answered the admission fence with an `Option<bool>`
    // and then dispatched on a device id, so a replacement installed during the
    // dispatch answered every lookup and received the effect, the liveness
    // touch, the counters, and the delivery. The controls below pin the
    // replaced case for each of those four, plus a same-fixture positive
    // baseline so none of them can pass vacuously.
    //
    // The pause is an API seam, not a scheduler race: `admit_inbound_for_test`
    // mints exactly the authority the fence mints, the control installs a
    // replacement while holding it, and only then dispatches. There is no
    // sleep, no yield ordering, and no timing assumption anywhere.

    /// Mint the exact inbound authority `handle_inbound_frame_from` mints, so a
    /// control can hold it across a replacement.
    fn admit_inbound_for_test(
        state: &Arc<NetworkState>,
        owner: &state::PeerOwnerToken,
        msg: MeshMessage,
    ) -> Option<state::AdmittedInboundApplicationOperation> {
        state
            .peers
            .with_admitted_current_or_refused(
                owner,
                |admitted| Some(admitted.inbound_application_operation(msg)),
                |_| None,
            )
            .flatten()
    }

    /// An installed peer that passes the application-admission fence: policy
    /// state plus a real authenticated-channel capability. No connector, so
    /// every outbound reply correctly fails — which is what the delivery and
    /// counter assertions below want.
    fn insert_admitted_session_less_peer(
        state: &Arc<NetworkState>,
        device_id: &str,
    ) -> Arc<PeerConnection> {
        let peer = Arc::new(PeerConnection::new(device_id.to_string(), None));
        {
            let mut d = peer.state.write();
            d.authenticated = true;
            d.status = PeerStatus::Active;
        }
        peer.install_authenticated_channel_for_test();
        install_peer(&state.peers, Arc::clone(&peer));
        peer
    }

    fn shelve_frame() -> MeshMessage {
        MeshMessage::Shelve(crate::protocol::ShelveMessage {
            reason: Some("arc04-e1".into()),
        })
    }

    #[tokio::test]
    async fn v4_arc04e1_admitted_inbound_effect_lands_on_the_captured_installation() {
        // Positive baseline for the control below: with no replacement, the
        // admitted frame moves the captured peer and announces it. Without
        // this, "the replacement got nothing" would also pass if the dispatch
        // did nothing at all.
        let state = build_test_state("arc04e1-baseline");
        let captured = insert_admitted_session_less_peer(&state, "peer");
        let owner = state.peers.owner("peer").expect("the peer is installed");
        let mut events = state.events_tx.subscribe();

        let operation = admit_inbound_for_test(&state, &owner, shelve_frame())
            .expect("an admitted owner mints an inbound authority");
        let (msg, dispatch) = operation.into_dispatch();
        let MeshMessage::Shelve(s) = msg else {
            panic!("the authority carries the frame it admitted");
        };
        on_shelve(&state, &dispatch, s).await;

        assert!(
            captured.state.read().remote_shelved,
            "the admitted effect lands on the captured installation"
        );
        assert!(
            matches!(
                events.try_recv(),
                Ok(MeshEvent::Peer(PeerEvent::Shelved { .. }))
            ),
            "and is announced once"
        );
    }

    #[tokio::test]
    async fn v4_arc04e1_inbound_application_effect_never_reaches_a_replacement() {
        // Pause / replacement / resume. The authority is minted while A is
        // current and consumed after B has taken the device id.
        let state = build_test_state("arc04e1-effect");
        let captured = insert_admitted_session_less_peer(&state, "peer");
        let captured_owner = state.peers.owner("peer").expect("A is installed");

        // PAUSE — hold the authority minted for A.
        let operation = admit_inbound_for_test(&state, &captured_owner, shelve_frame())
            .expect("A is admitted at mint time");

        // REPLACEMENT — a genuinely distinct installation under the same id.
        let replacement = insert_admitted_session_less_peer(&state, "peer");
        assert!(
            !Arc::ptr_eq(&captured, &replacement),
            "the two installations are distinct peer objects"
        );
        assert!(
            state.peers.get_if_current(&captured_owner).is_none(),
            "A is superseded"
        );
        let before = {
            let d = replacement.state.read();
            (
                d.diag.frames_in,
                d.diag.bytes_in,
                d.last_recv_at,
                d.remote_shelved,
                d.admission_rejected,
            )
        };
        let mut events = state.events_tx.subscribe();

        // RESUME — dispatch the authority minted for A.
        let (msg, dispatch) = operation.into_dispatch();
        let MeshMessage::Shelve(s) = msg else {
            panic!("the authority carries the frame it admitted");
        };
        on_shelve(&state, &dispatch, s).await;

        // Effect, liveness, counters, mutation.
        let after = {
            let d = replacement.state.read();
            (
                d.diag.frames_in,
                d.diag.bytes_in,
                d.last_recv_at,
                d.remote_shelved,
                d.admission_rejected,
            )
        };
        assert_eq!(
            before, after,
            "the replacement receives no effect, liveness, counter or mutation"
        );
        // Delivery.
        assert!(
            events.try_recv().is_err(),
            "and nothing is announced on its behalf"
        );
    }

    #[tokio::test]
    async fn v4_arc04e1_captured_peer_effect_is_refused_after_replacement() {
        // Every synchronous inbound effect — shelve, unshelve, capabilities,
        // both heartbeat writes, channel delivery, and RPC handler entry — now
        // funnels through `with_captured_peer`, which runs the effect *inside*
        // `PeerRegistry::with_current` and therefore under the mutation lock
        // replacement itself takes. This pins that one choke point: the effect
        // either runs whole or does not run, and the refusal is a `None` the
        // caller must handle, not a bool it may ignore.
        let state = build_test_state("arc04e1-choke-point");
        let captured = insert_admitted_session_less_peer(&state, "peer");
        let captured_owner = state.peers.owner("peer").expect("A is installed");

        let operation = admit_inbound_for_test(&state, &captured_owner, shelve_frame())
            .expect("A is admitted at mint time");
        let (_msg, dispatch) = operation.into_dispatch();

        // Still current: the effect runs and its value comes back.
        assert_eq!(
            dispatch.with_captured_peer(&state.peers, |peer| {
                peer.state.write().remote_shelved = true;
                "ran"
            }),
            Some("ran"),
            "a current installation runs the effect under the fence"
        );
        assert!(captured.state.read().remote_shelved);

        // Replaced: the effect does not run at all, and the caller is told so
        // by the absence of a value rather than by a boolean it could drop.
        let replacement = insert_admitted_session_less_peer(&state, "peer");
        let mut ran = false;
        let outcome = dispatch.with_captured_peer(&state.peers, |peer| {
            ran = true;
            peer.state.write().remote_shelved = false;
            "ran"
        });
        assert_eq!(
            outcome, None,
            "a superseded installation authorizes nothing"
        );
        assert!(!ran, "and the effect body is never entered");
        assert!(
            captured.state.read().remote_shelved,
            "the captured installation is left exactly as the fence last saw it"
        );
        assert!(
            !replacement.state.read().remote_shelved,
            "and the replacement is untouched"
        );
    }

    #[tokio::test]
    async fn v4_arc04e1_inbound_delivery_is_never_attributed_to_a_replacement() {
        // The escape a subscriber can see: a payload admitted for A delivered
        // under a device id B now owns would be read as B's.
        let state = build_test_state("arc04e1-delivery");
        insert_admitted_session_less_peer(&state, "peer");
        let captured_owner = state.peers.owner("peer").expect("A is installed");
        let mut frames = state.subscribe_channel("c");

        let channel_frame = || MeshMessage::Channel {
            channel: "c".into(),
            payload: serde_json::json!("arc04-e1"),
        };

        // Baseline: still current, so it is delivered.
        let (msg, dispatch) = admit_inbound_for_test(&state, &captured_owner, channel_frame())
            .expect("A is admitted")
            .into_dispatch();
        let MeshMessage::Channel { channel, payload } = msg else {
            panic!("the authority carries the frame it admitted");
        };
        on_channel_frame(&state, &dispatch, channel, payload).await;
        assert!(
            frames.try_recv().is_ok(),
            "an admitted payload is delivered while its installation is current"
        );

        // Replaced between mint and dispatch: not delivered at all.
        let operation = admit_inbound_for_test(&state, &captured_owner, channel_frame())
            .expect("A is still admitted at mint time");
        insert_admitted_session_less_peer(&state, "peer");
        let (msg, dispatch) = operation.into_dispatch();
        let MeshMessage::Channel { channel, payload } = msg else {
            panic!("the authority carries the frame it admitted");
        };
        on_channel_frame(&state, &dispatch, channel, payload).await;
        assert!(
            frames.try_recv().is_err(),
            "a payload admitted for a superseded installation is not delivered under its device id"
        );
    }

    #[tokio::test]
    async fn v4_arc04e1_stale_owner_application_frame_credits_the_replacement_nothing() {
        // End to end through the real entry point, with A already replaced:
        // the fence answers `None` for a stale owner, so the replacement gets
        // no liveness, no counters, and not even the refusal count.
        let state = build_test_state("arc04e1-stale-counters");
        insert_admitted_session_less_peer(&state, "peer");
        let stale_owner = state.peers.owner("peer").expect("A is installed");
        let replacement = insert_admitted_session_less_peer(&state, "peer");

        handle_inbound_frame_from(&state, &stale_owner, frame_bytes(&shelve_frame())).await;

        let d = replacement.state.read();
        assert_eq!(d.diag.frames_in, 0, "no frame is counted against B");
        assert_eq!(d.diag.bytes_in, 0, "no bytes are counted against B");
        assert!(d.last_recv_at.is_none(), "no liveness is credited to B");
        assert!(!d.remote_shelved, "no effect lands on B");
        assert_eq!(
            d.admission_rejected, 0,
            "a stale owner is not B's refusal either"
        );
    }

    #[tokio::test]
    async fn v4_arc04e1_reliable_stream_state_moves_only_under_the_fence() {
        // The reliable tables are keyed by device id, so successive
        // installations share them. A frame from a stale owner must not move
        // the mark that B will read, nor drain the outbox B inherits.
        //
        // The receive side additionally owes a *biconditional*, asserted at the
        // end: the high-water mark advances exactly when the payload was handed
        // to the subscribers. Advancing it without delivering is the worse
        // failure of the two — the sender's retransmit then reads as a
        // duplicate, gets acked, and the caller's `enqueue` resolves `Ok` for a
        // payload nobody received. Every case below asserts delivery and mark
        // together for that reason.
        //
        // Determinism: replacement is installed through the same API seam the
        // sibling controls use — the authority is minted, a replacement is
        // installed while it is held, and only then is it dispatched. No sleep,
        // no yield ordering, no scheduler assumption.
        let state = build_test_state("arc04e1-reliable");
        insert_admitted_session_less_peer(&state, "peer");
        let stale_owner = state.peers.owner("peer").expect("A is installed");
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        reliable::enqueue(&state, "peer", "c", serde_json::json!(1), None, tx).await;
        let stream = state
            .reliable_out
            .lock()
            .get("peer")
            .expect("the outbox exists")
            .stream_for_test();
        let mut frames = state.subscribe_channel("c");
        insert_admitted_session_less_peer(&state, "peer");

        // A `ChannelSeq` from the superseded owner: the high-water mark never
        // moves, so B's first real frame is not treated as a duplicate.
        handle_inbound_frame_from(
            &state,
            &stale_owner,
            frame_bytes(&MeshMessage::ChannelSeq {
                stream: 7,
                seq: 1,
                channel: "c".into(),
                payload: serde_json::json!(1),
            }),
        )
        .await;
        assert!(
            state.reliable_in.lock().get("peer").is_none(),
            "a refused frame does not advance the mark a replacement reads"
        );
        assert!(
            frames.try_recv().is_err(),
            "and it is delivered to nobody under the id the replacement now holds"
        );

        // A `ChannelAck` from the superseded owner settles nothing in the
        // outbox the replacement inherits.
        handle_inbound_frame_from(
            &state,
            &stale_owner,
            frame_bytes(&MeshMessage::ChannelAck { stream, up_to: 1 }),
        )
        .await;
        assert!(
            rx.try_recv().is_err(),
            "a refused ack does not drain the replacement's outbox"
        );
        assert_eq!(reliable::pending_total(&state), 1);

        // ---- the receive-side biconditional, on the installation that is
        // ---- current from here on.
        let seq_frame = |seq: u64, payload: serde_json::Value| MeshMessage::ChannelSeq {
            stream: 7,
            seq,
            channel: "c".into(),
            payload,
        };
        // `on_channel_seq_admitted` takes the frame apart exactly as the
        // dispatch does, so a control cannot drive it with a seq the authority
        // was not minted for.
        async fn receive(
            state: &Arc<NetworkState>,
            dispatch: &state::AdmittedInboundDispatch,
            msg: MeshMessage,
        ) {
            let MeshMessage::ChannelSeq {
                stream,
                seq,
                channel,
                payload,
            } = msg
            else {
                panic!("the authority carries the frame it admitted");
            };
            reliable::on_channel_seq_admitted(state, dispatch, stream, seq, channel, payload).await;
        }
        let mark_now = |state: &Arc<NetworkState>| {
            state
                .reliable_in
                .lock()
                .get("peer")
                .map(|mark| mark.last_seq_for_test())
        };

        // FRESH, current: delivered, and the mark advances with it.
        let owner_b = state.peers.owner("peer").expect("B is installed");
        let (msg, dispatch) =
            admit_inbound_for_test(&state, &owner_b, seq_frame(1, "fresh".into()))
                .expect("B is admitted")
                .into_dispatch();
        receive(&state, &dispatch, msg).await;
        assert_eq!(
            frames.try_recv().map(|frame| frame.payload).ok(),
            Some(serde_json::json!("fresh")),
            "a fresh seq on the current installation is delivered"
        );
        assert_eq!(mark_now(&state), Some(1), "and the mark advances with it");

        // ADMITTED FOR B, DISPATCHED AFTER C: neither. This is the case the
        // repair exists for — the mark must not run ahead of the delivery the
        // fence refused, or seq 2 below would be silently written off as a
        // duplicate the sender was already acked for.
        let operation = admit_inbound_for_test(&state, &owner_b, seq_frame(2, "fenced-out".into()))
            .expect("B is still admitted at mint time");
        insert_admitted_session_less_peer(&state, "peer");
        let (msg, dispatch) = operation.into_dispatch();
        receive(&state, &dispatch, msg).await;
        assert!(
            frames.try_recv().is_err(),
            "a payload admitted for a superseded installation is delivered to nobody"
        );
        assert_eq!(
            mark_now(&state),
            Some(1),
            "and its seq is not recorded as received either"
        );

        // DUPLICATE, current: suppression applies only to a seq that really was
        // delivered. Seq 1 was, so it is not delivered again and moves nothing.
        let owner_c = state.peers.owner("peer").expect("C is installed");
        let (msg, dispatch) =
            admit_inbound_for_test(&state, &owner_c, seq_frame(1, "replay".into()))
                .expect("C is admitted")
                .into_dispatch();
        receive(&state, &dispatch, msg).await;
        assert!(
            frames.try_recv().is_err(),
            "an already-delivered seq is suppressed"
        );
        assert_eq!(mark_now(&state), Some(1), "and moves nothing");

        // Seq 2 was fenced out, never delivered — so it is *not* a duplicate,
        // and the sender's retransmit of it lands. This is the half that fails
        // if the mark is ever allowed to advance without the delivery.
        let (msg, dispatch) =
            admit_inbound_for_test(&state, &owner_c, seq_frame(2, "retransmit".into()))
                .expect("C is admitted")
                .into_dispatch();
        receive(&state, &dispatch, msg).await;
        assert_eq!(
            frames.try_recv().map(|frame| frame.payload).ok(),
            Some(serde_json::json!("retransmit")),
            "a seq the fence refused is still fresh, not a duplicate"
        );
        assert_eq!(mark_now(&state), Some(2), "and the mark advances with it");
    }

    #[tokio::test]
    async fn failed_approve_send_does_not_record_local_acceptance() {
        // A roster-driven approve can run before the peer's data channel
        // opens. A failed local send must leave `local_approve_sent` false so
        // a later handshake trigger can try again. The flag is written only
        // after the current channel accepts the bytes for transmission.
        let state = build_test_state("approve-failed-send");
        insert_session_less_peer(&state, "early-peer", None); // no session → the send fails
        handshake::send_local_approve(&state, "early-peer").await;
        let peer = state.peers.get("early-peer").expect("peer present");
        assert!(
            !peer.state.read().local_approve_sent,
            "a failed approve send must not read as locally accepted"
        );
    }

    #[tokio::test]
    async fn connect_timeout_reclaims_a_peer_whose_data_channel_never_opened() {
        // A session created long ago whose data channel never opened is a
        // failed attempt — the connect-timeout watchdog must reclaim it so
        // discovery rebuilds. This is the teardown authority that replaced
        // the ICE-checking timeout; it keys off the reliable milestone.
        let state = build_test_state("connect-timeout-drop");
        insert_session_less_peer(&state, "stuck-peer", None);
        {
            let peer = state.peers.get("stuck-peer").expect("peer present");
            let mut d = peer.state.write();
            d.session_started_at = Some(pre_connect_timeout_instant());
            d.data_channel_open = false;
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            !state.peers.contains_key("stuck-peer"),
            "a session whose data channel never opened past the deadline must be reclaimed"
        );
    }

    #[test]
    fn connecting_stuck_detection_keys_off_data_channel_and_age() {
        let grace = scheduler::RESTART_TRAFFIC_GRACE_MS;
        let old = Instant::now()
            .checked_sub(Duration::from_millis(grace + 1_000))
            .expect("clock headroom");

        // Fresh session, channel not open yet → still legitimately
        // negotiating, NOT stuck (don't churn a new attempt).
        let fresh = connection::PeerStateData {
            session_started_at: Some(Instant::now()),
            ..Default::default()
        };
        assert!(!connecting_stuck_past_grace(&fresh, grace));

        // Old session, channel still never opened → stuck; a fresh offer
        // should rebuild rather than renegotiate onto the corpse.
        let stuck = connection::PeerStateData {
            session_started_at: Some(old),
            ..Default::default()
        };
        assert!(connecting_stuck_past_grace(&stuck, grace));

        // Channel opened → never "stuck" regardless of age; liveness is the
        // heartbeat's job from here, and an offer is a real renegotiation.
        let open = connection::PeerStateData {
            session_started_at: Some(old),
            data_channel_open: true,
            ..Default::default()
        };
        assert!(!connecting_stuck_past_grace(&open, grace));
    }

    #[tokio::test]
    async fn restart_verify_rebuilds_a_restart_that_never_carried_traffic() {
        // A peer stuck in IceRestart whose clock is older than the deadline,
        // with no session (so it reads as "ICE not up" → the connect-timeout
        // deadline applies): the restart never confirmed via traffic, so it
        // must be rebuilt. data_channel_open=true keeps the connect-timeout
        // watchdog out of it, isolating the restart-verify path.
        let state = build_test_state("restart-verify-drop");
        insert_session_less_peer(&state, "dead-restart", None);
        {
            let peer = state.peers.get("dead-restart").expect("peer present");
            let mut d = peer.state.write();
            d.data_channel_open = true;
            d.session_started_at = None;
            d.tier = ConnectionTier::IceRestart {
                started: pre_connect_timeout_instant(),
            };
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            !state.peers.contains_key("dead-restart"),
            "a restart that never confirmed via traffic past the deadline must be rebuilt"
        );
    }

    #[tokio::test]
    async fn restart_verify_spares_a_fresh_restart() {
        // A just-kicked restart must be given time to confirm, not rebuilt
        // on the first poll.
        let state = build_test_state("restart-verify-keep");
        insert_session_less_peer(&state, "fresh-restart", None);
        {
            let peer = state.peers.get("fresh-restart").expect("peer present");
            let mut d = peer.state.write();
            d.data_channel_open = true;
            d.session_started_at = None;
            d.tier = ConnectionTier::IceRestart {
                started: Instant::now(),
            };
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            state.peers.contains_key("fresh-restart"),
            "a just-kicked restart must be given its grace, not rebuilt immediately"
        );
    }

    #[tokio::test]
    async fn connect_timeout_spares_a_peer_whose_data_channel_opened() {
        // Same old session clock, but the data channel opened — so liveness
        // is the heartbeat's job now, not the connect-timeout's. ICE state
        // could say anything; once the channel is up this watchdog must
        // never touch the peer.
        let state = build_test_state("connect-timeout-keep");
        insert_session_less_peer(&state, "live-peer", None);
        {
            let peer = state.peers.get("live-peer").expect("peer present");
            let mut d = peer.state.write();
            d.session_started_at = Some(pre_connect_timeout_instant());
            d.data_channel_open = true;
        }
        ice_watchdog::poll_all(&state).await;
        assert!(
            state.peers.contains_key("live-peer"),
            "once the data channel has opened, the connect-timeout must never reclaim the peer"
        );
    }

    #[tokio::test]
    async fn reconnect_intent_is_due_once_then_backs_off() {
        // A freshly recorded intent is due immediately (so the next tick
        // re-offers it), then the backoff pushes it out — it must NOT come due
        // on every tick (that would publish an offer per tick).
        let state = build_test_state("reconnect-intent-due");
        state.record_reconnect_intent("peer-x", false);
        assert_eq!(
            state.due_reconnect_intents(),
            vec!["peer-x".to_string()],
            "a fresh intent is due immediately"
        );
        assert!(
            state.due_reconnect_intents().is_empty(),
            "after servicing, the intent backs off and isn't due again on the very next tick"
        );
        assert!(
            state.has_reconnect_intent("peer-x"),
            "backing off keeps the intent — it's retried later, not dropped"
        );
    }

    #[tokio::test]
    async fn reconnect_intent_cleared_on_success() {
        let state = build_test_state("reconnect-intent-clear");
        state.record_reconnect_intent("peer-y", false);
        assert!(state.has_reconnect_intent("peer-y"));
        state.clear_reconnect_intent("peer-y");
        assert!(!state.has_reconnect_intent("peer-y"));
        assert!(state.due_reconnect_intents().is_empty());
    }

    #[tokio::test]
    async fn reconnect_intent_expires_after_grace() {
        // Past the reconnecting grace, an intent is given up — dropped, never
        // retried — so a peer that genuinely went away can't spin forever.
        let state = build_test_state("reconnect-intent-expire");
        state.record_reconnect_intent("peer-z", false);
        {
            let mut map = state.reconnect_intents.lock();
            let intent = map.get_mut("peer-z").expect("intent present");
            intent.give_up_at = std::time::Instant::now() - std::time::Duration::from_millis(1);
        }
        assert!(
            state.due_reconnect_intents().is_empty(),
            "an intent past its grace is given up, not retried"
        );
        assert!(!state.has_reconnect_intent("peer-z"));
    }

    #[tokio::test]
    async fn evicted_peer_drop_never_rearms_reconnect() {
        // The evicted-peer loop guard. A device our own signed state has
        // evicted must not be self-dialed back: its post-deny channel close
        // arrives as a "recoverable" IceFailed, and since we hold the lex-lower
        // id we're its offerer — so without the guard `drop_peer` re-arms a
        // reconnect intent, the 2 s tick reconnects, the handshake re-denies,
        // the channel closes, and it drops again, forever. Dropping an evicted
        // peer is intentional teardown, so no intent is left behind; the peer's
        // own announce (answered + re-denied with proof) is the only thing that
        // re-opens a session, so convergence keeps its channel without the spin.
        use crate::network_state::{
            transition_payload, NetworkState as GovState, Transition, TransitionVariant,
        };
        use crate::{NetworkKind, Role};

        let state = build_test_state("evicted-no-reconnect");
        let net = state.network_id.clone();

        // Both must sort lex-greater than any base32 identity so `we_offer`
        // holds (we're the offerer) and dash-free so `pubkey_part` leaves the id
        // whole and the evict target matches. base32-lowercase tops out at 'z' in
        // a 52-char id, so any all-'z' string longer than 52 chars clears every
        // identity deterministically — a plain "y"*60 did not (a ~3 % of ephemeral
        // identities that happen to start with 'z' sort above it, flaking the
        // precondition assert). Distinct lengths keep the two ids distinct.
        let evicted = "z".repeat(60);
        let live = "z".repeat(61);
        assert!(
            state.identity.public_id() < evicted.as_str()
                && state.identity.public_id() < live.as_str(),
            "test ids must sort above our identity so we're their offerer"
        );

        // Seed a Closed governance whose signed member log evicts `evicted`.
        let owner = crate::identity::Identity::ephemeral();
        let owner_pk = owner.public_id().to_string();
        {
            let mut gov = state.governance_state.write();
            *gov = GovState::empty_for(&net);
            gov.kind = NetworkKind::Closed;
            gov.roles.insert(owner_pk.clone(), Role::Owner);
            let signed = |variant: TransitionVariant, at: u64| {
                let payload = transition_payload(&net, &variant);
                Transition {
                    at,
                    signatures: vec![crate::signing::sign_with(owner.signing_key(), &payload)],
                    signers: vec![owner_pk.clone()],
                    variant,
                }
            };
            gov.member_log = vec![
                signed(
                    TransitionVariant::RoleGrant {
                        target: evicted.clone(),
                        role: Role::Member,
                    },
                    1,
                ),
                signed(
                    TransitionVariant::Evict {
                        target: evicted.clone(),
                    },
                    2,
                ),
            ];
        }
        assert!(
            governance::log_evicted(&state, &evicted),
            "seed must make the target read as evicted"
        );
        assert!(
            !governance::log_evicted(&state, &live),
            "the control peer must not read as evicted"
        );

        // The evicted peer: its IceFailed drop must leave no reconnect intent.
        insert_session_less_peer(&state, &evicted, None);
        drop_peer(&state, &evicted, DropReason::IceFailed).await;
        assert!(
            !state.has_reconnect_intent(&evicted),
            "an evicted peer's drop must not arm a reconnect intent"
        );

        // Control: a non-evicted offerer-role peer with the identical drop DOES
        // self-reconnect — proving the guard, not the plumbing, suppresses the
        // evicted one.
        insert_session_less_peer(&state, &live, None);
        drop_peer(&state, &live, DropReason::IceFailed).await;
        assert!(
            state.has_reconnect_intent(&live),
            "a non-evicted offerer-role peer still self-reconnects on IceFailed"
        );
    }

    #[tokio::test]
    async fn flush_reconnect_intents_returns_all_and_backs_off() {
        // The relay-reconnect event flushes every owed intent at once; flushing
        // advances each backoff so the tick doesn't immediately re-offer them.
        let state = build_test_state("reconnect-intent-flush");
        state.record_reconnect_intent("a", false);
        state.record_reconnect_intent("b", false);
        let mut flushed = state.flush_reconnect_intents();
        flushed.sort();
        assert_eq!(flushed, vec!["a".to_string(), "b".to_string()]);
        assert!(
            state.due_reconnect_intents().is_empty(),
            "flushing advanced the backoff, so the tick won't double-offer the same intents"
        );
    }

    #[tokio::test]
    async fn zombie_session_cleared_on_stale_inbound() {
        let state = build_test_state("zombie-clear");
        insert_session_less_peer(&state, "peer-zombie", Some(stale_instant()));
        assert!(state.peers.contains_key("peer-zombie"));
        clear_stale_session_if_zombie(&state, "peer-zombie").await;
        assert!(
            !state.peers.contains_key("peer-zombie"),
            "a peer silent past STALE_INBOUND_MS must be dropped so the inbound announce/offer rebuilds it"
        );
    }

    #[tokio::test]
    async fn recently_active_peer_not_cleared() {
        let state = build_test_state("fresh-keep");
        insert_session_less_peer(&state, "peer-fresh", Some(Instant::now()));
        clear_stale_session_if_zombie(&state, "peer-fresh").await;
        assert!(
            state.peers.contains_key("peer-fresh"),
            "a peer that received recently must be kept — in-place ICE recovery, not a full rebuild"
        );
    }

    #[tokio::test]
    async fn peer_without_inbound_not_cleared() {
        let state = build_test_state("none-keep");
        insert_session_less_peer(&state, "peer-handshaking", None);
        clear_stale_session_if_zombie(&state, "peer-handshaking").await;
        assert!(
            state.peers.contains_key("peer-handshaking"),
            "a peer with no inbound yet (mid-handshake / Sighted) must be left for the re-offer path"
        );
    }

    #[tokio::test]
    async fn offline_flag_round_trips_and_reports_edges() {
        let state = build_test_state("offline-flag");
        assert!(!state.is_offline(), "a fresh state is online");
        // online → offline: swap returns the previous value (false).
        assert!(!state.set_offline(true));
        assert!(state.is_offline());
        // offline → offline: previous value is true (no edge).
        assert!(state.set_offline(true));
        // offline → online: previous value is true (the returning edge).
        assert!(state.set_offline(false));
        assert!(!state.is_offline());
    }

    #[tokio::test]
    async fn renegotiate_ice_is_a_noop_while_offline() {
        let state = build_test_state("offline-reneg");
        state.set_offline(true);
        // The offline guard sits ahead of every peer-map / session access,
        // so a renegotiation request while offline simply returns — no
        // gather attempt, no panic on a peer that isn't there.
        renegotiate_ice(&state, "ghost-peer", true, "test").await;
        assert!(
            state.peers.is_empty(),
            "renegotiate_ice must not touch state while offline"
        );
    }

    #[tokio::test]
    async fn reoffer_after_failed_answer_is_a_noop_while_offline() {
        let state = build_test_state("offline-reoffer");
        state.set_offline(true);
        // Same guard: a late/stale answer that can't apply must not kick a
        // rebuild while the interface is down.
        reoffer_after_failed_answer(&state, "ghost-peer").await;
        assert!(state.peers.is_empty());
    }

    #[tokio::test]
    async fn stale_peer_mid_ice_restart_is_not_cleared() {
        let state = build_test_state("restart-keep");
        // Inbound is pre-wake-stale (the condition that fires the zombie
        // clear), but an in-place ICE restart is in flight — the session is
        // recovering, not wedged. It must survive: dropping it here is what
        // guillotined the restart-before-drop path after a wake.
        insert_session_less_peer(&state, "peer-restarting", Some(stale_instant()));
        {
            let peer = state.peers.get("peer-restarting").expect("peer present");
            peer.state.write().tier = ConnectionTier::IceRestart {
                started: Instant::now(),
            };
        }
        clear_stale_session_if_zombie(&state, "peer-restarting").await;
        assert!(
            state.peers.contains_key("peer-restarting"),
            "a peer with an in-flight ICE restart must survive the stale-inbound zombie check"
        );
    }

    /// The headline case: an Active session that's gone silent (its ICE
    /// would falsely read `Connected`, so the zombie clear leaves it) is
    /// confirmed by traffic on the peer's re-announce and rebuilt when no
    /// frame answers — recovery driven by presence, not by a `Leave`.
    #[tokio::test]
    #[ignore = "opens a local WebRTC object; run explicitly in the isolated WSL harness"]
    async fn silent_active_session_rebuilt_on_reannounce() {
        let (state, command_driver) = build_test_state_with_command_driver("announce-probe-drop");
        let (worker, _events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("test connector opens");
        let worker = Arc::new(worker);
        let peer = Arc::new(PeerConnection::new(
            "peer-silent".to_string(),
            Some(Arc::clone(&worker)),
        ));
        {
            let mut data = peer.state.write();
            data.last_recv_at = Some(stale_instant());
            data.status = PeerStatus::Active;
        }
        install_peer(&state.peers, peer);

        confirm_active_session_on_announce(&state, "peer-silent").await;

        // The probe pinged (no session, so the ping no-ops) and scheduled a
        // confirm sweep; with nothing answering, the silent session is
        // reclaimed within the probe delay.
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.peers.contains_key("peer-silent") {
            if Instant::now() > deadline {
                panic!("a silent Active session must be rebuilt after the announce-driven probe");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        state.shutdown().await;
        command_driver.abort();
    }

    #[tokio::test]
    #[ignore = "opens a local WebRTC object; run explicitly in the isolated WSL harness"]
    async fn probe_answered_by_traffic_keeps_the_session() {
        // The teardown is keyed off inbound traffic, never a timer or ICE
        // state: if a frame arrives during the confirm window — a pong
        // answering the probe — the session is genuinely alive and must
        // survive, even though `last_recv_at` looked stale when we pinged.
        let (state, command_driver) =
            build_test_state_with_command_driver("announce-probe-answered");
        let (worker, _events) = state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("test connector opens");
        let peer = Arc::new(PeerConnection::new(
            "peer-answers".to_string(),
            Some(Arc::new(worker)),
        ));
        {
            let mut data = peer.state.write();
            data.last_recv_at = Some(stale_instant());
            data.status = PeerStatus::Active;
        }
        install_peer(&state.peers, peer);

        confirm_active_session_on_announce(&state, "peer-answers").await;
        // Inbound traffic answers the probe partway through the confirm
        // window — a real pong refreshes `last_recv_at` exactly this way,
        // landing well before the sweep at `WAKE_PROBE_DELAY_MS`.
        tokio::time::sleep(Duration::from_millis(scheduler::WAKE_PROBE_DELAY_MS / 3)).await;
        state
            .peers
            .get("peer-answers")
            .expect("peer present")
            .state
            .write()
            .last_recv_at = Some(Instant::now());

        // Wait past the sweep; the session must survive because traffic
        // confirmed it, even though it looked stale when we pinged.
        tokio::time::sleep(Duration::from_millis(scheduler::WAKE_PROBE_DELAY_MS)).await;
        assert!(
            state.peers.contains_key("peer-answers"),
            "a probe answered by inbound traffic must not rebuild the session"
        );
        state.shutdown().await;
        command_driver.abort();
    }

    #[tokio::test]
    async fn fresh_active_session_not_probed_on_reannounce() {
        // A peer we've heard from within the staleness window is healthy —
        // its heartbeat pong keeps `last_recv_at` fresh — so a routine
        // re-announce must not probe (let alone rebuild) it.
        let state = build_test_state("announce-probe-fresh");
        insert_session_less_peer(&state, "peer-fresh", Some(Instant::now()));
        state
            .peers
            .get("peer-fresh")
            .expect("peer present")
            .state
            .write()
            .status = PeerStatus::Active;

        confirm_active_session_on_announce(&state, "peer-fresh").await;

        let peer = state
            .peers
            .get("peer-fresh")
            .expect("fresh peer must survive");
        assert!(
            peer.state.read().last_liveness_probe_at.is_none(),
            "a peer we've heard from recently must not be probed"
        );
    }

    #[tokio::test]
    async fn non_established_session_not_probed_on_reannounce() {
        // Only Active/Shelved sessions are probed — a still-connecting
        // (Sighted) peer is handled by the re-offer / connect-timeout paths,
        // not by an inbound-silence rebuild.
        let state = build_test_state("announce-probe-sighted");
        insert_session_less_peer(&state, "peer-sighted", Some(stale_instant()));
        // Default status is Sighted.

        confirm_active_session_on_announce(&state, "peer-sighted").await;

        let peer = state
            .peers
            .get("peer-sighted")
            .expect("sighted peer must survive the probe gate");
        assert!(
            peer.state.read().last_liveness_probe_at.is_none(),
            "only established (Active/Shelved) sessions are probed"
        );
    }

    #[tokio::test]
    async fn restarting_active_session_not_probed_on_reannounce() {
        // A session mid in-place ICE restart is recovering, not wedged; the
        // probe must leave it alone so it owns its window (the same guard the
        // zombie clear honours).
        let state = build_test_state("announce-probe-restart");
        insert_session_less_peer(&state, "peer-restarting", Some(stale_instant()));
        {
            let peer = state.peers.get("peer-restarting").expect("peer present");
            let mut d = peer.state.write();
            d.status = PeerStatus::Active;
            d.tier = ConnectionTier::IceRestart {
                started: Instant::now(),
            };
        }

        confirm_active_session_on_announce(&state, "peer-restarting").await;

        let peer = state
            .peers
            .get("peer-restarting")
            .expect("recovering peer must survive");
        assert!(
            peer.state.read().last_liveness_probe_at.is_none(),
            "a session mid in-place restart owns its recovery window"
        );
    }
}
