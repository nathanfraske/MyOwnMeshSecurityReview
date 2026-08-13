//! Daemon control protocol — line-delimited JSON over a local
//! interprocess socket (unix-domain socket on Unix, named pipe on
//! Windows). `myownmesh ctl …` clients and the GUI both talk to the
//! running daemon via this socket.
//!
//! Wire shape: one JSON object per line. Requests have `op` plus
//! op-specific fields; responses have `ok` (bool) plus
//! op-specific payload, or `error: string` on failure.
//!
//! Most ops are single-shot request → response. The exception is
//! [`Request::EventsSubscribe`], which converts the connection into a
//! one-way server-push stream: the daemon writes one JSON event per
//! line until the client disconnects. The GUI's Tauri backend uses
//! this to forward live mesh events into the frontend.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use interprocess::local_socket::tokio::prelude::*;
use myownmesh_core::MeshHandle;
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::registry::NetworkRegistry;
use crate::services::ServiceManager;

/// The control endpoint's own existence and admission: where the socket
/// lives, what permissions it carries, and who may connect to it. Nothing
/// below this line decides those, and nothing in there knows the protocol.
mod listener;

pub use listener::default_socket_name;
use listener::{bind_listener, resolve_socket, verify_local_peer};

/// The request and response vocabulary itself: every `op` a client may send,
/// the response envelope, and the realtime advert shapes. Nothing in there
/// performs an operation or knows what a network is — it is what the two ends
/// have to agree on, and it is the part a client reimplements.
mod wire;

use wire::realtime_refused;
pub use wire::{
    RealtimeAdvert, RealtimeEncoding, RealtimeFlowCeiling, RealtimePipeDirection, Request, Response,
};

/// Bytes on the wire and the admission that funds them: the JSON line reader,
/// the binary realtime frame codec, and the one rule they share — nothing is
/// buffered that the process owner's grant has not paid for. Nothing in there
/// knows what a request means; it decides how much, never what.
mod framing;

pub use framing::{
    decode_realtime_send_unit, encode_realtime_recv_unit_with_ceiling, RealtimeRecvUnit,
    RealtimeSendUnit, MAX_REALTIME_FLOW_LABEL_BYTES,
};
use framing::{
    optional_nonzero_bytes, read_bounded_json_line, AdmittedReader, DecodeRefusal, FrameAdmission,
    REALTIME_FRAME_HEADER,
};

/// Places a control can reach into `serve` without production having a branch.
///
/// Empty outside `cfg(test)`, so in a release build this is a zero-sized value
/// threaded through one call and compiled away. The alternative shapes were both
/// worse: a process-global barrier races every other control in the binary, and
/// a `cfg(test)`-only parameter on `serve` makes the public signature depend on
/// the profile.
#[derive(Default)]
pub(crate) struct ControlHooks {
    /// Pauses one connection task at the instant before `EventsSubscribe`
    /// commits its client to the registry.
    ///
    /// This exact instant, because it is the one the shutdown has to beat. The
    /// mailbox is already funded and the scope already issued; the client is not
    /// yet in any table. A registration that got past here after the drain began
    /// would be an `EventsSubscribe` answered with success to a client nothing
    /// will ever clean up.
    #[cfg(test)]
    before_events_subscribe_commit: Option<Arc<DispatchBarrier>>,
    /// Hands the control the registry `serve` built for itself.
    ///
    /// `serve` constructs its own `ClientRegistry` from the mesh handle, so
    /// there is otherwise no way to ask it, after the fact, whether anything was
    /// left behind. Fired once, immediately after construction.
    #[cfg(test)]
    registry: Option<tokio::sync::oneshot::Sender<crate::ipc::ClientRegistry>>,
}

/// A one-shot pause, for controls that need a task stopped at an exact line.
///
/// One connection and one only: both halves are `take`n on first use, so a
/// second connection reaching the same line runs straight through. That is what
/// makes it usable in a `serve` that is still accepting — the control pauses the
/// connection it cares about without freezing the listener.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct DispatchBarrier {
    arrived: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

#[cfg(test)]
impl DispatchBarrier {
    /// The barrier and the two ends a control drives it by.
    ///
    /// Gated to match its one caller. The terminal-shutdown control that drives
    /// this needs a real accepted connection over a Unix socket, so it does not
    /// exist on Windows -- and neither, therefore, does anything that builds a
    /// barrier for it. The type itself stays available to both, because
    /// `ControlHooks` names it on every platform.
    #[cfg(unix)]
    fn paired() -> (
        Arc<Self>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        (
            Arc::new(Self {
                arrived: Mutex::new(Some(arrived_tx)),
                release: Mutex::new(Some(release_rx)),
            }),
            arrived_rx,
            release_tx,
        )
    }

    /// Announce arrival, then wait to be let go.
    ///
    /// Both sends are allowed to fail: a control that has dropped its end has
    /// stopped caring, and the connection should carry on rather than hang.
    async fn pass(&self) {
        let arrived = self.arrived.lock().take();
        let release = self.release.lock().take();
        if let Some(arrived) = arrived {
            let _ = arrived.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }
    }
}

/// Start the control socket listener. Returns when the shutdown
/// broadcast fires.
pub async fn serve(
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    custom: Option<PathBuf>,
    realtime: RealtimeAdvert,
    shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    serve_with_hooks(
        mesh,
        registry,
        services,
        custom,
        realtime,
        shutdown,
        ControlHooks::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_with_hooks(
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    custom: Option<PathBuf>,
    realtime: RealtimeAdvert,
    mut shutdown: broadcast::Receiver<()>,
    hooks: ControlHooks,
) -> Result<()> {
    // Both are optional, and absence is not absence of a bound. Nothing a
    // connection retains is held without a lease -- a frame's growth funded per
    // step at the capacity that step requests, the fixed read window funded in
    // full before a byte is read -- so a daemon started with neither of these
    // set is bounded by what its owner granted it, rather than by a number
    // someone had to invent at startup. An explicit value is an additional,
    // stricter policy layered on top; see [`FrameAdmission`].
    //
    // `MYOWNMESH_IPC_STREAM_CAPACITY` used to be read here and is gone. It named
    // a fixed item count for the inbound RPC stream queue, and that queue is a
    // resource mailbox now: it has no item count to select, and an owner value
    // that nothing could enforce is worse than the compatibility break of
    // removing it.
    let json_line_bytes = optional_nonzero_bytes("MYOWNMESH_IPC_JSON_LINE_BYTES")?;
    let realtime_frame_bytes = optional_nonzero_bytes("MYOWNMESH_IPC_REALTIME_FRAME_BYTES")?;
    // The registry's own acquisition port, issued once for the whole control
    // surface rather than per connection: what it admits — client records,
    // method claims, subscriptions — outlives any single connection, so funding
    // them from a connection's subtree would release them when the wrong thing
    // went away. Taken before the listener binds, so a daemon that cannot fund
    // its own registry fails to start rather than accepting a connection it
    // cannot register.
    let clients = crate::ipc::ClientRegistry::new(
        mesh.local_application_resource_scope()
            .context("issue the IPC registry's local application resource scope")?,
    );
    #[cfg(test)]
    let hooks = {
        let mut hooks = hooks;
        if let Some(publish) = hooks.registry.take() {
            let _ = publish.send(clients.clone());
        }
        hooks
    };
    let target = resolve_socket(custom)?;
    let listener = bind_listener(&target)?;
    info!(?target, "control socket listening");
    let state = Arc::new(ControlState {
        mesh,
        registry,
        services,
        clients,
        json_line_bytes,
        realtime_frame_bytes,
        realtime,
        #[cfg(test)]
        before_events_subscribe_commit: hooks.before_events_subscribe_commit,
    });
    #[cfg(not(test))]
    let _ = hooks;

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                info!("control socket shutting down");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok(stream) => {
                        // Funded before the task exists. A connection this
                        // daemon cannot account for is closed here by dropping
                        // its stream, which is the truthful answer: no task was
                        // started, nothing was half-registered, and the client
                        // sees a closed socket rather than one that accepted it
                        // and then never spoke. Spawning first and discovering
                        // the refusal inside the task would already have taken
                        // the worker the refusal is about.
                        // Refused for either reason — no capacity, or the
                        // runtime is closing — the connection is closed here by
                        // dropping its stream. Accepting into a closing runtime
                        // would spawn a task the drain has already decided not
                        // to wait for work from, and that `serve` would then
                        // have to wait for anyway.
                        let task = match state.clients.lease_task() {
                            Ok(task) => task,
                            Err(refusal) => {
                                warn!("control connection refused, not accounted: {refusal}");
                                drop(stream);
                                continue;
                            }
                        };
                        let state = state.clone();
                        tokio::spawn(async move {
                            // Moved in, so the lease is released exactly when
                            // this task stops — including if it is dropped
                            // mid-await rather than returning.
                            let _task = task;
                            if let Err(e) = handle_client(stream, state).await {
                                debug!("control client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept failed: {e}");
                    }
                }
            }
        }
    }

    // Terminal from here. The order below is the whole of the shutdown contract
    // and each step depends on the one before it.
    //
    // 1. `begin_closing` moves the runtime out of `Running` under the same lock
    //    the routing tables live under, and answers `true` to exactly one
    //    caller. From this instant every admitting path in the registry refuses
    //    — a client cannot register, claim a method, subscribe to a channel,
    //    install a realtime flow or file a pending operation into tables the
    //    drain is about to walk. `false` means someone else is already draining
    //    this registry, and a second drain would try to close flows that are
    //    already closed.
    //
    // 2. The connection tasks already accepted are told, and they stop reading.
    //    Told rather than aborted: a task cancelled mid-dispatch would drop a
    //    half-applied request, and the point of waiting is that it does not have
    //    to be.
    //
    // 3. The drain itself. Every client's flows are closed and every handler it
    //    was the last claimant of is forgotten, through their own networks.
    //    Dropping the handles would release nothing — a flow handle owns no part
    //    of the flow — so a daemon that shut down without this would leave
    //    native transceivers and senders behind for as long as their sessions
    //    lived.
    //
    // 4. And only then does this return. `serve` returning is a claim that the
    //    control surface is over, and it was not true before: a connection task
    //    outliving it would still be holding a registry, a mesh handle and a
    //    socket that this function's caller is entitled to treat as finished
    //    with. Waiting for the count to reach zero is what makes the claim true.
    if state.clients.begin_closing() {
        // One client at a time, released before the next is taken. The registry
        // hands back ids rather than records for exactly this reason: a record
        // carries the client's retired routes and forgotten names, and
        // collecting every one of them first would hold every client's cleanup
        // state at once instead of one client's.
        for client in state.clients.shutdown_ids() {
            if let Some(removed) = state.clients.unregister(client) {
                release_owned_registrations(&state, removed).await;
            }
        }
        state.clients.shutdown_settle_pending();
    }
    state.clients.wait_for_tasks().await;
    // Answers the state rather than asserting one, so a second `serve` over the
    // same registry — which drained nothing — cannot publish `Closed` on the
    // strength of having waited. Logged rather than panicked: a daemon on its
    // way out should say what it found, not abort on it.
    match state.clients.finish_closed() {
        crate::ipc::Lifecycle::Closed => info!("control surface closed"),
        other => warn!(?other, "control surface did not reach Closed"),
    }

    Ok(())
}

struct ControlState {
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    clients: crate::ipc::ClientRegistry,
    realtime: RealtimeAdvert,
    json_line_bytes: Option<usize>,
    realtime_frame_bytes: Option<usize>,
    #[cfg(test)]
    before_events_subscribe_commit: Option<Arc<DispatchBarrier>>,
}

// The daemon keeps no realtime flow state of its own, and deliberately holds
// nothing keyed by label. `recv_webrtc_realtime_any` delivers the label with the
// unit, so a local index of open flows would be a second answer to a question
// core already answers — and the failure mode of a stale mirror on this path is
// units routed to a flow that closed.

async fn handle_client(stream: LocalSocketStream, state: Arc<ControlState>) -> Result<()> {
    verify_local_peer(&stream)?;
    // One acquisition subtree for everything this connection buffers on the way
    // in, so its inbound bytes are released together when it ends rather than
    // lingering in the daemon's scope. Two admissions over the one subtree
    // because they carry the same connection's bytes under two owner policies,
    // and a connection only ever uses one of them: a socket that becomes a
    // realtime pipe has stopped reading JSON lines for good.
    let inbound = state
        .mesh
        .local_application_resource_scope()
        .context("issue this connection's inbound frame resource scope")?;
    let json_lines = FrameAdmission::new(inbound.clone(), state.json_line_bytes);
    let realtime_frames = FrameAdmission::new(inbound, state.realtime_frame_bytes);
    let (reader, mut writer) = stream.split();
    // The reader's own buffer, funded before it exists. `fill_buf` copies bytes
    // into this allocation before any admission code can see them, so it is the
    // one inbound allocation that cannot be charged at the moment it is used --
    // a claim taken then would be funding storage that already existed. The
    // acquire-then-construct order, and the leases that outlive the buffer, are
    // `AdmittedReader`'s so that a control can reach the same sequence this
    // connection runs.
    let mut reader = AdmittedReader::admit(reader, &json_lines)
        .context("control connection read buffer was not admitted")?;
    // The read is raced against the shutdown signal, and the signal wins ties.
    //
    // Without this a connection sitting idle on a socket nobody is writing to
    // would hold the whole daemon open: `serve` waits for every accepted task,
    // and this task's only other way to finish is a client that may never send
    // another byte. Selecting here means the task ends at the shutdown rather
    // than at the client's convenience.
    //
    // Requests already being dispatched are not interrupted — the select is at
    // the top of the loop, not around the dispatch — so shutting down cannot
    // leave a request half-applied. It costs one more round trip at worst.
    loop {
        let line = tokio::select! {
            biased;
            () = state.clients.closing() => break,
            line = read_bounded_json_line(reader.frames(), &json_lines) => match line? {
                Some(line) => line,
                None => break,
            },
        };
        // Funded before the parse runs, and the lease outlives the decoded value
        // it accounts for: `(lease, request)` drops `request` first, because
        // bindings from one pattern drop in reverse. The parsed `Request` owns
        // dynamically allocated strings and payload that live for as long as the
        // dispatch below, which may be the connection's whole life -- an earlier
        // comment here said the line's bytes were the only thing worth
        // accounting past this point and dropped the funding outright, leaving
        // that decoded state charged to nobody.
        let (_decoded, request) = match line.decode_request(&json_lines) {
            Ok(decoded) => decoded,
            Err(DecodeRefusal::Malformed(e)) => {
                let resp = Response::err(format!("parse: {e}"));
                let error = serde_json::to_string(&resp)? + "\n";
                writer.write_all(error.as_bytes()).await?;
                continue;
            }
            Err(refusal @ DecodeRefusal::Admission(_)) => {
                let resp = Response::err(refusal.to_string());
                let error = serde_json::to_string(&resp)? + "\n";
                writer.write_all(error.as_bytes()).await?;
                continue;
            }
        };
        // The raw line's bytes are dead weight from here -- the decoded request
        // owns its own copies -- so the byte leases go now while the structural
        // lease above stays with what it funds.
        drop(line);
        // EventsSubscribe converts the connection into a server-
        // push channel: the daemon writes mesh events plus any
        // IPC-routed frames (RpcInbound, ChannelInbound, ...)
        // until the client disconnects. Allocate a ClientId so
        // subsequent RPC/channel-management requests on OTHER
        // command sockets can target this connection.
        if matches!(request, Request::EventsSubscribe) {
            // One acquisition subtree per event-subscribed connection.
            // `local_application_resource_scope` already issues a child of the
            // runtime's owner, so this connection's queued frames are accounted
            // as their own subtree and every byte behind them is released when
            // both mailbox ends drop at disconnect — without the daemon naming
            // a frame count anywhere.
            let scope = state
                .mesh
                .local_application_resource_scope()
                .context("issue this client's local application resource scope")?;
            let (tx, rx) = myownmesh_core::resource_mailbox(scope)
                .context("fund this client's outbound frame mailbox")?;
            // Registration is an admission now. A refusal is answered on this
            // connection rather than raised: the socket is healthy and the
            // client is entitled to know why it was not subscribed, whereas
            // returning would drop the connection and leave it guessing.
            // The seam is here and not a line earlier or later. Above it the
            // mailbox is funded and the scope issued but nothing is filed;
            // below it the client is in the table. A control that paused
            // anywhere else would be asserting about a different race.
            #[cfg(test)]
            if let Some(barrier) = &state.before_events_subscribe_commit {
                barrier.pass().await;
            }
            let client = match state.clients.register(tx) {
                Ok(client) => client,
                Err(refusal) => {
                    let resp = Response::err(format!("events subscribe refused: {refusal}"));
                    let line = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    continue;
                }
            };
            let client_id = client.id;
            // Ack carries the client_id so the caller knows what
            // to pass back on subsequent `client_id`-bearing ops.
            let ack = Response::ok(serde_json::json!({
                "subscribed": true,
                "client_id": client_id.to_string(),
                "client_capability": state.clients.capability(&client),
            }));
            let line = serde_json::to_string(&ack)? + "\n";
            writer.write_all(line.as_bytes()).await?;
            let result = run_events_stream(&state, &mut writer, rx).await;
            // Clean up the client's claims regardless of how the stream ended.
            //
            // What comes back is what the registry cannot release on its own:
            // the handle, whose realtime flows have to be *closed* rather than
            // dropped — a flow handle owns nothing, so dropping one leaves the
            // label claimed and the native half up until the session itself
            // ends — and the methods this client was the last claimant of, whose
            // synthetic handlers are still installed. This is the one place that
            // knows both those and the networks to reach them through.
            //
            // `None` means something else already removed this client, and that
            // something else is the shutdown sweep, which does the same release
            // with the same handle. Doing nothing here is not skipping the work.
            if let Some(removed) = state.clients.unregister(client_id) {
                release_owned_registrations(&state, removed).await;
            }
            result?;
            break;
        }
        // TraceSubscribe is the same server-push pattern as
        // EventsSubscribe but carries only ConnTrace records and needs
        // no ClientId (it routes nothing back in). An unknown network
        // is reported as a plain error response and the connection
        // stays open for another request.
        if let Request::TraceSubscribe { network } = &request {
            let network = network.clone();
            match state.registry.get(&network) {
                Some(net) => {
                    let ack = Response::ok(serde_json::json!({
                        "subscribed": true,
                        "stream": "conn_trace",
                        "network": network,
                    }));
                    let line = serde_json::to_string(&ack)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    let rx = net.state().subscribe_conn_trace();
                    let result = run_trace_stream(&mut writer, rx).await;
                    result?;
                    break;
                }
                None => {
                    let resp = Response::err(format!("unknown network: {network}"));
                    let line = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    continue;
                }
            }
        }
        // RealtimePipe converts the connection into a one-way binary stream of
        // realtime units, the EventsSubscribe pattern in whichever direction was
        // asked for. After the ack the connection speaks only length-prefixed
        // binary frames — no per-frame JSON, no base64.
        if let Request::RealtimePipe {
            direction,
            network,
            peer,
            client_id,
            client_capability,
            flow_capability,
        } = &request
        {
            // Field shapes are checked before the ack, and extras are refused
            // rather than ignored. A pipe that acked and then behaved as though
            // a field had not been sent would be indistinguishable, from the
            // client's side, from one that honoured it.
            let bound = match realtime_pipe_binding(
                *direction,
                network,
                peer.as_deref(),
                flow_capability.as_deref(),
            ) {
                Ok(bound) => bound,
                Err(message) => {
                    let resp = Response::err(message);
                    writer
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                    continue;
                }
            };
            // Both directions are owned now. Inbound has always needed an owner
            // to end with; outbound needs one because the flow it writes to
            // belongs to a client, and the client capability is what proves this
            // connection is that client.
            let pipe_owner = {
                let (Some(client_id), Some(capability)) =
                    (*client_id, client_capability.as_deref())
                else {
                    let resp = Response::err(
                        "realtime_pipe requires client_id and client_capability: a pipe \
                         is owned by the client that opened its flow, and possession of \
                         the capability is what proves this connection is that client",
                    );
                    writer
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                    continue;
                };
                let Some(owner) = state.clients.authenticate(client_id, capability) else {
                    let resp = Response::err("invalid local client authority");
                    writer
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                    continue;
                };
                owner
            };
            let bound_network = match &bound {
                RealtimePipeBinding::Outbound { network, .. }
                | RealtimePipeBinding::Inbound { network, .. } => network.clone(),
            };
            let Some(net) = state.registry.get(&bound_network) else {
                let resp = Response::err(format!("unknown network: {bound_network}"));
                writer
                    .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                    .await?;
                continue;
            };
            // An inbound pipe claims the session's unit stream BEFORE the ack.
            // The claim is once per session, so it can legitimately fail — a
            // second pipe for the same peer, or a session that is already gone —
            // and those must be refusals, not an ack followed by a connection
            // that silently never delivers anything.
            //
            // The claim is an exclusive lease, and the reader IS the lease:
            // dropping it returns it. So when this pipe ends — cleanly, or
            // because the client crashed and its socket died — the next pipe for
            // the same session claims successfully and resumes. Nothing is lost
            // in the gap, because units accumulate on the session's own queue
            // and never in the reader.
            //
            // Which is why the daemon caches nothing here. Holding a reader
            // across reconnects, or remembering which sessions were claimed,
            // would give the daemon a lease to release correctly and a mirror to
            // keep in step. The lease already releases itself, and the queue it
            // guards belongs to the session.
            //
            // A refusal therefore means what it says: the session is gone, or a
            // pipe for it is live right now. Neither is a lingering claim from a
            // pipe that has already died.
            //
            // An outbound pipe proves its flow before the ack for the mirror
            // reason: a client that acked and then found every unit refused
            // would have to discover from silence that its capability was wrong.
            let inbound_stream = match &bound {
                RealtimePipeBinding::Inbound { peer, .. } => match net.realtime_inbound(peer) {
                    Some(stream) => Some(stream),
                    None => {
                        let resp = Response::err(format!(
                            "no inbound realtime stream for {peer}: the session is not \
                                 current, or a live pipe already holds it — one inbound pipe \
                                 per session, and the lease returns when that pipe ends"
                        ));
                        writer
                            .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                            .await?;
                        continue;
                    }
                },
                RealtimePipeBinding::Outbound {
                    network,
                    flow_capability,
                } => {
                    if pipe_owner
                        .with_realtime_flow(flow_capability, network, |_flow| ())
                        .is_none()
                    {
                        let resp = Response::err(
                            "unknown flow_capability on this network: it was never issued \
                             to this client, or the flow it named has already been closed",
                        );
                        writer
                            .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                            .await?;
                        continue;
                    }
                    None
                }
            };
            let ack = Response::ok(serde_json::json!({ "realtime_pipe": true }));
            writer
                .write_all((serde_json::to_string(&ack)? + "\n").as_bytes())
                .await?;
            writer.flush().await?;
            // Recover the buffered reader — it may already hold the first frame.
            let pipe = async {
                match (inbound_stream, &bound) {
                    (
                        None,
                        RealtimePipeBinding::Outbound {
                            network,
                            flow_capability,
                        },
                    ) => {
                        run_realtime_outbound_pipe(
                            &net,
                            &pipe_owner,
                            flow_capability,
                            network,
                            // The frames, not the admitted reader. Handing the
                            // wrapper over would move it, and its leases fund
                            // the buffer these bytes arrive in -- the pipe would
                            // be reading from an allocation whose funding had
                            // travelled with a value it does not know it owns.
                            // Borrowing leaves the owner here, alive for exactly
                            // as long as the pipe runs.
                            reader.frames(),
                            &realtime_frames,
                        )
                        .await
                    }
                    (Some(stream), RealtimePipeBinding::Inbound { peer, .. }) => {
                        run_realtime_inbound_pipe(
                            &net,
                            peer,
                            &stream,
                            reader.frames(),
                            &mut writer,
                            &realtime_frames,
                        )
                        .await
                    }
                    // Unreachable by construction — the claim above is taken on
                    // exactly the inbound arm — and spelled as a refusal rather
                    // than a panic, because a control connection failing closed
                    // is always preferable to a daemon that stops.
                    _ => Ok(()),
                }
            };
            let result = tokio::select! {
                result = pipe => result,
                () = pipe_owner.wait_disconnected() => Ok(()),
            };
            result?;
            break;
        }
        let resp = dispatch(&state, request).await;
        let line = serde_json::to_string(&resp)? + "\n";
        writer.write_all(line.as_bytes()).await?;
    }
    Ok(())
}

/// The two binary `realtime_pipe` connections and what they are bound to.
/// Frame-shaped work only: reading units off a socket and writing them back.
/// It decides nothing about admission — the binding is checked before either
/// pump starts, and every refusal it can meet comes from core.
mod realtime_pipe;

use realtime_pipe::{
    realtime_pipe_binding, release_owned_registrations, run_realtime_inbound_pipe,
    run_realtime_outbound_pipe, RealtimePipeBinding,
};

/// The per-request router and everything it calls to satisfy one `op`.
/// One exhaustive match over [`Request`] lives there, so a new variant is a
/// compile error rather than a silent fallthrough, and the work each arm does
/// sits beside it in a module named for the domain it belongs to.
mod dispatch;

use dispatch::dispatch;

/// Stream events to one connected subscriber. Drains two
/// sources concurrently:
///
/// 1. The mesh-wide [`MeshHandle::events`] broadcast — peer /
///    phase / diag entries the engine emits.
/// 2. The per-client mpsc — `ServerOut` frames the IPC bridge
///    (RPC inbound, channel inbound, handler-displaced
///    notifications) pushes for this specific client.
///
/// Returns when the writer breaks (client gone) or both source
/// streams close. Source 1 closes only on daemon shutdown;
/// source 2 closes when the client's `unregister` drops the
/// last sender, which the caller invokes after this function
/// returns.
async fn run_events_stream<W>(
    state: &Arc<ControlState>,
    writer: &mut W,
    mut client_rx: myownmesh_core::ResourceMailboxReceiver<crate::ipc::ServerOut>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut mesh_rx = state.mesh.events();
    loop {
        tokio::select! {
            biased;
            // Per-client frames first — drains IPC-routed
            // RpcInbound / ChannelInbound / etc.
            maybe_frame = client_rx.recv() => {
                let Some(delivery) = maybe_frame else {
                    // Sender dropped — only happens after the
                    // outer handle_client called `unregister`,
                    // which only fires after this returns. In
                    // practice this branch never fires while
                    // the connection is live; treat as benign
                    // shutdown.
                    return Ok(());
                };
                // The retention lease stays bound across the write and is
                // dropped only after the bytes have left. Releasing it at pop
                // would report the frame's memory as free while this task still
                // holds and serializes it, which is the window a client that
                // stopped reading would otherwise be admitted through twice.
                let (frame, _retention) = delivery.into_parts();
                let line = serde_json::to_string(&frame)? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            recv = mesh_rx.recv() => match recv {
                Ok(event) => {
                    let frame = crate::ipc::ServerOut::Event { event };
                    let line = serde_json::to_string(&frame)? + "\n";
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                    if writer.flush().await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let frame = crate::ipc::ServerOut::Lagged { skipped: n };
                    let line = serde_json::to_string(&frame)? + "\n";
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        }
    }
}

/// Stream one network's connection-state transitions to a connected
/// `ctl trace` client. Writes each [`myownmesh_core::ConnTrace`] as a
/// compact JSON object on its own line (clean JSONL for
/// `scripts/merge-traces.py` and `jq`). On broadcast lag — a
/// transition storm outran a slow reader — emits a `{"lagged":N}`
/// marker rather than silently skipping, so a gap in the timeline is
/// always explicit. Returns when the client disconnects or the network
/// shuts down.
async fn run_trace_stream<W>(
    writer: &mut W,
    mut rx: broadcast::Receiver<myownmesh_core::ConnTrace>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        match rx.recv().await {
            Ok(trace) => {
                let line = serde_json::to_string(&trace)? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let line = serde_json::to_string(&serde_json::json!({ "lagged": n }))? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Single shared `MeshHandle` storage for the ctl client. Mostly a
/// future-proofing hook so a follow-up can attach per-network
/// state without changing the protocol.
#[allow(dead_code)]
static CTL_STATE: Mutex<Option<Arc<ControlState>>> = parking_lot::const_mutex(None);

/// What a client may say on this socket, and what it may not.
///
/// Renamed from `realtime_control_tests`, which had stopped being true of it:
/// the frame round-trips it used to hold went to [`framing`] with the codec
/// they exercise, and what is left is about the request vocabulary — an
/// operation that must no longer parse, a variant that must not parse without
/// the field its direction requires, and one that must round-trip exactly. None
/// of those is about bytes.
#[cfg(test)]
mod request_wire_tests {
    use super::*;

    /// Kept as a wire literal rather than a Rust variant, because what this
    /// control proves is that the *operation* is gone from the socket — not
    /// merely that a variant was renamed. A client still sending base64 units
    /// must be refused outright; there is no compatibility arm to catch it.
    const LEGACY_VIDEO_SEND: &str = r#"{
        "op":"video_send",
        "network":"test-network",
        "peer":"test-peer",
        "stream":0,
        "duration_us":1,
        "data":"AA=="
    }"#;

    #[test]
    fn base64_unit_operations_are_gone_from_the_wire() {
        assert!(
            serde_json::from_str::<Request>(LEGACY_VIDEO_SEND).is_err(),
            "video_send carried units as base64 over the reliable JSON path and \
             has no successor: the binary pipe is the only media path"
        );
    }

    /// A pipe is refused unless it is bound to the thing its direction is
    /// actually bound to — a flow outbound, a session inbound.
    ///
    /// Parsing and binding are separate steps here, and the assertions follow
    /// that split rather than blurring it: `network` is the only field the
    /// request type itself requires, because everything else is
    /// direction-dependent and a serde-level `Option` cannot express "required
    /// for one variant of a sibling field". The direction-dependent rules are
    /// [`realtime_pipe_binding`]'s, and are asserted against it.
    ///
    /// The outbound case is the finding: a pipe that accepted a `peer` would be
    /// carrying a selector it re-resolves per unit, which is how a pipe whose
    /// session had ended went on writing into the replacement's flow of the
    /// same name.
    #[test]
    fn a_realtime_pipe_will_not_parse_without_its_session() {
        let unbound = r#"{"op":"realtime_pipe","direction":"outbound"}"#;
        assert!(
            serde_json::from_str::<Request>(unbound).is_err(),
            "a pipe with no network names nothing to operate through"
        );

        assert!(
            realtime_pipe_binding(RealtimePipeDirection::Outbound, "home", None, Some("cap"))
                .is_ok(),
            "non-vacuity: an outbound pipe bound to a flow capability is accepted"
        );
        assert!(
            realtime_pipe_binding(
                RealtimePipeDirection::Outbound,
                "home",
                Some("peerpub"),
                Some("cap"),
            )
            .is_err(),
            "an outbound pipe must not carry a peer: that selector is what gets \
             re-resolved into a replacement session"
        );
        assert!(
            realtime_pipe_binding(RealtimePipeDirection::Outbound, "home", None, None).is_err(),
            "and it must carry the capability, which is the only thing that \
             authorizes a write"
        );

        assert!(
            realtime_pipe_binding(
                RealtimePipeDirection::Inbound,
                "home",
                Some("peerpub"),
                None
            )
            .is_ok(),
            "non-vacuity: an inbound pipe bound to a session is accepted"
        );
        assert!(
            realtime_pipe_binding(RealtimePipeDirection::Inbound, "home", None, None).is_err(),
            "an inbound pipe claims one session's stream and must name it"
        );
        assert!(
            realtime_pipe_binding(
                RealtimePipeDirection::Inbound,
                "home",
                Some("peerpub"),
                Some("cap"),
            )
            .is_err(),
            "and it is bound to a session rather than a flow, so a flow \
             capability here is refused rather than ignored"
        );
    }

    /// The `network_connect_peer` op is what a daemon-client embedder sends to
    /// dial one peer on a Silent network. Pin its wire tag + shape: it must
    /// decode from the exact JSON a client writes, and round-trip.
    #[test]
    fn network_connect_peer_request_round_trips() {
        let json = r#"{"op":"network_connect_peer","network":"test-network","peer":"peerpubkey"}"#;
        let req: Request = serde_json::from_str(json).expect("decode network_connect_peer");
        match &req {
            Request::NetworkConnectPeer {
                network,
                peer,
                pin,
                wait_ms,
            } => {
                assert_eq!(network, "test-network");
                assert_eq!(peer, "peerpubkey");
                // Wire-additive: an old client's op decodes with the
                // defaults — no pin, no wait.
                assert!(!pin);
                assert_eq!(*wait_ms, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // The `op` tag is the load-bearing discriminator; pin it on re-encode.
        let value = serde_json::to_value(&req).expect("encode");
        assert_eq!(value["op"], "network_connect_peer");
        assert_eq!(value["peer"], "peerpubkey");
        let back: Request = serde_json::from_value(value).expect("re-decode");
        assert!(matches!(back, Request::NetworkConnectPeer { .. }));
    }
}

/// The control surface's shutdown, driven end to end over a real socket.
///
/// Unix-only because it needs a socket at a path this control chooses.
/// `resolve_socket` honours a custom path on Unix and ignores it elsewhere,
/// falling back to a process-wide namespaced name — which two controls running
/// concurrently in one test binary would fight over.
#[cfg(all(test, unix))]
mod terminal_shutdown_tests {
    use interprocess::local_socket::{GenericFilePath, ToFsName};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;

    /// Long enough that a loaded machine will not trip it, short enough that a
    /// genuine hang is reported as a failure rather than as the whole suite
    /// timing out. Nothing below asserts *because* of this bound: every claim is
    /// made against an event already observed. It exists so that a regression
    /// which hangs says which step hung.
    const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

    async fn guarded<F: std::future::Future>(what: &str, future: F) -> F::Output {
        match tokio::time::timeout(HANG_GUARD, future).await {
            Ok(value) => value,
            Err(_) => panic!("hang guard: {what}"),
        }
    }

    /// A mesh with an ephemeral identity over the daemon test grant.
    ///
    /// `Identity::ephemeral` rather than `load_or_create`, so nothing here reads
    /// or writes the on-disk anchor. Provider installation is idempotent by
    /// identity, so this shares the one provider the rest of the daemon test
    /// binary uses rather than opening a second grant over the same process.
    async fn test_mesh() -> MeshHandle {
        myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            myownmesh_core::MeshConfig::default(),
            Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the daemon test grant opens an infrastructure-only mesh")
    }

    /// A shutdown arriving while an `EventsSubscribe` is mid-commit loses
    /// nothing and leaves nothing.
    ///
    /// The production path end to end: a real listener, a real accepted
    /// connection holding its own `TaskAdmission`, a real client socket, and a
    /// real `EventsSubscribe` paused at the instant before it would commit to
    /// the registry. Every assertion is made against an event already observed
    /// rather than after a sleep — arrival is a `oneshot`, the transition is the
    /// registry's own `closing()` signal, and the refusal is a line read off the
    /// socket.
    ///
    /// Four claims, and the middle two are what a registry-level control cannot
    /// reach:
    ///
    /// 1. the drain begins while the connection task is paused;
    /// 2. `serve` has *not* returned at that moment, because a task it accepted
    ///    is still alive — the whole of the "terminal" claim, and a `serve` that
    ///    returned on the shutdown signal alone fails here;
    /// 3. the paused request, once released, is answered *truthfully*: the
    ///    client is told its subscription was refused and why, rather than being
    ///    left to infer it from a dropped socket, and rather than being told it
    ///    succeeded;
    /// 4. and when `serve` does return, the registry is `Closed` and holds
    ///    nothing — no client, flow, handler claim, installed handler, channel
    ///    subscription, pending call or task lease.
    #[tokio::test]
    async fn a_subscribe_barriered_at_its_commit_loses_to_shutdown_and_leaves_nothing() {
        let directory = tempfile::tempdir().expect("temporary control root");
        let socket = directory.path().join("control.sock");
        let (barrier, arrived, release) = DispatchBarrier::paired();
        let (registry_tx, registry_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let mesh = test_mesh().await;
        let networks = NetworkRegistry::new();
        let services = ServiceManager::new(mesh.clone(), networks.clone());
        let serving = tokio::spawn(serve_with_hooks(
            mesh,
            networks,
            services,
            Some(socket.clone()),
            RealtimeAdvert {
                supported: false,
                encodings: Vec::new(),
                flow_ceiling: None,
            },
            shutdown_rx,
            ControlHooks {
                before_events_subscribe_commit: Some(barrier),
                registry: Some(registry_tx),
            },
        ));
        let clients = guarded("serve publishes its registry", registry_rx)
            .await
            .expect("serve publishes the registry it built");

        // A real client, over the socket `serve` is really listening on.
        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let stream = guarded("client connects", async {
            loop {
                // The listener binds inside the spawned `serve`, so the first
                // connect can lose the race with it. Retrying is not a timing
                // assumption — the hang guard is what fails if the listener
                // never appears at all.
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => return stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        let (client_reader, mut client_writer) = stream.split();
        let mut client_reader = BufReader::new(client_reader);
        client_writer
            .write_all(b"{\"op\":\"events_subscribe\"}\n")
            .await
            .expect("the client sends its subscribe");

        // (1) The connection task is parked at the commit, holding an accepted
        // `TaskAdmission`, with nothing filed in any table.
        guarded("the subscribe reaches its commit", arrived)
            .await
            .expect("the connection task reached the barrier");
        assert_eq!(
            clients.residue(),
            crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Running).with_tasks(1),
            "nothing is filed yet, but the connection carrying the paused              subscribe is itself an accepted task and is counted as one"
        );

        shutdown_tx
            .send(())
            .expect("the shutdown broadcast is live");
        // Observed, not waited out: this resolves on the registry's own signal,
        // which `begin_closing` publishes from inside `serve`'s terminal path.
        // Past this line the drain has provably started.
        guarded("serve begins closing", clients.closing()).await;

        // (2) And `serve` has not returned, because a task it accepted is still
        // alive.
        assert!(
            !serving.is_finished(),
            "serve returned while a connection task it accepted was still live"
        );
        assert_eq!(clients.lifecycle(), crate::ipc::Lifecycle::Closing);

        // (3) Released, the paused request is answered truthfully.
        release.send(()).expect("the paused task is still waiting");
        let mut answer = String::new();
        guarded(
            "the client is answered",
            client_reader.read_line(&mut answer),
        )
        .await
        .expect("the daemon answers on the still-open socket");
        let answer: Response =
            serde_json::from_str(answer.trim()).expect("the answer is a control response");
        assert!(
            !answer.ok,
            "a subscription refused by the drain is not reported as one that succeeded"
        );
        assert!(
            answer
                .error
                .as_deref()
                .is_some_and(|error| error.contains("closing")),
            "and the client is told why: {:?}",
            answer.error
        );

        // (4) Only now does `serve` return, and it leaves nothing behind.
        drop(client_writer);
        drop(client_reader);
        guarded("serve returns", serving)
            .await
            .expect("the serve task did not panic")
            .expect("serve returns without error");
        assert_eq!(
            clients.residue(),
            crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed),
            "no client, flow, handler, subscription, pending call or task lease remains"
        );
    }
}
