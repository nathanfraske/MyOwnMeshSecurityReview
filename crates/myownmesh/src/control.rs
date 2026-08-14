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

/// One decoded control request and the exact retention that funds its tree.
///
/// The request is declared first and therefore destroyed first on every unwind
/// path. The only place this owner is opened is the exhaustive control-loop
/// boundary below: ordinary requests keep `_retention` through dispatch, while
/// connection-converting variants drop it only after their exact successor
/// owner has been admitted. There is deliberately no `into_request` or generic
/// parts accessor that could return an unfunded request.
pub(super) struct AdmittedRequest {
    request: Request,
    _retention: myownmesh_core::ResourceLease,
}

impl AdmittedRequest {
    fn new(request: Request, retention: myownmesh_core::ResourceLease) -> Self {
        Self {
            request,
            _retention: retention,
        }
    }
}

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

pub use wire::{
    RealtimeAdvert, RealtimeEncoding, RealtimeFlowCeiling, RealtimePipeDirection, Request, Response,
};

/// Bytes on the wire and the admission that funds them: the JSON line reader,
/// the binary realtime frame codec, and the one rule they share — nothing is
/// buffered that the process owner's grant has not paid for. Nothing in there
/// knows what a request means; it decides how much, never what.
mod framing;

use framing::{
    config_reply_line_ceiling, events_subscribed_line_ceiling, network_id_reply_line_ceiling,
    optional_nonzero_bytes, prepare_reply_then, prepare_typed_and_line_building,
    read_bounded_json_line, variable_data_reply_line_ceiling, variable_operation_claim,
    AdmittedLineOut, AdmittedReader, ControlOut, DecodeRefusal, FrameAdmission,
    FundedVariableReply, OperationReplyData, PreparedReply, PreparedText, VariableReplySource,
    REALTIME_FRAME_HEADER,
};
pub use framing::{
    decode_realtime_send_unit, encode_realtime_recv_unit_with_ceiling, RealtimeRecvUnit,
    RealtimeSendUnit, MAX_REALTIME_FLOW_LABEL_BYTES,
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
    /// Pauses one connection task at the instant `EventsSubscribe` becomes a
    /// live stream.
    ///
    /// Past the ack, before the first poll of the stream loop. That is the only
    /// instant at which "this connection is subscribed" and "this connection has
    /// finished with the request that subscribed it" are both true, which is
    /// what a control asserting the request's funding is gone has to stand on. A
    /// barrier at the ack would be a line too early -- the write can still fail
    /// -- and one inside the loop would be a line too late, since the loop only
    /// returns when the stream is over.
    #[cfg(test)]
    at_events_stream_entry: Option<Arc<DispatchBarrier>>,
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

/// Everything that ends one accepted control connection, besides the client.
///
/// A write to a local socket completes when its peer reads it. A same-user
/// client that stops reading can therefore park an accepted task inside
/// `write_all` or `flush` indefinitely, and a client that sends nothing can park
/// one inside a stream receive — neither of which the client is obliged to stop
/// doing because this daemon has begun shutting down. Every long-lived mode on
/// this socket races its work against one of these instead.
///
/// Two owners, not one, because the connection modes genuinely have two. Before
/// an `EventsSubscribe` there is no client record, so the runtime's close signal
/// is the only cancellation there is; after one, the exact client this
/// connection registered is a second and more specific one — the drain removes
/// clients one at a time, and this is how a connection learns that its own was
/// taken.
///
/// Owned rather than borrowed, and cheaply: a `ClientRegistry` and an
/// funded client handle are each one pointer clone. Borrowing would put a
/// lifetime on every writer helper below and buy nothing.
#[derive(Clone)]
pub(super) struct ConnectionCancel {
    clients: crate::ipc::ClientRegistry,
    owner: Option<myownmesh_core::FundedArc<crate::ipc::ClientHandle>>,
}

impl ConnectionCancel {
    /// A connection with no client record of its own.
    fn runtime(clients: &crate::ipc::ClientRegistry) -> Self {
        Self {
            clients: clients.clone(),
            owner: None,
        }
    }

    /// A connection that has registered, and is now ended by its own removal as
    /// well as by the runtime's close.
    ///
    /// This closes the gap the frame mailbox cannot. The connection task holds
    /// its own funded client handle, so the writer sender inside it stays alive
    /// after the registry entry is removed and the mailbox never reports closed.
    /// An idle client on a quiet mesh would otherwise wait forever for a source
    /// that had already been taken away from it, holding an accepted task and
    /// with it the whole drain.
    fn owned_by(
        clients: &crate::ipc::ClientRegistry,
        owner: &myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
    ) -> Self {
        Self {
            clients: clients.clone(),
            owner: Some(owner.clone()),
        }
    }

    /// Resolves when this connection must stop, whatever the socket is doing.
    ///
    /// Both halves are edge-safe on their own: `closing` subscribes before it
    /// reads the lifecycle, and `wait_disconnected` re-checks its flag around
    /// the subscription. A signal that arrived before this future was built
    /// therefore resolves it at once rather than being waited for a second time.
    pub(super) async fn cancelled(&self) {
        match &self.owner {
            Some(owner) => {
                tokio::select! {
                    () = self.clients.closing() => {}
                    () = owner.wait_disconnected() => {}
                }
            }
            None => self.clients.closing().await,
        }
    }
}

/// Tells `serve` that one accepted connection has ended, however it ended.
///
/// A guard rather than a line at the bottom of the task, because a task can end
/// three ways — returning, panicking, and being dropped mid-await — and all
/// three have to reach the join loop. Only a `Drop` covers the last two.
struct ConnectionEnded(Arc<ControlState>);

impl Drop for ConnectionEnded {
    fn drop(&mut self) {
        // Count first, then wake. A waiter woken before the count was published
        // could read zero and conclude there was nothing to reap, which is the
        // one ordering that turns an exact signal back into a hint.
        self.0
            .ended
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        self.0.finished.notify_one();
    }
}

/// What became of one attempt to put a line on this socket.
///
/// `Ended` covers a broken socket and a cancelled write together, deliberately.
/// The caller's answer to both is the same — this connection is over — and the
/// distinction it would otherwise carry is one no caller can act on: a client
/// that stopped reading and a runtime that stopped waiting leave the same
/// unfinished line on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wrote {
    Sent,
    Ended,
}

/// Encode one value, fund the bytes before they exist, and write them — or stop.
///
/// Three steps in one function because they have to happen in one order.
/// [`AdmittedLineOut`] measures the encoding without allocating it and acquires
/// the buffer before building it, so an answer this daemon cannot afford is
/// refused rather than allocated and then noticed. The write is then raced
/// against this connection's cancellation, so the encoded buffer — whose lease
/// lives in the value and is released when it drops — cannot be pinned by a
/// client that has stopped reading.
///
/// A cancelled write may leave a partial line on the socket, and that is the
/// intended terminal answer. A shutdown that depended on a malicious or stalled
/// client accepting a final response would not be terminal at all: where the
/// socket is writable the client gets its typed refusal, and where it is not it
/// gets EOF. No timer chooses between those.
///
/// [`ControlOut`] rather than a generic `Serialize`, because the measurement
/// runs the encoder: the seam is only refusable if counting allocates nothing,
/// and that is a property of a closed set of shapes rather than of a trait
/// bound.
async fn write_line<W>(
    writer: &mut W,
    frames: &FrameAdmission,
    cancel: &ConnectionCancel,
    value: ControlOut<'_>,
) -> Result<Wrote>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let line =
        AdmittedLineOut::encode(value, frames).context("control response was not admitted")?;
    let write = async {
        writer.write_all(line.bytes()).await?;
        writer.flush().await
    };
    // Biased to the *write*, and this is the one place in this module where
    // cancellation is not polled first. The two are only ever both ready when
    // the socket would accept the line without blocking and the runtime is
    // already closing — which is exactly the case the review requires an answer
    // for: where the socket is writable, a pre-commit request receives its typed
    // `Closing` refusal rather than a dropped connection. Polling cancellation
    // first would make that answer a coin toss.
    //
    // Terminality is unaffected, because the bias only decides a tie. A write
    // that cannot make progress returns `Pending`, cancellation is polled next
    // and wins, and every loop that calls this has cancellation polled first in
    // its own select — so no sequence of instantly-writable lines can keep a
    // connection alive past the drain.
    tokio::select! {
        biased;
        result = write => Ok(match result {
            Ok(()) => Wrote::Sent,
            Err(_) => Wrote::Ended,
        }),
        () = cancel.cancelled() => Ok(Wrote::Ended),
    }
}

async fn write_static_error<W>(
    writer: &mut W,
    frames: &FrameAdmission,
    cancel: &ConnectionCancel,
    message: &'static str,
) -> Result<Wrote>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let reply = PreparedReply::StaticError(message);
    write_line(writer, frames, cancel, ControlOut::Prepared(&reply)).await
}

async fn write_admitted_line<W>(
    writer: &mut W,
    cancel: &ConnectionCancel,
    line: AdmittedLineOut,
) -> Result<Wrote>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let write = async {
        writer.write_all(line.bytes()).await?;
        writer.flush().await
    };
    tokio::select! {
        biased;
        result = write => Ok(match result {
            Ok(()) => Wrote::Sent,
            Err(_) => Wrote::Ended,
        }),
        () = cancel.cancelled() => Ok(Wrote::Ended),
    }
}

/// One value a connection-long mode keeps, and the funding for exactly the
/// buffers it owns.
///
/// A subscription or a pipe outlives the request that started it, and what it
/// really retains is a field or two out of that request rather than the decoded
/// tree. Funding those as themselves is what lets the request's own admission be
/// released when the stream begins — and that admission is derived from the
/// *encoded* length, so it is as large as whatever padding the client chose to
/// send.
///
/// Field order is load-bearing in the usual direction: `value` is destroyed
/// before the leases that paid for it.
pub(super) struct Retained<T> {
    value: T,
    _bytes: myownmesh_core::ResourceLease,
    _allocation: myownmesh_core::ResourceLease,
}

impl<T> Retained<T> {
    /// Fund `lengths` buffers totalling their sum, then take ownership.
    ///
    /// `lengths` is supplied rather than derived, because only the caller knows
    /// which of a value's buffers it is keeping. One allocation is counted per
    /// length, on the same reasoning as every other retained claim in this
    /// daemon: a `String` reserves at least its length and the excess is the
    /// allocator's, not this code's to state.
    fn admit(
        value: T,
        lengths: impl IntoIterator<Item = usize>,
        frames: &FrameAdmission,
    ) -> Result<Self> {
        let mut bytes = 0usize;
        let mut allocations = 0u64;
        for length in lengths {
            bytes = bytes
                .checked_add(length)
                .context("retained control field lengths are not representable")?;
            allocations = allocations
                .checked_add(1)
                .context("retained control field count is not representable")?;
        }
        let (bytes, allocation) = frames
            .admit_retained(bytes, allocations)
            .context("the fields this control stream keeps were not admitted")?;
        Ok(Self {
            value,
            _bytes: bytes,
            _allocation: allocation,
        })
    }

    fn admit_building<B>(
        lengths: impl IntoIterator<Item = usize>,
        frames: &FrameAdmission,
        build: B,
    ) -> Result<Self>
    where
        B: FnOnce() -> T,
    {
        let mut bytes = 0usize;
        let mut allocations = 0u64;
        for length in lengths {
            bytes = bytes
                .checked_add(length)
                .context("retained control field lengths are not representable")?;
            allocations = allocations
                .checked_add(1)
                .context("retained control field count is not representable")?;
        }
        let (bytes, allocation) = frames
            .admit_retained(bytes, allocations)
            .context("the fields this control stream keeps were not admitted")?;
        Ok(Self {
            value: build(),
            _bytes: bytes,
            _allocation: allocation,
        })
    }
}

impl<T> std::ops::Deref for Retained<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
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
        finished: tokio::sync::Notify::new(),
        ended: std::sync::atomic::AtomicUsize::new(0),
        mesh,
        registry,
        services,
        clients,
        json_line_bytes,
        realtime_frame_bytes,
        realtime,
        #[cfg(test)]
        before_events_subscribe_commit: hooks.before_events_subscribe_commit,
        #[cfg(test)]
        at_events_stream_entry: hooks.at_events_stream_entry,
    });
    #[cfg(not(test))]
    let _ = hooks;

    // Every accepted connection's join handle, one funded node each.
    //
    // Retained rather than detached, and this is the difference between waiting
    // for a count and joining a task. The count reaching zero says each task's
    // `TaskAdmission` was dropped, which a task ending *or being dropped
    // mid-await* both do; it cannot observe a panic, and a panicking connection
    // task would decrement exactly like a clean one and leave `serve` reporting
    // a tidy close over a connection that had aborted mid-request. Joining
    // observes the `JoinError`.
    //
    // Funded, and not an ordinary `Vec`: the storage is sized by how many
    // connections a local client chose to open, which is the same reason every
    // other collection in this daemon is admitted. One node per live connection
    // rather than per connection ever accepted -- see the reap below.
    let mut accepted: crate::ipc::LeasedList<tokio::task::JoinHandle<()>> =
        crate::ipc::LeasedList::new();

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                info!("control socket shutting down");
                break;
            }
            // A connection ended. Reaping is driven by completion rather than
            // by the next accept, so a listener that goes quiet after its last
            // client leaves does not keep that connection's funding charged
            // until shutdown. `join_finished` waits out the finalization the
            // signal races; see its own note for why that wait terminates
            // without a timer.
            () = state.finished.notified() => {
                join_finished(&state.ended, &mut accepted).await;
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
                        // Connections that have already ended, joined and
                        // released before another is funded. No lock is held
                        // here and none is needed: this list belongs to the
                        // control task alone. Without it the daemon would hold
                        // one funded node per connection it had *ever* accepted
                        // and would eventually refuse a live client on behalf of
                        // tasks that finished hours ago.
                        join_finished(&state.ended, &mut accepted).await;
                        // The node that will hold this connection's handle,
                        // funded before the task it will name exists. Refused,
                        // the connection is closed here rather than spawned into
                        // a handle nothing could join -- which is the detached
                        // task this whole list exists to remove.
                        let node = match crate::ipc::LeasedList::<
                            tokio::task::JoinHandle<()>,
                        >::node_claim()
                        .map_err(crate::ipc::clients::IpcAdmissionError::Claim)
                        .and_then(|claim| state.clients.acquire_claim(claim))
                        {
                            Ok(node) => node,
                            Err(refusal) => {
                                warn!(
                                    "control connection refused, its join could not be \
                                     retained: {refusal}"
                                );
                                drop(task);
                                drop(stream);
                                continue;
                            }
                        };
                        let ended = ConnectionEnded(state.clone());
                        let state = state.clone();
                        let join = tokio::spawn(async move {
                            // Declared first so it is dropped last: the
                            // completion signal is the final thing this task
                            // does, after its funding has been released.
                            let _ended = ended;
                            // Moved in, so the lease is released exactly when
                            // this task stops — including if it is dropped
                            // mid-await rather than returning.
                            let _task = task;
                            if let Err(e) = handle_client(stream, state).await {
                                debug!("control client error: {e:#}");
                            }
                        });
                        accepted.push(join, node);
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
    //    Closed rather than dropped, and the difference is no longer that
    //    dropping releases nothing: a `RealtimeFlowHandle`'s own Drop performs
    //    exact flow cleanup now. Explicit close is still the stronger of the
    //    two, because it awaits the native retirement and can report what it
    //    found, where Drop is the non-blocking backstop for the paths that
    //    cannot await one. A shutdown that reports the control surface closed
    //    should have waited for the native halves rather than left them
    //    retiring behind it.
    //
    // 4. And only then does this return. `serve` returning is a claim that the
    //    control surface is over, and it was not true before: a connection task
    //    outliving it would still be holding a registry, a mesh handle and a
    //    socket that this function's caller is entitled to treat as finished
    //    with. Joining every retained connection handle is what makes the claim
    //    true; the task count that follows is the weaker, wider check, and it
    //    covers what this list does not — the channel pumps and inbound-stream
    //    watchdogs the registry admitted on those connections' behalf. A count
    //    alone never made the claim: it decrements identically for a task that
    //    returned and one that panicked.
    //
    //    The wait terminates because every long-lived mode observes step 1's
    //    signal: an events stream, a trace stream, a realtime pipe and every
    //    socket write are each raced against the runtime's close, and a
    //    registered client's connection is raced against its own removal in
    //    step 3 as well. Without those the count could stay above zero for as
    //    long as an idle client chose to stay connected, and this wait would be
    //    the hang rather than the join.
    if state.clients.begin_closing() {
        // One client at a time, released before the next is taken, and asked for
        // one at a time too. The registry answers an id rather than a record for
        // exactly this reason: a record carries the client's retired routes and
        // forgotten names, so collecting every one of them first would hold
        // every client's cleanup state at once instead of one client's. And it
        // answers one id rather than all of them because a snapshot of every
        // connected client is an allocation sized by how many connected —
        // `unregister` removes what this answered, so asking again is what
        // makes progress rather than a list to walk.
        while let Some(client) = state.clients.shutdown_next() {
            match state.clients.unregister(client) {
                Some(removed) => release_owned_registrations(&state, removed).await,
                // Removed by something else between the two calls. The table no
                // longer holds it, so the next question moves past it.
                None => continue,
            }
        }
        state.clients.shutdown_settle_pending();
    }
    // Every accepted connection, joined. This is the claim `serve` returning
    // makes, and a decrementing counter cannot make it: a task that panicked
    // released its admission exactly like one that returned. Each node is freed
    // before its own funding is released, and the list is empty by the time this
    // returns.
    join_all(&mut accepted).await;
    // And then the count, which covers what this list does not: the channel
    // pumps and inbound-stream watchdogs the registry admitted on connections'
    // behalf. It should already be zero -- retiring a route joins its pump --
    // and waiting on it is what makes that a checked fact rather than an
    // assumption.
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

/// Join every accepted connection that has already finished.
///
/// **Awaited, never dropped.** Dropping a finished `JoinHandle` detaches it and
/// discards its `JoinError`, so a connection task that panicked would be
/// indistinguishable from one that returned — which is the whole reason these
/// handles are retained rather than merely counted. A dropped finished handle is
/// not a join.
///
/// Split first, so the awaits happen over a list of this function's own rather
/// than during a walk of the one `serve` is still adding to. Each handle's node
/// is freed and its funding released as it is popped.
///
/// **Waits out finalization rather than looking once.** `ended` counts tasks
/// that have run their completion guard and not yet been joined, and that guard
/// runs *inside* the task's future — so a handle can be counted here and still
/// report `is_finished() == false` for the moment it takes the runtime to
/// finalize it. Looking once would consume the wake, find nothing, and leave
/// that connection's funded node charged until the next completion, the next
/// accept, or shutdown; on a listener that has gone quiet after its last client
/// left, that is until shutdown.
///
/// The spin has an exact, non-timer termination condition, and the count is what
/// supplies it: a nonzero `ended` means some handle *already ran its guard*, and
/// a handle is only removed from `accepted` by being joined here, so that handle
/// is still in the list and will report finished. Every iteration either extracts
/// at least one — which decrements — or yields the runtime the step it needs.
/// Nothing waits on elapsed time and no bound is invented.
///
/// The two arms that call this are arms of one select in one task, so a task
/// spawned in the accept arm is always pushed before the completion arm can be
/// polled; there is no counted guard whose handle is not yet in the list. The
/// empty-list check is a backstop for that invariant rather than the mechanism.
///
/// Answers how many ended abnormally, so a control can observe that this joins
/// rather than discards — the two are otherwise identical from outside.
async fn join_finished(
    ended: &std::sync::atomic::AtomicUsize,
    accepted: &mut crate::ipc::LeasedList<tokio::task::JoinHandle<()>>,
) -> usize {
    let mut abnormal = 0;
    loop {
        if ended.load(std::sync::atomic::Ordering::Acquire) == 0 || accepted.is_empty() {
            return abnormal;
        }
        let mut finished = accepted.split_where(|join| join.is_finished());
        let reaped = finished.len();
        if reaped == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        // Never more than were counted: a handle reports finished only after its
        // own guard ran, and each handle is joined exactly once.
        ended.fetch_sub(reaped, std::sync::atomic::Ordering::AcqRel);
        abnormal += join_all(&mut finished).await;
    }
}

/// Join everything in `handles`, whether it has finished or not, and answer how
/// many ended abnormally.
async fn join_all(handles: &mut crate::ipc::LeasedList<tokio::task::JoinHandle<()>>) -> usize {
    let mut abnormal = 0;
    while let Some(join) = handles.pop() {
        if let Err(e) = join.await {
            abnormal += 1;
            warn!("control connection task did not end cleanly: {e}");
        }
    }
    abnormal
}

struct ControlState {
    /// Woken when one accepted connection task ends, however it ends.
    ///
    /// The reap signal. Without it a finished connection's funded join node is
    /// released only by the *next* accept, so a daemon whose listener goes quiet
    /// after a client disconnects keeps that node charged for as long as the
    /// quiet lasts — funding held on behalf of a task that ended.
    ///
    /// Here rather than in a new `Arc`, because every connection task already
    /// holds one of these: the signal costs a `Notify` in a struct that exists,
    /// and no allocation at all.
    ///
    /// `notify_one` rather than `notify_waiters`, deliberately: it stores a
    /// permit when nobody is waiting, so a completion landing between two polls
    /// of the accept loop is consumed by the next poll rather than lost. One
    /// permit is enough because the reap drains *every* finished handle rather
    /// than one.
    finished: tokio::sync::Notify,
    /// How many connection tasks have signalled completion and not yet been
    /// joined.
    ///
    /// The wake alone is not enough, and this is what makes the reap exact
    /// rather than opportunistic. A task signals from a drop guard *inside* its
    /// own future, so at the instant the signal lands its `JoinHandle` is not
    /// yet finalized and reports `is_finished() == false`. A reap that looked
    /// once and gave up would consume the permit, find nothing, and — on a
    /// listener that then went quiet — leave that connection's funded node
    /// charged until shutdown.
    ///
    /// A nonzero count is a *causal* guarantee that some retained handle is in
    /// finalization, which is what gives [`join_finished`] an exact termination
    /// condition to spin on instead of a duration. Incremented by the guard,
    /// decremented by the join that consumes it, so it can only be nonzero while
    /// there is really something to reap.
    ended: std::sync::atomic::AtomicUsize,
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    clients: crate::ipc::ClientRegistry,
    realtime: RealtimeAdvert,
    json_line_bytes: Option<usize>,
    realtime_frame_bytes: Option<usize>,
    #[cfg(test)]
    before_events_subscribe_commit: Option<Arc<DispatchBarrier>>,
    /// See [`ControlHooks::at_events_stream_entry`].
    #[cfg(test)]
    at_events_stream_entry: Option<Arc<DispatchBarrier>>,
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
    // What ends this connection besides its own client. Rebound to the exact
    // client inside the modes that register one; until then the runtime's close
    // signal is the only cancellation a connection with no record can have.
    let cancel = ConnectionCancel::runtime(&state.clients);
    loop {
        let line = tokio::select! {
            biased;
            () = state.clients.closing() => break,
            line = read_bounded_json_line(reader.frames(), &json_lines) => match line? {
                Some(line) => line,
                None => break,
            },
        };
        // Funded before the parse runs, and what comes back is the *retention*
        // alone: the parse work is acquired, spent and released inside
        // `decode_request`, so the padded worst case of a line's parse and CPU
        // claim cannot be pinned by whatever the request turns into. The
        // move-only owner that comes back declares the request first and its
        // retention last, so the lease outlives the decoded tree on every drop
        // path without relying on a caller's binding order.
        let admitted = match line.decode_request(&json_lines) {
            Ok(decoded) => decoded,
            Err(DecodeRefusal::Malformed(e)) => {
                let text = PreparedText::json_parse_error(&e, &json_lines)
                    .context("parse refusal text was not admitted")?;
                let resp = PreparedReply::Error(text);
                match write_line(
                    &mut writer,
                    &json_lines,
                    &cancel,
                    ControlOut::Prepared(&resp),
                )
                .await?
                {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Err(refusal @ DecodeRefusal::Admission(_)) => {
                let text = PreparedText::decode_admission_error(&refusal, &json_lines)
                    .context("parse-admission refusal text was not admitted")?;
                let resp = PreparedReply::Error(text);
                match write_line(
                    &mut writer,
                    &json_lines,
                    &cancel,
                    ControlOut::Prepared(&resp),
                )
                .await?
                {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
        };
        // The raw line's bytes are dead weight from here -- the decoded request
        // owns its own copies -- so the byte leases go now while the retention
        // above stays with what it funds.
        drop(line);
        // This is the one closed consumption boundary for decoded control
        // state. The retention is still a named owner after the request moves
        // into the exhaustive matches below; connection-converting arms drop it
        // explicitly after funding their successor, and the ordinary path keeps
        // it through `dispatch` and the response write.
        let AdmittedRequest {
            request,
            _retention: decoded,
        } = admitted;
        // Taken by value, and the three connection-converting variants are
        // handled here rather than through `dispatch`, because each of them
        // starts something that outlives the request. Each releases `decoded`
        // before its stream begins, having first funded the one or two fields it
        // is actually keeping. Everything else falls through with its funding
        // intact, which is correct: an ordinary request is still being processed
        // for exactly as long as its decoded tree is alive.
        let request = match request {
            // EventsSubscribe converts the connection into a server-push
            // channel: the daemon writes mesh events plus any IPC-routed frames
            // (RpcInbound, ChannelInbound, ...) until the client disconnects. A
            // ClientId is allocated so subsequent RPC/channel-management
            // requests on OTHER command sockets can target this connection.
            Request::EventsSubscribe => {
                // Nothing of the request survives this line. `events_subscribe`
                // carries no fields, so there is no field to move anywhere and
                // no retention to acquire -- a padded one funds nothing at all
                // past here.
                drop(decoded);
                // One acquisition subtree per event-subscribed connection.
                // `local_application_resource_scope` already issues a child of
                // the runtime's owner, so this connection's queued frames are
                // accounted as their own subtree and every byte behind them is
                // released when both mailbox ends drop at disconnect -- without
                // the daemon naming a frame count anywhere.
                let scope = state
                    .mesh
                    .local_application_resource_scope()
                    .context("issue this client's local application resource scope")?;
                let (tx, rx) = myownmesh_core::resource_mailbox(scope)
                    .context("fund this client's outbound frame mailbox")?;
                // Registration is an admission now. A refusal is answered on
                // this connection rather than raised: the socket is healthy and
                // the client is entitled to know why it was not subscribed,
                // whereas returning would drop the connection and leave it
                // guessing.
                // The seam is here and not a line earlier or later. Above it the
                // mailbox is funded and the scope issued but nothing is filed;
                // below it the client is in the table. A control that paused
                // anywhere else would be asserting about a different race.
                #[cfg(test)]
                if let Some(barrier) = &state.before_events_subscribe_commit {
                    barrier.pass().await;
                }
                let output = AdmittedLineOut::prepare_capacity(
                    events_subscribed_line_ceiling()?,
                    &json_lines,
                )
                .context("events-subscribe response capacity was not admitted")?;
                let client = match state.clients.register(tx) {
                    Ok(client) => client,
                    Err(refusal) => {
                        drop(output);
                        let text = PreparedText::events_registration_error(&refusal, &json_lines)
                            .context("events-subscribe refusal text was not admitted")?;
                        let resp = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&resp),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let client_id = client.id;
                // From here the exact client is a cancellation owner too. See
                // [`ConnectionCancel::owned_by`]: the mailbox alone cannot end
                // this task, because this task is holding the handle its sender
                // lives in.
                let cancel = ConnectionCancel::owned_by(&state.clients, &client);
                // Ack carries the client_id so the caller knows what to pass
                // back on subsequent `client_id`-bearing ops.
                let ack = PreparedReply::EventsSubscribed(client.clone());
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&ack), output)
                    .context("events-subscribe response exceeded its structural ceiling")?;
                let result = match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => {
                        // The subscription is live and the request that opened
                        // it is finished with. See
                        // [`ControlHooks::at_events_stream_entry`].
                        #[cfg(test)]
                        if let Some(barrier) = &state.at_events_stream_entry {
                            barrier.pass().await;
                        }
                        run_events_stream(
                            &json_lines,
                            &cancel,
                            &mut writer,
                            rx,
                            state.mesh.events(),
                        )
                        .await
                    }
                    // The client never learned its own id, so there is nothing
                    // for it to do with the subscription. Cleanup below is the
                    // same either way.
                    Wrote::Ended => Ok(()),
                };
                // Clean up the client's claims regardless of how the stream
                // ended.
                //
                // What comes back is what the registry cannot release on its
                // own: the handle, whose realtime flows are closed through their
                // own networks rather than merely dropped -- explicit close
                // awaits the native retirement and can report it, where the
                // handle's own Drop is the non-blocking backstop -- and the
                // methods this client was the last claimant of, whose synthetic
                // handlers are still installed. This is the one place that knows
                // both those and the networks to reach them through.
                //
                // `None` means something else already removed this client, and
                // that something else is the shutdown sweep, which does the same
                // release with the same handle. Doing nothing here is not
                // skipping the work.
                if let Some(removed) = state.clients.unregister(client_id) {
                    release_owned_registrations(&state, removed).await;
                }
                result?;
                break;
            }
            // TraceSubscribe is the same server-push pattern as EventsSubscribe
            // but carries only ConnTrace records and needs no ClientId (it
            // routes nothing back in). An unknown network is reported as a plain
            // error response and the connection stays open for another request.
            Request::TraceSubscribe { network } => {
                // The one field this stream keeps, funded as itself before the
                // request's own funding is released -- so the buffer is never
                // live unaccounted, and a padded `trace_subscribe` reserves the
                // network name and nothing else for the subscription's life.
                let lengths = [network.len()];
                let network = Retained::admit(network, lengths, &json_lines)?;
                drop(decoded);
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let resp = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&resp),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let ack = PreparedReply::TraceSubscribed {
                    network: PreparedText::copying(&network, &json_lines)
                        .context("trace-subscribe response text was not admitted")?,
                };
                let rx = net.state().subscribe_conn_trace();
                // A trace client has no registry entry to be unregistered, so
                // the runtime's close is its only cancellation -- and without
                // one, a connected trace client on a quiet network held the
                // whole drain open.
                match write_line(
                    &mut writer,
                    &json_lines,
                    &cancel,
                    ControlOut::Prepared(&ack),
                )
                .await?
                {
                    Wrote::Sent => run_trace_stream(&json_lines, &cancel, &mut writer, rx).await?,
                    Wrote::Ended => {}
                }
                break;
            }
            // RealtimePipe converts the connection into a one-way binary stream
            // of realtime units, the EventsSubscribe pattern in whichever
            // direction was asked for. After the ack the connection speaks only
            // length-prefixed binary frames -- no per-frame JSON, no base64.
            Request::RealtimePipe {
                direction,
                network,
                peer,
                client_id,
                client_capability,
                flow_capability,
            } => {
                // Field shapes are checked before the ack, and extras are
                // refused rather than ignored. A pipe that acked and then
                // behaved as though a field had not been sent would be
                // indistinguishable, from the client's side, from one that
                // honoured it.
                let plan = match realtime_pipe_binding_plan(
                    direction,
                    &network,
                    peer.as_deref(),
                    flow_capability.as_deref(),
                ) {
                    Ok(plan) => plan,
                    Err(message) => {
                        let resp = PreparedReply::StaticError(message);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&resp),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                // Both directions are owned now. Inbound has always needed an
                // owner to end with; outbound needs one because the flow it
                // writes to belongs to a client, and the client capability is
                // what proves this connection is that client.
                let pipe_owner = {
                    let (Some(client_id), Some(capability)) =
                        (client_id, client_capability.as_deref())
                    else {
                        match write_static_error(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            "realtime_pipe requires client_id and client_capability: a pipe \
                             is owned by the client that opened its flow, and possession of \
                             the capability is what proves this connection is that client",
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    };
                    let Some(owner) = state.clients.authenticate(client_id, capability) else {
                        match write_static_error(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            "invalid local client authority",
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    };
                    owner
                };
                // The binding made its own copies of the two coordinates it
                // keeps, and those are all the pipe retains. Funded as
                // themselves here, and only then is the decoded request -- whose
                // claim is sized by the encoded line rather than by these two
                // strings -- released. The capability was consumed by the
                // authentication above and the rest was never needed past this
                // point, so all of it goes together and the funding goes last.
                let lengths = plan.retained_lengths();
                let bound = Retained::admit_building(lengths, &json_lines, || plan.build())?;
                drop((network, peer, client_capability, flow_capability, decoded));
                // The pipe's owner is a real client, so this connection ends on
                // its disconnect or on the runtime's close, whichever comes
                // first.
                let cancel = ConnectionCancel::owned_by(&state.clients, &pipe_owner);
                // Borrowed, not cloned. The binding already owns this name and
                // the lookup only reads it; the copy this used to take was a
                // third live allocation of a client-chosen string, and removing
                // it is a better answer than funding it.
                let Some(net) = state.registry.get(bound.network()) else {
                    let text = PreparedText::unknown_network(bound.network(), &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let resp = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&resp),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                // An inbound pipe claims the session's unit stream BEFORE the
                // ack. The claim is once per session, so it can legitimately
                // fail -- a second pipe for the same peer, or a session that is
                // already gone -- and those must be refusals, not an ack
                // followed by a connection that silently never delivers
                // anything.
                //
                // The claim is an exclusive lease, and the reader IS the lease:
                // dropping it returns it. So when this pipe ends -- cleanly, or
                // because the client crashed and its socket died -- the next
                // pipe for the same session claims successfully and resumes.
                // Nothing is lost in the gap, because units accumulate on the
                // session's own queue and never in the reader.
                //
                // Which is why the daemon caches nothing here. Holding a reader
                // across reconnects, or remembering which sessions were claimed,
                // would give the daemon a lease to release correctly and a
                // mirror to keep in step. The lease already releases itself, and
                // the queue it guards belongs to the session.
                //
                // A refusal therefore means what it says: the session is gone,
                // or a pipe for it is live right now. Neither is a lingering
                // claim from a pipe that has already died.
                //
                // An outbound pipe proves its flow before the ack for the mirror
                // reason: a client that acked and then found every unit refused
                // would have to discover from silence that its capability was
                // wrong.
                let inbound_stream = match &*bound {
                    RealtimePipeBinding::Inbound { peer, .. } => match net.realtime_inbound(peer) {
                        Some(stream) => Some(stream),
                        None => {
                            let text = PreparedText::no_inbound_realtime_stream(peer, &json_lines)
                                .context("realtime-stream refusal text was not admitted")?;
                            let resp = PreparedReply::Error(text);
                            match write_line(
                                &mut writer,
                                &json_lines,
                                &cancel,
                                ControlOut::Prepared(&resp),
                            )
                            .await?
                            {
                                Wrote::Sent => continue,
                                Wrote::Ended => break,
                            }
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
                            match write_static_error(
                                &mut writer,
                                &json_lines,
                                &cancel,
                                "unknown flow_capability on this network: it was never issued \
                                 to this client, or the flow it named has already been closed",
                            )
                            .await?
                            {
                                Wrote::Sent => continue,
                                Wrote::Ended => break,
                            }
                        }
                        None
                    }
                };
                let ack = PreparedReply::Bool {
                    key: "realtime_pipe",
                    value: true,
                };
                match write_line(
                    &mut writer,
                    &json_lines,
                    &cancel,
                    ControlOut::Prepared(&ack),
                )
                .await?
                {
                    Wrote::Sent => {}
                    Wrote::Ended => break,
                }
                // Recover the buffered reader — it may already hold the first
                // frame.
                let pipe = async {
                    match (inbound_stream, &*bound) {
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
                                // The frames, not the admitted reader. Handing
                                // the wrapper over would move it, and its leases
                                // fund the buffer these bytes arrive in -- the
                                // pipe would be reading from an allocation whose
                                // funding had travelled with a value it does not
                                // know it owns. Borrowing leaves the owner here,
                                // alive for exactly as long as the pipe runs.
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
                        // Unreachable by construction — the claim above is taken
                        // on exactly the inbound arm — and spelled as a refusal
                        // rather than a panic, because a control connection
                        // failing closed is always preferable to a daemon that
                        // stops.
                        _ => Ok(()),
                    }
                };
                // The pipe's own writes are inside `pipe`, so this one select
                // ends them as well as the pump: a client that stops reading an
                // inbound pipe cannot hold the drain inside a frame write.
                let result = tokio::select! {
                    biased;
                    () = cancel.cancelled() => Ok(()),
                    result = pipe => result,
                };
                result?;
                break;
            }
            other => other,
        };
        let request = match request {
            Request::Status => {
                let (status, output) = {
                    let source = state
                        .registry
                        .status_source(state.mesh.identity(), &state.realtime);
                    let typed_claim = source
                        .typed_claim()
                        .context("status typed claim was not representable")?;
                    let line_ceiling = source
                        .line_ceiling()
                        .context("status line ceiling was not representable")?;
                    let (committed, output) = prepare_typed_and_line_building(
                        typed_claim,
                        line_ceiling,
                        &json_lines,
                        |typed| source.commit(typed),
                    )
                    .context("status snapshot or response line was not admitted")?;
                    let status = committed
                        .map_err(|_| anyhow::anyhow!("status typed claim changed before commit"))?;
                    (status, output)
                };
                let reply = PreparedReply::Status(status);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("status response exceeded its measured ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworksList => {
                let plan = state
                    .registry
                    .prepare_networks_list()
                    .context("NetworksList capacity was not representable")?;
                let typed = json_lines
                    .acquire_claim(plan.typed_claim())
                    .context("NetworksList typed snapshot was not admitted")?;
                let work = json_lines
                    .acquire_claim(plan.work_claim())
                    .context("NetworksList snapshot work was not admitted")?;
                let plan = plan
                    .measure_line_ceiling(&work)
                    .context("NetworksList line capacity was not representable")?;
                let output = AdmittedLineOut::prepare_capacity(plan.line_ceiling(), &json_lines)
                    .context("NetworksList response line was not admitted")?;
                let networks = plan.commit(typed, work).map_err(|_| {
                    anyhow::anyhow!(
                        "NetworksList changed shape while its funded snapshot was built"
                    )
                })?;
                let reply = PreparedReply::Networks(networks);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("NetworksList response exceeded its measured ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            request @ (Request::IdentityShow | Request::IdentitySetLabel { .. }) => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("identity response was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("identity operation lease did not match"))?;
                let result = match request {
                    Request::IdentityShow => Ok(OperationReplyData::Identity {
                        device_id: state.mesh.identity().display_id(),
                        pubkey: state.mesh.identity().public_id().to_owned(),
                        label: state.mesh.identity().label().to_owned(),
                    }),
                    Request::IdentitySetLabel { label } => {
                        match myownmesh_core::identity::set_label(&label) {
                            Err(error) => Err(error.to_string()),
                            Ok(()) => {
                                state.mesh.identity().set_label(&label);
                                Ok(OperationReplyData::Identity {
                                    device_id: state.mesh.identity().display_id(),
                                    pubkey: state.mesh.identity().public_id().to_owned(),
                                    label: state.mesh.identity().label().to_owned(),
                                })
                            }
                        }
                    }
                    _ => unreachable!(),
                };
                let variable = plan.finish(result);
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("identity response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("identity response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            request @ (Request::RealtimeFlowOpen { .. } | Request::RealtimeFlowClose { .. }) => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("realtime operation result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("realtime operation lease did not match"))?;
                let variable = dispatch::dispatch_realtime_funded(&state, request, plan).await;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("realtime response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("realtime response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            request @ Request::RpcCallStream { .. } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("RPC stream setup result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("RPC stream setup lease did not match"))?;
                let variable =
                    dispatch::dispatch_rpc_stream_funded(&state, &cancel, request, plan).await;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("RPC stream setup response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("RPC stream setup response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::PeersList { network } => {
                let Some(joined) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("PeersList lookup refusal text was not admitted")?;
                    let reply = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&reply),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let staging = joined.plan_peers();
                let membership = json_lines
                    .acquire_claim(
                        staging
                            .membership_claim()
                            .context("PeersList membership claim was not representable")?,
                    )
                    .context("PeersList membership staging was not admitted")?;
                let plan = staging
                    .stage(membership)
                    .context("PeersList membership changed while it was staged")?;
                let full_line_ceiling =
                    AdmittedLineOut::peers_capacity(plan.encoded_line_ceiling())
                        .context("PeersList response line capacity was not representable")?;
                let work = json_lines
                    .acquire_claim(plan.work_claim())
                    .context("PeersList snapshot work was not admitted")?;
                let typed = json_lines
                    .acquire_claim(plan.typed_retention_claim())
                    .context("PeersList typed snapshot was not admitted")?;
                let peer_output = json_lines
                    .acquire_claim(plan.output_retention_claim())
                    .context("PeersList peer output was not admitted")?;
                let peer_line = json_lines
                    .acquire_claim(plan.line_claim())
                    .context("PeersList raw array was not admitted")?;
                let output = AdmittedLineOut::prepare_capacity(full_line_ceiling, &json_lines)
                    .context("PeersList daemon response line was not admitted")?;
                let peers = plan
                    .commit(work, typed, peer_output, peer_line)
                    .context("PeersList changed while its funded snapshot was built")?;
                let line = AdmittedLineOut::encode_peers(peers, output)
                    .context("PeersList response exceeded its measured ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::RosterList { network } => {
                let Some(joined) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("RosterList lookup refusal text was not admitted")?;
                    let reply = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&reply),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let source = VariableReplySource::roster(
                    joined
                        .prepare_roster_snapshot()
                        .context("RosterList snapshot was not representable")?,
                );
                let typed = json_lines
                    .acquire_claim(source.typed_claim())
                    .context("RosterList typed snapshot was not admitted")?;
                let line_ceiling = variable_data_reply_line_ceiling(source.data_ceiling()?)?;
                let output = AdmittedLineOut::prepare_capacity(line_ceiling, &json_lines)
                    .context("RosterList response line was not admitted")?;
                let roster = source.commit(typed).await?;
                let reply = PreparedReply::Variable(roster);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("RosterList response exceeded its measured ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::GovernanceState { network } => {
                let Some(joined) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("GovernanceState lookup refusal text was not admitted")?;
                    let reply = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&reply),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let source = VariableReplySource::governance(
                    joined
                        .prepare_governance_snapshot()
                        .await
                        .context("GovernanceState capacity could not be measured")?,
                );
                let typed = json_lines
                    .acquire_claim(source.typed_claim())
                    .context("GovernanceState typed snapshot was not admitted")?;
                let line_ceiling = variable_data_reply_line_ceiling(source.data_ceiling()?)?;
                let output = AdmittedLineOut::prepare_capacity(line_ceiling, &json_lines)
                    .context("GovernanceState response line was not admitted")?;
                let governance = source.commit(typed).await?;
                let reply = PreparedReply::Variable(governance);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("GovernanceState response exceeded its measured ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            request @ (Request::RosterApprove { .. }
            | Request::RosterRemove { .. }
            | Request::TopologySet { .. }
            | Request::GovernanceProposeKindChange { .. }
            | Request::GovernanceProposeRoleGrant { .. }
            | Request::GovernanceProposeRoleRevoke { .. }
            | Request::GovernanceProposeEvict { .. }
            | Request::GovernanceProposeTopology { .. }
            | Request::GovernanceSign { .. }
            | Request::GovernanceDeny { .. }
            | Request::GovernanceWithdraw { .. }
            | Request::GovernanceSpawnSplit { .. }) => {
                let operation = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("governance/network operation result was not admitted")?;
                let result: std::result::Result<OperationReplyData, String> = match request {
                    Request::RosterApprove {
                        network,
                        device_id,
                        label,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .roster_approve(&device_id, label.as_deref().unwrap_or(""))
                            .await
                            .map(|_| OperationReplyData::Approved(device_id))
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::RosterRemove { network, device_id } => {
                        match state.registry.get(&network) {
                            Some(net) => net
                                .roster_remove(&device_id)
                                .await
                                .map(|_| OperationReplyData::Removed(device_id))
                                .map_err(|error| error.to_string()),
                            None => Err(format!("unknown network: {network}")),
                        }
                    }
                    Request::TopologySet {
                        network,
                        topology,
                        hub,
                    } => match dispatch::network::parse_topology(&topology, hub.as_deref()) {
                        Err(error) => Err(error),
                        Ok(mode) => match state.registry.get(&network) {
                            None => Err(format!("unknown network: {network}")),
                            Some(net) => {
                                if net
                                    .governance_state()
                                    .await
                                    .is_ok_and(|governance| governance.topology.is_some())
                                {
                                    Err("this network's topology is governed by a signed owner transition — propose a change instead (`networks topology-propose` / GovernanceProposeTopology)".to_owned())
                                } else {
                                    net.set_topology(mode)
                                        .await
                                        .map(|_| OperationReplyData::Topology(topology))
                                        .map_err(|error| error.to_string())
                                }
                            }
                        },
                    },
                    Request::GovernanceProposeKindChange {
                        network,
                        to,
                        mfa_code,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .propose_transition(
                                myownmesh_core::TransitionVariant::KindChange { to },
                                mfa_code,
                            )
                            .await
                            .map(OperationReplyData::ProposalId)
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceProposeRoleGrant {
                        network,
                        target,
                        role,
                        mfa_code,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .propose_transition(
                                myownmesh_core::TransitionVariant::RoleGrant { target, role },
                                mfa_code,
                            )
                            .await
                            .map(OperationReplyData::ProposalId)
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceProposeRoleRevoke {
                        network,
                        target,
                        mfa_code,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .propose_transition(
                                myownmesh_core::TransitionVariant::RoleRevoke { target },
                                mfa_code,
                            )
                            .await
                            .map(OperationReplyData::ProposalId)
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceProposeEvict {
                        network,
                        target,
                        mfa_code,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .propose_transition(
                                myownmesh_core::TransitionVariant::Evict { target },
                                mfa_code,
                            )
                            .await
                            .map(OperationReplyData::ProposalId)
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceProposeTopology {
                        network,
                        topology,
                        hub,
                        mfa_code,
                    } => match dispatch::network::parse_topology(&topology, hub.as_deref()) {
                        Err(error) => Err(error),
                        Ok(mode) => match state.registry.get(&network) {
                            Some(net) => net
                                .propose_transition(
                                    myownmesh_core::TransitionVariant::TopologyChange { to: mode },
                                    mfa_code,
                                )
                                .await
                                .map(OperationReplyData::ProposalId)
                                .map_err(|error| error.to_string()),
                            None => Err(format!("unknown network: {network}")),
                        },
                    },
                    Request::GovernanceSign {
                        network,
                        proposal_id,
                        mfa_code,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .sign_proposal(&proposal_id, mfa_code)
                            .await
                            .map(|_| OperationReplyData::Signed(proposal_id))
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceDeny {
                        network,
                        proposal_id,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .deny_proposal(&proposal_id)
                            .await
                            .map(|_| OperationReplyData::Denied(proposal_id))
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceWithdraw {
                        network,
                        proposal_id,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .withdraw_proposal(&proposal_id)
                            .await
                            .map(|_| OperationReplyData::Withdrawn(proposal_id))
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    Request::GovernanceSpawnSplit {
                        network,
                        proposal_id,
                    } => match state.registry.get(&network) {
                        Some(net) => net
                            .spawn_split(&proposal_id)
                            .await
                            .map(OperationReplyData::NewNetworkId)
                            .map_err(|error| error.to_string()),
                        None => Err(format!("unknown network: {network}")),
                    },
                    _ => unreachable!("grouped governance/network operation"),
                };
                let variable = FundedVariableReply::operation(result, operation).map_err(|_| {
                    anyhow::anyhow!("governance/network operation lease did not match")
                })?;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("governance/network response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("governance/network response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkReconnect { network, peer } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("network reconnect result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("network operation lease did not match"))?;
                let variable = dispatch::network::network_reconnect(&state, &network, peer, plan);
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("network reconnect response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("network reconnect response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkAdd { config } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("network add result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("network operation lease did not match"))?;
                let variable = dispatch::network::network_add(&state, config, plan).await;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("network add response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("network add response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkRemove { network, purge } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("network remove result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("network operation lease did not match"))?;
                let variable =
                    dispatch::network::network_remove(&state, &network, purge, plan).await;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("network remove response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("network remove response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkUpdate { config } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("network update result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("network operation lease did not match"))?;
                let variable = dispatch::network::network_update(&state, config, plan).await;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("network update response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("network update response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            request @ (Request::ForgetAllNetworks | Request::FactoryReset) => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("network reset result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("network operation lease did not match"))?;
                let variable = match request {
                    Request::ForgetAllNetworks => {
                        dispatch::network::forget_all_networks(&state, plan).await
                    }
                    Request::FactoryReset => dispatch::network::factory_reset(&state, plan).await,
                    _ => unreachable!(),
                };
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("network reset response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("network reset response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkConnectPeer {
                network,
                peer,
                pin,
                wait_ms,
            } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("network connect result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("network operation lease did not match"))?;
                let variable = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    result = dispatch::network::network_connect_peer(&state, &network, &peer, pin, wait_ms, plan) => result,
                };
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("network connect response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("network connect response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::UpdateStatus => {
                let plan = myownmesh_updater::prepare_operation();
                let lease = json_lines
                    .acquire_claim(plan.claim())
                    .context("updater status operation was not admitted")?;
                let funded = plan.run(lease, myownmesh_updater::status).map_err(|_| {
                    anyhow::anyhow!("updater operation lease did not match its plan")
                })?;
                let variable = FundedVariableReply::updater_status(funded);
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("updater status response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("updater status response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::UpdateApply => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("updater apply result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("updater apply lease did not match"))?;
                let variable = plan.finish(match myownmesh_updater::apply_now() {
                    Ok(applied) => Ok(OperationReplyData::Applied(applied)),
                    Err(error) => Err(error.to_string()),
                });
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("updater apply response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("updater apply response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::RpcCall {
                network,
                peer,
                method,
                payload,
            } => {
                let Some(joined) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("RpcCall lookup refusal text was not admitted")?;
                    let reply = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&reply),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let operation = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("RpcCall result operation was not admitted")?;
                let rpc = joined.rpc();
                let result = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    result = rpc.call_funded(&peer, &method, payload) => result,
                };
                let variable = FundedVariableReply::rpc_call(result, operation)
                    .map_err(|_| anyhow::anyhow!("RpcCall operation lease did not match"))?;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("RpcCall response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("RpcCall response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::UpdateCheck => {
                let plan = myownmesh_updater::prepare_operation();
                let lease = json_lines
                    .acquire_claim(plan.claim())
                    .context("updater check operation was not admitted")?;
                let funded = plan
                    .run_async(lease, myownmesh_updater::check_now(true))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("updater operation lease did not match its plan")
                    })?;
                let variable = FundedVariableReply::updater_check(funded);
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("updater check response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("updater check response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::UpdateSetPrefs { prefs } => {
                let plan = myownmesh_updater::prepare_operation();
                let lease = json_lines
                    .acquire_claim(plan.claim())
                    .context("updater preferences operation was not admitted")?;
                let funded = plan
                    .run(lease, || {
                        let prefs = serde_json::from_value::<myownmesh_updater::UpdatePrefs>(prefs)
                            .map_err(|error| {
                                myownmesh_updater::Error::Other(format!(
                                    "bad update prefs: {error}"
                                ))
                            })?;
                        myownmesh_updater::set_prefs(prefs)
                    })
                    .map_err(|_| {
                        anyhow::anyhow!("updater operation lease did not match its plan")
                    })?;
                let variable = FundedVariableReply::updater_status(funded);
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("updater preferences response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("updater preferences response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::GovernanceMfaEnroll { network } => {
                let operation = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("MFA enrollment operation was not admitted")?;
                let result = myownmesh_core::custody::enroll(&network, &network);
                let variable = FundedVariableReply::mfa_enrollment(result, operation)
                    .map_err(|_| anyhow::anyhow!("MFA operation lease did not match"))?;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("MFA enrollment response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("MFA enrollment response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkIdGenerate => {
                let plan = match myownmesh_core::identity::prepare_generated_network_id() {
                    Ok(plan) => plan,
                    Err(error) => {
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("network-id generation refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let line_ceiling = network_id_reply_line_ceiling(plan.encoding_ceiling())?;
                let (committed, output) = prepare_typed_and_line_building(
                    plan.typed_retention_claim(),
                    line_ceiling,
                    &json_lines,
                    |typed| plan.commit(typed),
                )
                .context("generated network id or response line was not admitted")?;
                let network_id = match committed {
                    Ok(network_id) => network_id,
                    Err(error) => {
                        drop(output);
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("network-id generation refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let reply = PreparedReply::NetworkId(network_id);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("generated network-id response exceeded its exact ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::NetworkIdNormalize { input } => {
                let plan = match myownmesh_core::identity::prepare_normalized_network_id(&input) {
                    Ok(plan) => plan,
                    Err(refusal) => {
                        let text = PreparedText::network_id_error(&refusal, &json_lines)
                            .context("network-id validation refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let line_ceiling = network_id_reply_line_ceiling(plan.encoding_ceiling())?;
                let (committed, output) = prepare_typed_and_line_building(
                    plan.typed_retention_claim(),
                    line_ceiling,
                    &json_lines,
                    |typed| plan.commit(typed),
                )
                .context("normalized network id or response line was not admitted")?;
                let network_id = match committed {
                    Ok(network_id) => network_id,
                    Err(error) => {
                        drop(output);
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("network-id normalization refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                drop(input);
                let reply = PreparedReply::NetworkId(network_id);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("normalized network-id response exceeded its exact ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::ServicesStatus => {
                let source = state.services.status_source().await;
                let typed_claim = source
                    .typed_claim()
                    .context("services-status typed claim was not representable")?;
                let line_ceiling = source
                    .line_ceiling()
                    .context("services-status line ceiling was not representable")?;
                let (funded, output) = prepare_typed_and_line_building(
                    typed_claim,
                    line_ceiling,
                    &json_lines,
                    |typed| source.commit(typed),
                )
                .context("services-status typed snapshot or response line was not admitted")?;
                let funded = funded.map_err(|_| {
                    anyhow::anyhow!("services-status typed claim changed before commit")
                })?;
                let reply = PreparedReply::ServicesStatus(funded);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("services-status response exceeded its measured ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::ServicesSet { services } => {
                let lease = json_lines
                    .acquire_claim(variable_operation_claim())
                    .context("services-set result was not admitted")?;
                let plan = FundedVariableReply::begin_operation(lease)
                    .map_err(|_| anyhow::anyhow!("services-set lease did not match"))?;
                let variable = dispatch::services::services_set(&state, services, plan).await;
                let output =
                    AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, &json_lines)
                        .context("services-set response line was not admitted")?;
                let reply = PreparedReply::Variable(variable);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("services-set response changed after measurement")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::GovernanceMfaStatus { network } => {
                let reply = PreparedReply::Bool {
                    key: "enrolled",
                    value: myownmesh_core::custody::is_enrolled(&network),
                };
                match write_line(
                    &mut writer,
                    &json_lines,
                    &cancel,
                    ControlOut::Prepared(&reply),
                )
                .await?
                {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::GovernanceMfaDisable { network, code } => {
                match myownmesh_core::custody::disable(&network, &code) {
                    Ok(()) => {
                        let reply = PreparedReply::Bool {
                            key: "disabled",
                            value: true,
                        };
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                    Err(error) => {
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("MFA refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                }
            }
            other => other,
        };
        let request = match request {
            Request::ChannelSubscribe {
                client_id,
                client_capability,
                network,
                channel,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let reply = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&reply),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let success = PreparedReply::Bool {
                    key: "subscribed",
                    value: true,
                };
                let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&success), &json_lines)
                    .context("channel-subscribe response capacity was not admitted")?;
                let key = (network, channel);
                let join = match state.clients.subscribe_channel_borrowed(&key, client_id) {
                    Ok(join) => join,
                    Err(refusal) => {
                        drop(output);
                        let text = PreparedText::channel_registration_error(&refusal, &json_lines)
                            .context("channel-subscribe refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                match join {
                    crate::ipc::ChannelJoin::Install(ready) => {
                        let pump = crate::ipc::bridge::spawn_channel_pump(
                            &net,
                            &key,
                            state.clients.clone(),
                        );
                        let orphan = match pump {
                            Ok(pump) => {
                                state
                                    .clients
                                    .finish_channel_install(&key, &ready, Some(pump))
                            }
                            Err(error) => {
                                if let Some(orphan) =
                                    state.clients.finish_channel_install(&key, &ready, None)
                                {
                                    orphan.retire().await;
                                }
                                drop(output);
                                let text = PreparedText::channel_pump_error(&error, &json_lines)
                                    .context("channel-pump refusal text was not admitted")?;
                                let reply = PreparedReply::Error(text);
                                match write_line(
                                    &mut writer,
                                    &json_lines,
                                    &cancel,
                                    ControlOut::Prepared(&reply),
                                )
                                .await?
                                {
                                    Wrote::Sent => continue,
                                    Wrote::Ended => break,
                                }
                            }
                        };
                        if let Some(orphan) = orphan {
                            orphan.retire().await;
                        }
                    }
                    crate::ipc::ChannelJoin::Pending(ready) => {
                        if !ready.wait().await {
                            drop(output);
                            match write_static_error(
                                &mut writer,
                                &json_lines,
                                &cancel,
                                "channel subscribe refused: the route this subscription joined could not be installed",
                            ).await? {
                                Wrote::Sent => continue,
                                Wrote::Ended => break,
                            }
                        }
                    }
                    crate::ipc::ChannelJoin::Live => {}
                }
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&success), output)
                    .context("channel-subscribe response changed after admission")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::RpcRegister {
                client_id,
                client_capability,
                network,
                method,
                streaming,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let refusal = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&refusal),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let success = PreparedReply::Bool {
                    key: "registered",
                    value: true,
                };
                let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&success), &json_lines)
                    .context("RPC-register response capacity was not admitted")?;
                let mode = if streaming {
                    crate::ipc::clients::HandlerMode::Stream
                } else {
                    crate::ipc::clients::HandlerMode::Single
                };
                let key = (network, method);
                let generation = match state.clients.next_handler_generation() {
                    Ok(generation) => generation,
                    Err(refusal) => {
                        drop(output);
                        let text = PreparedText::rpc_registration_error(&refusal, &json_lines)
                            .context("RPC-register refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let prepared = match crate::ipc::bridge::prepare_handler_for_mode(
                    &net.rpc(),
                    &key,
                    generation,
                    mode,
                    &state.clients,
                ) {
                    Ok(prepared) => prepared,
                    Err(refusal) => {
                        drop(output);
                        let text = PreparedText::rpc_gateway_error(&refusal, &json_lines)
                            .context("RPC-register gateway refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let previous = match state
                    .clients
                    .claim_method_committing_with_key(key, client_id, mode, generation, prepared)
                {
                    Ok(previous) => previous,
                    Err(refusal) => {
                        drop(output);
                        let text = PreparedText::rpc_registration_error(&refusal, &json_lines)
                            .context("RPC-register commit refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                if let Some((previous, key)) = previous {
                    crate::ipc::bridge::notify_displaced(
                        &state.clients,
                        previous,
                        client_id,
                        key.0,
                        key.1,
                    );
                }
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&success), output)
                    .context("RPC-register response changed after admission")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::RpcRespond {
                client_id,
                client_capability,
                network,
                peer,
                method,
                request_id,
                operation_id,
                ok,
                error,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let success = PreparedReply::Bool {
                    key: "resolved",
                    value: true,
                };
                let key = crate::ipc::clients::PendingKey {
                    network,
                    method,
                    remote_peer: peer,
                    remote_request_id: request_id,
                    class: crate::ipc::clients::HandlerMode::Single,
                };
                let result = error.map_or_else(|| Ok(ok.unwrap_or(serde_json::Value::Null)), Err);
                let (resolved, output) = prepare_reply_then(&success, &json_lines, || {
                    state
                        .clients
                        .resolve_exact_single(&key, client_id, operation_id, result)
                })
                .context("RPC-resolve response capacity was not admitted")?;
                if resolved {
                    let line =
                        AdmittedLineOut::encode_prepared(ControlOut::Prepared(&success), output)
                            .context("RPC-resolve response changed after admission")?;
                    match write_admitted_line(&mut writer, &cancel, line).await? {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                } else {
                    drop(output);
                    let text = PreparedText::no_inflight_rpc(&key.remote_request_id, &json_lines)
                        .context("RPC-resolve refusal text was not admitted")?;
                    let refusal = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&refusal),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
            }
            Request::RpcStreamChunk {
                client_id,
                client_capability,
                network,
                peer,
                method,
                request_id,
                operation_id,
                payload,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let success = PreparedReply::Bool {
                    key: "delivered",
                    value: true,
                };
                let key = crate::ipc::clients::PendingKey {
                    network,
                    method,
                    remote_peer: peer,
                    remote_request_id: request_id,
                    class: crate::ipc::clients::HandlerMode::Stream,
                };
                let (accepted, output) = prepare_reply_then(&success, &json_lines, || {
                    state
                        .clients
                        .push_exact_stream(&key, client_id, operation_id, payload)
                })
                .context("stream-chunk response capacity was not admitted")?;
                if accepted {
                    let line =
                        AdmittedLineOut::encode_prepared(ControlOut::Prepared(&success), output)
                            .context("stream-chunk response changed after admission")?;
                    match write_admitted_line(&mut writer, &cancel, line).await? {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                } else {
                    drop(output);
                    let text =
                        PreparedText::no_inflight_stream(&key.remote_request_id, &json_lines)
                            .context("stream-chunk refusal text was not admitted")?;
                    let refusal = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&refusal),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
            }
            Request::RpcStreamEnd {
                client_id,
                client_capability,
                network,
                peer,
                method,
                request_id,
                operation_id,
                error,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let ceiling = PreparedReply::Bool {
                    key: "closed",
                    value: false,
                };
                let key = crate::ipc::clients::PendingKey {
                    network,
                    method,
                    remote_peer: peer,
                    remote_request_id: request_id,
                    class: crate::ipc::clients::HandlerMode::Stream,
                };
                let (closed, output) = prepare_reply_then(&ceiling, &json_lines, || {
                    state
                        .clients
                        .close_exact_stream(&key, client_id, operation_id, error)
                })
                .context("stream-close response capacity was not admitted")?;
                let reply = PreparedReply::Bool {
                    key: "closed",
                    value: closed,
                };
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("stream-close response exceeded its scalar ceiling")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::ChannelSendTo {
                network,
                channel,
                peer,
                payload,
            } => {
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let refusal = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&refusal),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let reply = PreparedReply::Bool {
                    key: "sent",
                    value: true,
                };
                let channel = net.channel::<serde_json::Value>(&channel);
                let (send, output) =
                    prepare_reply_then(&reply, &json_lines, || channel.send_to(&peer, &payload))
                        .context("channel-send response capacity was not admitted")?;
                match send.await {
                    Ok(()) => {
                        let line =
                            AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                                .context("channel-send response changed after admission")?;
                        match write_admitted_line(&mut writer, &cancel, line).await? {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                    Err(error) => {
                        drop(output);
                        let text = PreparedText::channel_error(&error, &json_lines)
                            .context("channel-send refusal text was not admitted")?;
                        let refusal = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&refusal),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                }
            }
            Request::ChannelSendAll {
                network,
                channel,
                payload,
            } => {
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let refusal = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&refusal),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let ceiling = PreparedReply::Usize {
                    key: "dispatched_to",
                    value: usize::MAX,
                };
                let channel = net.channel::<serde_json::Value>(&channel);
                let (broadcast, output) =
                    prepare_reply_then(&ceiling, &json_lines, || channel.broadcast(&payload))
                        .context("channel-broadcast response capacity was not admitted")?;
                match broadcast.await {
                    Ok(count) => {
                        let reply = PreparedReply::Usize {
                            key: "dispatched_to",
                            value: count,
                        };
                        let line =
                            AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                                .context(
                                    "channel-broadcast response exceeded its scalar ceiling",
                                )?;
                        match write_admitted_line(&mut writer, &cancel, line).await? {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                    Err(error) => {
                        drop(output);
                        let text = PreparedText::channel_error(&error, &json_lines)
                            .context("channel-broadcast refusal text was not admitted")?;
                        let refusal = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&refusal),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                }
            }
            Request::CapabilitiesSet {
                network,
                capabilities,
            } => {
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let refusal = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&refusal),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let reply = PreparedReply::Bool {
                    key: "advertised",
                    value: true,
                };
                let (advertised, output) =
                    prepare_reply_then(&reply, &json_lines, || net.advertise(capabilities))
                        .context("capability-advert response capacity was not admitted")?;
                match advertised {
                    Ok(()) => {
                        let line =
                            AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                                .context("capability-advert response changed after admission")?;
                        match write_admitted_line(&mut writer, &cancel, line).await? {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                    Err(error) => {
                        drop(output);
                        let text = PreparedText::rpc_advertise_error(&error, &json_lines)
                            .context("capability-advert refusal text was not admitted")?;
                        let refusal = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&refusal),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                }
            }
            Request::ChannelSendReliable {
                network,
                channel,
                peer,
                payload,
            } => {
                let Some(net) = state.registry.get(&network) else {
                    let text = PreparedText::unknown_network(&network, &json_lines)
                        .context("unknown-network refusal text was not admitted")?;
                    let reply = PreparedReply::Error(text);
                    match write_line(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        ControlOut::Prepared(&reply),
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                };
                let reply = PreparedReply::Bool {
                    key: "delivered",
                    value: true,
                };
                let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&reply), &json_lines)
                    .context("reliable-send response capacity was not admitted")?;
                let result = tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        drop(output);
                        match write_static_error(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            "control connection closing",
                        ).await? {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                    result = net.send_reliable(&peer, &channel, payload) => result,
                };
                let line = match result {
                    Ok(()) => {
                        AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                            .context("reliable-send response changed after admission")?
                    }
                    Err(error) => {
                        drop(output);
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("reliable-send refusal text was not admitted")?;
                        let refusal = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&refusal),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::ConfigShow => {
                let plan = match myownmesh_core::MeshConfig::prepare_load() {
                    Ok(plan) => plan,
                    Err(error) => {
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("config planning refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let work = json_lines
                    .acquire_claim(plan.load_work_claim())
                    .context("ConfigShow load work was not admitted")?;
                let loader_residual = json_lines
                    .acquire_claim(plan.loader_residual_claim())
                    .context("ConfigShow loader residual was not admitted")?;
                let config = match plan.commit(loader_residual, work) {
                    Ok(config) => config,
                    Err(error) => {
                        let text = PreparedText::core_error(&error, &json_lines)
                            .context("config load refusal text was not admitted")?;
                        let reply = PreparedReply::Error(text);
                        match write_line(
                            &mut writer,
                            &json_lines,
                            &cancel,
                            ControlOut::Prepared(&reply),
                        )
                        .await?
                        {
                            Wrote::Sent => continue,
                            Wrote::Ended => break,
                        }
                    }
                };
                let line_ceiling = config_reply_line_ceiling(
                    config
                        .compact_encoded_len()
                        .context("ConfigShow compact width was not representable")?,
                )
                .context("ConfigShow response width was not representable")?;
                let output = AdmittedLineOut::prepare_capacity(line_ceiling, &json_lines)
                    .context("ConfigShow response line was not admitted")?;
                let reply = PreparedReply::Config(config);
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("ConfigShow exceeded its core encoding ceiling")?;
                // `reply` owns the funded config and deliberately remains live
                // until the encoded line has either been written or cancelled.
                let wrote = write_admitted_line(&mut writer, &cancel, line).await?;
                drop(reply);
                match wrote {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::RpcUnregister {
                client_id,
                client_capability,
                network,
                method,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let ceiling = PreparedReply::Bool {
                    key: "released",
                    value: false,
                };
                let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&ceiling), &json_lines)
                    .context("RpcUnregister response capacity was not admitted")?;
                let key = (network, method);
                let release = state.clients.release_method(&key, client_id);
                let released = release.released;
                // Releasing the core registration is the local commit. Output
                // capacity is already held, and cancellation only races the
                // later write.
                drop(release);
                let reply = PreparedReply::Bool {
                    key: "released",
                    value: released,
                };
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("RpcUnregister response changed after admission")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            Request::ChannelUnsubscribe {
                client_id,
                client_capability,
                network,
                channel,
            } => {
                if state
                    .clients
                    .authenticate(client_id, &client_capability)
                    .is_none()
                {
                    match write_static_error(
                        &mut writer,
                        &json_lines,
                        &cancel,
                        "invalid local client authority",
                    )
                    .await?
                    {
                        Wrote::Sent => continue,
                        Wrote::Ended => break,
                    }
                }
                let reply = PreparedReply::Bool {
                    key: "unsubscribed",
                    value: true,
                };
                let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&reply), &json_lines)
                    .context("ChannelUnsubscribe response capacity was not admitted")?;
                let key = (network, channel);
                // Route retirement is the local commit and intentionally is
                // not cancelled with the socket. Success means the pump has
                // stopped; only the subsequent pre-funded response write races
                // connection shutdown.
                if let Some(route) = state.clients.unsubscribe_channel(&key, client_id) {
                    route.retire().await;
                }
                let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
                    .context("ChannelUnsubscribe response changed after admission")?;
                match write_admitted_line(&mut writer, &cancel, line).await? {
                    Wrote::Sent => continue,
                    Wrote::Ended => break,
                }
            }
            other => other,
        };
        let resp = dispatch(&state, &cancel, request).await;
        match write_line(
            &mut writer,
            &json_lines,
            &cancel,
            ControlOut::Response(&resp),
        )
        .await?
        {
            Wrote::Sent => {}
            Wrote::Ended => break,
        }
    }
    Ok(())
}

/// The two binary `realtime_pipe` connections and what they are bound to.
/// Frame-shaped work only: reading units off a socket and writing them back.
/// It decides nothing about admission — the binding is checked before either
/// pump starts, and every refusal it can meet comes from core.
mod realtime_pipe;

#[cfg(test)]
use realtime_pipe::realtime_pipe_binding;
use realtime_pipe::{
    realtime_pipe_binding_plan, release_owned_registrations, run_realtime_inbound_pipe,
    run_realtime_outbound_pipe, RealtimePipeBinding,
};

/// The per-request router and everything it calls to satisfy one `op`.
/// One exhaustive match over [`Request`] lives there, so a new variant is a
/// compile error rather than a silent fallthrough, and the work each arm does
/// sits beside it in a module named for the domain it belongs to.
mod dispatch;

use dispatch::dispatch;

/// Stream events to one connected subscriber. Drains two sources concurrently:
///
/// 1. The mesh-wide [`MeshHandle::events`] broadcast — peer / phase / diag
///    entries the engine emits.
/// 2. The per-client mailbox — `ServerOut` frames the IPC bridge (RPC inbound,
///    channel inbound, handler-displaced notifications) pushes for this specific
///    client.
///
/// **Neither source is preferred, and cancellation outranks both.** The two are
/// separate questions and the selects are nested to keep them separate.
///
/// Fairness is between the *sources*, and it is **explicit alternation** rather
/// than randomness. The single select this replaces was biased with the
/// per-client mailbox first, which is deterministic starvation rather than
/// ordinary scheduling variance — a sustained sequence of IPC-routed frames
/// keeps that branch continuously ready, so mesh events are never polled at all
/// until the broadcast ring gives up and reports lag, and the lag report is then
/// the first the subscriber hears of events it should have been given.
///
/// An unbiased select would fix the starvation and would only fix it
/// *probably*: with both sources continuously ready, each round is a coin toss,
/// so the guarantee is statistical and a control asserting it can only be
/// statistical too. `first` names which source gets the first look this round
/// and is flipped by whichever one is served, so between any two frames from one
/// source the other has been looked at. That is a property a control can assert
/// exactly, and it is the same bound in the worst case.
///
/// No service count is fixed anywhere, because none would be right for two
/// sources whose rates this daemon does not choose. Alternation is not a count:
/// a source with nothing ready is passed over rather than waited for.
///
/// Cancellation is not a third source and must not be fair with them. Folding it
/// into one unbiased select would make the close signal merely *probable* while
/// either source stayed continuously ready — a subscriber under sustained load
/// would leave the drain waiting on repeated coin tosses. The outer select is
/// biased with cancellation first, so it is observed at the first opportunity
/// and the sources compete only for what is left.
///
/// Returns when the writer breaks, when both sources close, or when this
/// connection is cancelled — its own client removed, or the control runtime
/// closing. The cancellation arm is what makes an idle subscriber on a quiet
/// mesh terminal: the connection task holds the handle its mailbox sender lives
/// in, so the mailbox never closes on its own and the two receive branches would
/// otherwise both park forever.
///
/// Takes the mesh receiver rather than the `ControlState` it comes off, for the
/// reason [`run_channel_pump`] takes its subscription: the alternation above is
/// the whole subject of a control, and a control that had to stand up a mesh,
/// a network registry and a service manager to reach it would end up asserting
/// against a copy of this loop instead of this loop.
///
/// [`run_channel_pump`]: crate::ipc::bridge
async fn run_events_stream<W>(
    frames: &FrameAdmission,
    cancel: &ConnectionCancel,
    writer: &mut W,
    mut client_rx: myownmesh_core::ResourceMailboxReceiver<crate::ipc::ServerOut>,
    mut mesh_rx: broadcast::Receiver<myownmesh_core::events::MeshEvent>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    /// One admitted frame out, and whether this connection is still serving.
    async fn emit<W>(
        writer: &mut W,
        frames: &FrameAdmission,
        cancel: &ConnectionCancel,
        frame: &crate::ipc::ServerOut,
    ) -> Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        Ok(write_line(writer, frames, cancel, ControlOut::Frame(frame)).await? == Wrote::Sent)
    }

    // Which source gets the first look this round. Starts on the client, so a
    // connection whose mailbox already has frames waiting when the stream opens
    // sends one before looking at the mesh -- the ordering the previous shape
    // had, kept for the first round only.
    let mut mesh_first = false;
    loop {
        let serving = tokio::select! {
            biased;
            () = cancel.cancelled() => false,
            serving = async {
                // Both orderings are `biased`, and which one runs is decided by
                // the flag rather than by the scheduler. Each arm flips it, so
                // the source that was just served is the one looked at second
                // next time -- and a source with nothing ready costs only the
                // poll, since the other arm is tried in the same round.
                //
                // The retention lease on a client frame stays bound across the
                // write and is dropped only after the bytes have left. Releasing
                // it at pop would report the frame's memory as free while this
                // task still holds and serializes it, which is the window a
                // client that stopped reading would otherwise be admitted
                // through twice. The encoded copy beside it is funded
                // separately, by `write_line`, because it is a second
                // simultaneously live allocation and this lease says nothing
                // about it.
                //
                // `None` from the mailbox means every sender is gone. In
                // practice the outer cancellation arm wins that race, because
                // the handle holding the last sender is this task's own; it is
                // treated as a benign end either way.
                if mesh_first {
                    tokio::select! {
                        biased;
                        recv = mesh_rx.recv() => {
                            mesh_first = false;
                            match recv {
                                Ok(event) => emit(writer, frames, cancel, &crate::ipc::ServerOut::Event { event }).await,
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    emit(writer, frames, cancel, &crate::ipc::ServerOut::Lagged { skipped: n }).await
                                }
                                Err(broadcast::error::RecvError::Closed) => Ok(false),
                            }
                        }
                        maybe_frame = client_rx.recv() => {
                            mesh_first = true;
                            let Some(delivery) = maybe_frame else {
                                return Ok(false);
                            };
                            // The delivery stays whole across the write: its
                            // funding is released when it is dropped at the end
                            // of this arm, which is after `emit` has returned.
                            // Taking the frame out first made the retention a
                            // separate local, free to fall before the bytes it
                            // paid for had finished being serialized.
                            emit(writer, frames, cancel, delivery.value()).await
                        }
                    }
                } else {
                    tokio::select! {
                        biased;
                        maybe_frame = client_rx.recv() => {
                            mesh_first = true;
                            let Some(delivery) = maybe_frame else {
                                return Ok(false);
                            };
                            // The delivery stays whole across the write: its
                            // funding is released when it is dropped at the end
                            // of this arm, which is after `emit` has returned.
                            // Taking the frame out first made the retention a
                            // separate local, free to fall before the bytes it
                            // paid for had finished being serialized.
                            emit(writer, frames, cancel, delivery.value()).await
                        }
                        recv = mesh_rx.recv() => {
                            mesh_first = false;
                            match recv {
                                Ok(event) => emit(writer, frames, cancel, &crate::ipc::ServerOut::Event { event }).await,
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    emit(writer, frames, cancel, &crate::ipc::ServerOut::Lagged { skipped: n }).await
                                }
                                Err(broadcast::error::RecvError::Closed) => Ok(false),
                            }
                        }
                    }
                }
            } => serving?,
        };
        if !serving {
            return Ok(());
        }
    }
}

/// Stream one network's connection-state transitions to a connected `ctl trace`
/// client. Writes each [`myownmesh_core::ConnTrace`] as a compact JSON object on
/// its own line (clean JSONL for `scripts/merge-traces.py` and `jq`). On
/// broadcast lag — a transition storm outran a slow reader — emits a
/// `{"lagged":N}` marker rather than silently skipping, so a gap in the timeline
/// is always explicit.
///
/// Returns when the client disconnects, when the network shuts down, or when the
/// control runtime closes. That last arm is the whole reason the receive is
/// wrapped in a select at all: a trace client has no registry entry to be
/// unregistered and no per-client mailbox to be closed, so on a quiet network
/// there is nothing else that would ever end this task — and `serve` waits for
/// every task it accepted.
async fn run_trace_stream<W>(
    frames: &FrameAdmission,
    cancel: &ConnectionCancel,
    writer: &mut W,
    mut rx: broadcast::Receiver<myownmesh_core::ConnTrace>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Biased: there is one source here, so nothing competes for fairness
        // and the close signal is polled first.
        let received = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            received = rx.recv() => received,
        };
        match received {
            Ok(trace) => {
                if write_line(writer, frames, cancel, ControlOut::Trace(&trace)).await?
                    == Wrote::Ended
                {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let marker = serde_json::json!({ "lagged": n });
                if write_line(writer, frames, cancel, ControlOut::Marker(&marker)).await?
                    == Wrote::Ended
                {
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

/// What `serve` does with the connection tasks it accepted.
///
/// Driven against the join helpers directly rather than through a socket,
/// because what is under test is a property of the *handles* — that they are
/// awaited rather than discarded — and reaching it through a real connection
/// would need a connection task that panics on demand, which is a production
/// branch this daemon should not have.
#[cfg(test)]
mod accepted_task_tests {
    use super::*;

    /// Bytes this provider holds beyond `baseline`, so every assertion here is
    /// a delta and none depends on which dimensions the provider's own
    /// bookkeeping happens to touch.
    fn charged(provider: &myownmesh_core::FiniteResourceProvider, baseline: u64) -> u64 {
        provider
            .in_use()
            .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes)
            .saturating_sub(baseline)
    }

    /// A provider granting exactly `nodes` join-list nodes, the port that spends
    /// it, and what that port had already charged before any node existed.
    ///
    /// Exact including the provider's own records — one for the process scope and
    /// one per reservation, asked of core rather than restated here, and without
    /// which this grant refuses its own second node. Locally owned and installed
    /// nowhere.
    fn join_grant(
        nodes: u64,
    ) -> (
        myownmesh_core::FiniteResourceProvider,
        myownmesh_core::ResourceProviderPort,
        myownmesh_core::ResourceScope,
        u64,
    ) {
        // Asked of core rather than restated here. The provider retains a
        // bookkeeping record per reservation and one for the scope, so a grant
        // sized to the node claims alone is short by one residual per node plus
        // one -- and short in a residual, which refuses a *later* acquisition
        // than the one that was underfunded, so the fixture would fail somewhere
        // other than where it was wrong. A figure restated on this side would be
        // a second answer to a question core already answers, which is the exact
        // drift this crate's accounting notes are written against.
        let node = crate::ipc::LeasedList::<tokio::task::JoinHandle<()>>::node_claim()
            .expect("the node claim is representable");
        let claim = myownmesh_core::FiniteResourceProvider::reservation_planning_charge(node)
            .expect("a node reservation is representable")
            .checked_scale(nodes)
            .expect("the fixture grant is representable")
            .checked_add(myownmesh_core::FiniteResourceProvider::scope_planning_charge())
            .expect("the process scope record is representable");
        let provider = myownmesh_core::FiniteResourceProvider::new(claim);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the fixture grant funds its own process scope");
        let scope = port.process_scope();
        // Read after the port: opening the process scope is itself a charge.
        let baseline = charged(&provider, 0);
        (provider, port, scope, baseline)
    }

    fn join_node(
        port: &myownmesh_core::ResourceProviderPort,
        scope: &myownmesh_core::ResourceScope,
    ) -> myownmesh_core::ResourceLease {
        port.acquire(
            scope,
            myownmesh_core::ResourceAuthorityClass::Admitted,
            crate::ipc::LeasedList::<tokio::task::JoinHandle<()>>::node_claim()
                .expect("the node claim is representable"),
        )
        .expect("the fixture grant funds this node")
    }

    /// A finished connection task is *joined*, and a live one is left alone.
    ///
    /// The finding this pins is that a dropped `JoinHandle` is not a join.
    /// Dropping one detaches its task and discards its `JoinError`, so a
    /// connection that aborted mid-request would be indistinguishable from one
    /// that returned — and the whole reason `serve` retains these handles rather
    /// than counting task admissions is that a count cannot tell those apart
    /// either. `join_finished` answers how many ended abnormally, which is the
    /// one observation that separates the two implementations.
    ///
    /// Three tasks, because the reap has to be selective as well as truthful:
    /// one that returns, one that panics, and one that never finishes. The last
    /// must still be in the list afterwards, still funded — reaping it would
    /// mean awaiting a connection that is still serving a client, inside the
    /// accept loop.
    ///
    /// Nothing here waits on a duration. The tasks are polled to completion by
    /// yielding until they report finished, which is their own state and not a
    /// clock.
    #[tokio::test]
    async fn v4_r2_daemon_a_finished_connection_task_is_joined_rather_than_discarded() {
        let (provider, port, scope, baseline) = join_grant(3);
        let node_bytes = crate::ipc::LeasedList::<tokio::task::JoinHandle<()>>::node_claim()
            .expect("the node claim is representable")
            .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes);
        let mut accepted = crate::ipc::LeasedList::new();

        let returned = tokio::spawn(async {});
        let aborted = tokio::spawn(async {
            panic!("a connection task aborted mid-request");
        });
        let serving = tokio::spawn(std::future::pending::<()>());
        // Their own state, not a duration: this ends when the two tasks under
        // test have really finished and never otherwise.
        while !returned.is_finished() || !aborted.is_finished() {
            tokio::task::yield_now().await;
        }
        assert!(
            !serving.is_finished(),
            "non-vacuity: the third connection is still serving"
        );

        accepted.push(returned, join_node(&port, &scope));
        accepted.push(aborted, join_node(&port, &scope));
        accepted.push(serving, join_node(&port, &scope));
        assert_eq!(
            charged(&provider, baseline),
            3 * node_bytes,
            "non-vacuity: three connections are retained and funded"
        );

        let ended = std::sync::atomic::AtomicUsize::new(2);
        let abnormal = join_finished(&ended, &mut accepted).await;
        assert_eq!(
            abnormal, 1,
            "the panicking connection was joined and its JoinError observed; a \
             reap that dropped its handle would answer zero here"
        );
        assert_eq!(
            accepted.len(),
            1,
            "and the connection that is still serving was not reaped"
        );
        assert_eq!(
            charged(&provider, baseline),
            node_bytes,
            "two nodes' funding came back with the tasks that ended, and the live \
             one's did not"
        );

        assert_eq!(
            ended.load(std::sync::atomic::Ordering::Acquire),
            0,
            "and both counted completions were consumed by the join"
        );

        // The remaining handle is detached deliberately here: this control owns
        // no runtime to shut down, and `serve`'s own drain is what joins it in
        // production.
        drop(accepted);
    }

    /// One connection, then a quiet listener: its funded node comes back at the
    /// completion rather than at some later event.
    ///
    /// This is the edge the counter exists for. A task signals from a drop guard
    /// *inside* its own future, so at the instant the signal lands its handle is
    /// not yet finalized. Here the task has not been polled at all — this is a
    /// current-thread runtime and nothing has yielded to it — so `is_finished()`
    /// is certainly false when the reap begins. A reap that looked once would
    /// return having freed nothing, and with no further connection ever accepted
    /// there would be no second look before shutdown.
    ///
    /// The assertion is on the ledger, not on a log line: the node's bytes are
    /// back, which can only be true if the node was reaped.
    #[tokio::test]
    async fn v4_r2_daemon_a_completion_reaps_its_node_even_before_the_handle_is_finalized() {
        let (provider, port, scope, baseline) = join_grant(1);
        let node_bytes = crate::ipc::LeasedList::<tokio::task::JoinHandle<()>>::node_claim()
            .expect("the node claim is representable")
            .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes);
        let mut accepted = crate::ipc::LeasedList::new();

        let connection = tokio::spawn(async {});
        assert!(
            !connection.is_finished(),
            "non-vacuity: the runtime has not polled this task, so the reap below \
             begins with a handle that is not finalized"
        );
        accepted.push(connection, join_node(&port, &scope));
        assert_eq!(
            charged(&provider, baseline),
            node_bytes,
            "non-vacuity: the connection's node is funded and held"
        );

        // Exactly what the completion guard publishes, and nothing else. No
        // second connection follows, and no accept ever will.
        let ended = std::sync::atomic::AtomicUsize::new(1);
        assert_eq!(
            join_finished(&ended, &mut accepted).await,
            0,
            "the connection returned rather than aborting"
        );
        assert!(
            accepted.is_empty(),
            "the completed connection was reaped by its own completion, with no \
             later accept to do it"
        );
        assert_eq!(
            charged(&provider, baseline),
            0,
            "and its funding came back with it"
        );
        assert_eq!(
            ended.load(std::sync::atomic::Ordering::Acquire),
            0,
            "the counted completion was consumed exactly once"
        );
    }
}

/// What ends a connection's outbound half when the runtime closes.
///
/// Unit-level and platform-neutral, because what is under test is the
/// cancellation composition rather than a socket. Both controls drive the
/// production functions directly, over a writer whose readiness this module
/// owns: [`NeverWritable`] where the point is a write that cannot proceed, and
/// a `tokio::io::duplex` pair where the point is one that can and whose bytes
/// are then read back.
#[cfg(test)]
mod stream_cancellation_tests {
    use super::*;

    /// A failure detector, and nothing here derives authority from it.
    ///
    /// Every step in both controls resolves on an event -- a writer signalling
    /// its own first poll, a runtime publishing its own close. What this bounds
    /// is only how a *regression* is reported: the shape each control replaces
    /// does not fail an assertion, it never reaches one, and without a guard
    /// that arrives as the whole suite timing out with nothing named. Long
    /// enough that a loaded machine will not trip it.
    const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

    async fn guarded<F: std::future::Future>(what: &str, future: F) -> F::Output {
        match tokio::time::timeout(HANG_GUARD, future).await {
            Ok(value) => value,
            Err(_) => panic!("hang guard: {what}"),
        }
    }

    /// A grant generous enough that nothing here is refused for capacity.
    ///
    /// Deliberately not tight: these controls are about cancellation, and a
    /// refusal would end the write for a reason neither of them is testing.
    fn writable_admission() -> FrameAdmission {
        let grant = myownmesh_core::ResourceClaim::try_from_entries([
            (myownmesh_core::ResourceClass::AccountedMemoryBytes, 1 << 20),
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                1 << 20,
            ),
        ])
        .expect("the control grant is representable");
        FrameAdmission::over_grant(grant, None)
    }

    /// A writer that never accepts a byte, and says so the first time it is
    /// asked to.
    ///
    /// The blocked half of the control below used to be a `duplex` with a small
    /// buffer and no reader, which blocks reliably and is still the wrong thing:
    /// it makes a buffer size the authority for whether the control is testing
    /// what it says it is. This owns readiness outright. `poll_write` never
    /// returns `Ready`, and it registers no waker, so nothing this writer does
    /// can ever wake the write arm — the only thing that can finish the future
    /// is the arm the control exists to prove.
    ///
    /// The signal is sent from inside `poll_write`, which makes "the write is at
    /// the writer" an event rather than an inference. A control that closed the
    /// runtime before the write had been polled would be proving that
    /// cancellation beats a write that never started, which is a weaker claim
    /// and the easy one.
    struct NeverWritable {
        /// Fired on the first `poll_write` and never again.
        reached: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl tokio::io::AsyncWrite for NeverWritable {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if let Some(reached) = self.reached.take() {
                // The receiver may already be gone if the control finished; a
                // failed send is that and nothing else.
                let _ = reached.send(());
            }
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A continuously ready client mailbox cannot starve one mesh event.
    ///
    /// The finding this pins is deterministic starvation, not scheduling
    /// variance. The select this replaces was biased with the per-client mailbox
    /// first, so a subscriber whose mailbox never went empty was never shown a
    /// mesh event at all — until the broadcast ring gave up and reported lag,
    /// which is the subscriber being told about events instead of given them.
    ///
    /// Every source is loaded *before* the stream is started, so the whole
    /// schedule is fixed by the alternation and not by arrival order or by the
    /// scheduler: two client frames are already queued and one mesh event is
    /// already published when the first poll happens. The alternation begins on
    /// the client, so the only order this loop can produce is
    /// `client, mesh, client` — and the shape it replaces can only produce
    /// `client, client, mesh`, because the mailbox is ready every time it is
    /// asked. One assertion separates them, and neither a duration nor a service
    /// count appears in it.
    ///
    /// The middle frame is the finding: the mesh event goes out while a client
    /// frame is still queued and ready behind it.
    #[tokio::test]
    async fn v4_r2_daemon_a_ready_client_mailbox_cannot_starve_a_mesh_event() {
        let clients = crate::ipc::ClientRegistry::default();
        let (client_tx, client_rx) = myownmesh_core::resource_mailbox::<crate::ipc::ServerOut>(
            crate::test_application_scope(),
        )
        .expect("the daemon test grant funds one subscriber mailbox");
        let (mesh_tx, mesh_rx) = broadcast::channel::<myownmesh_core::events::MeshEvent>(4);

        // Loaded first, all of it. Past this line both sources are ready and
        // stay ready, which is the condition the old shape starved under.
        for channel in ["first", "second"] {
            client_tx
                .send(crate::ipc::ServerOut::ChannelInbound {
                    network: "home".to_string(),
                    from: "peer".to_string(),
                    channel: channel.to_string(),
                    payload: serde_json::json!({ "seq": channel }),
                })
                .expect("the subscriber mailbox admits a preloaded frame");
        }
        mesh_tx
            .send(myownmesh_core::events::MeshEvent::Peer(
                myownmesh_core::events::PeerEvent::Sighted {
                    network_id: "home".to_string(),
                    device_id: "the-event-that-must-not-wait".to_string(),
                },
            ))
            .expect("the broadcast has a live receiver");

        let (daemon_side, client_side) = tokio::io::duplex(1 << 20);
        let streaming = {
            let clients = clients.clone();
            tokio::spawn(async move {
                let frames = writable_admission();
                let cancel = ConnectionCancel::runtime(&clients);
                let mut daemon_side = daemon_side;
                run_events_stream(&frames, &cancel, &mut daemon_side, client_rx, mesh_rx).await
            })
        };

        // Three lines, in the only order the alternation can produce.
        let mut reader = tokio::io::BufReader::new(client_side);
        let mut kinds = Vec::new();
        for _ in 0..3 {
            let mut line = String::new();
            guarded("the subscriber is written to", async {
                tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await
            })
            .await
            .expect("the daemon writes whole lines");
            let frame: serde_json::Value =
                serde_json::from_str(line.trim()).expect("each line is one frame");
            kinds.push(
                frame["kind"]
                    .as_str()
                    .expect("every server frame is tagged")
                    .to_string(),
            );
        }
        assert_eq!(
            kinds,
            vec![
                "channel_inbound".to_string(),
                "event".to_string(),
                "channel_inbound".to_string(),
            ],
            "the mesh event went out between the two client frames, so the second \
             client frame was ready and waiting when it did -- a mailbox-first \
             loop answers `[channel_inbound, channel_inbound, event]` here"
        );

        // Ended the way production ends it, and drained.
        clients.begin_closing();
        guarded("the stream ends when the runtime closes", streaming)
            .await
            .expect("the stream task did not panic")
            .expect("a cancelled stream ends cleanly");
    }

    /// A trace stream on a quiet network ends when the runtime closes.
    ///
    /// The finding this pins is that a trace subscriber has no registry entry
    /// and therefore no per-client cancellation: the runtime's own close is the
    /// only thing that can end it. Without that arm, one connected trace client
    /// on a network that happens to be quiet held the whole drain open — and
    /// "quiet" is not an unusual state, it is the normal one.
    ///
    /// Nothing is published, and that is the point rather than an omission: the
    /// broadcast sender is held open for the whole run, so the stream's one
    /// source is live and simply has nothing to say. The shape this replaces
    /// does not fail an assertion below; it never reaches one, which is what the
    /// hang guard exists to name. The control first polls the live stream to
    /// `Pending` and only then closes the runtime, so `closing()`'s
    /// subscribe-before-read ordering is part of the witness rather than a
    /// property inferred from a close that happened before the stream began.
    #[tokio::test]
    async fn v4_r2_daemon_a_quiet_trace_stream_ends_when_the_runtime_closes() {
        let clients = crate::ipc::ClientRegistry::default();
        let frames = writable_admission();
        let cancel = ConnectionCancel::runtime(&clients);
        // Held for the whole run: the source is open and quiet, not closed.
        let (traces, trace_rx) = broadcast::channel(4);
        // Room for a line, so nothing here is blocked on the socket instead.
        let (mut daemon_side, client_side) = tokio::io::duplex(4096);

        let mut streaming = Box::pin(run_trace_stream(
            &frames,
            &cancel,
            &mut daemon_side,
            trace_rx,
        ));
        std::future::poll_fn(
            |cx| match std::future::Future::poll(streaming.as_mut(), cx) {
                std::task::Poll::Pending => std::task::Poll::Ready(()),
                std::task::Poll::Ready(result) => {
                    panic!("non-vacuity: the open quiet stream ended before Closing: {result:?}")
                }
            },
        )
        .await;

        // Close only after the stream itself has reached its quiet receive. This
        // makes `closing()`'s subscribe-before-read ordering load-bearing: a
        // one-shot notification lost between those operations would hang here.
        clients.begin_closing();
        guarded(
            "a quiet trace stream ends when the runtime closes",
            streaming,
        )
        .await
        .expect("a cancelled trace stream ends cleanly rather than erroring");

        // Nothing was written, which is what makes this the quiet case: the
        // stream ended because the runtime closed and for no other reason.
        drop(daemon_side);
        let mut drained = Vec::new();
        let mut client_side = client_side;
        guarded(
            "the client half drains",
            tokio::io::AsyncReadExt::read_to_end(&mut client_side, &mut drained),
        )
        .await
        .expect("the duplex half reads to end");
        assert!(
            drained.is_empty(),
            "a quiet network produced no trace event, so the stream ended on the \
             close and not on a frame: {drained:?}"
        );
        assert_eq!(
            traces.receiver_count(),
            0,
            "and the stream really did let go of its receiver"
        );
    }

    /// A write that cannot complete still ends when the runtime closes.
    ///
    /// The terminal-shutdown claim rests on this. A client that stops reading
    /// leaves the daemon's writer blocked on a socket that will never drain, and
    /// a connection task blocked there is one `serve` would wait for forever —
    /// so "serve returns without a timer" is only true if a blocked write is
    /// itself cancellable.
    ///
    /// The block is owned rather than arranged: [`NeverWritable`] decides its
    /// own readiness, so no buffer size, socket, or scheduler behaviour is
    /// standing in for "this write cannot make progress". And the runtime is
    /// closed only *after* the writer has said the write reached it, so what is
    /// proved is that a write already parked at the writer ends — not that
    /// cancellation beats a write that never started.
    ///
    /// The bias is deliberate and this control is consistent with it: the write
    /// arm is polled first, cannot proceed, and only then does cancellation
    /// answer. An immediately writable refusal still goes out as itself, which
    /// is the second half below.
    ///
    /// The hang guard is a failure detector and not the authority: every step
    /// here resolves on an event, and the guard exists so that the shape this
    /// replaces — which does not fail an assertion, it never returns — is
    /// reported as a named failure rather than as the suite timing out.
    #[tokio::test]
    async fn v4_r2_daemon_a_blocked_write_still_ends_when_the_runtime_closes() {
        let clients = crate::ipc::ClientRegistry::default();
        let frames = writable_admission();
        let cancel = ConnectionCancel::runtime(&clients);
        let response = wire::Response::ok(serde_json::json!({
            "filler": "a line with something in it, so there is a write to park",
        }));

        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let mut writer = NeverWritable {
            reached: Some(reached_tx),
        };
        let writing = write_line(
            &mut writer,
            &frames,
            &cancel,
            ControlOut::Response(&response),
        );
        tokio::pin!(writing);
        // Driven only as far as the write boundary. The writer itself says when
        // that is; the runtime is still open at this point, so the cancel arm
        // cannot be what ends the select below.
        guarded("the write reaches the writer", async {
            tokio::select! {
                _ = &mut writing => panic!(
                    "a writer that never accepts a byte cannot have completed a write"
                ),
                signal = reached => signal.expect("the writer signals its first poll"),
            }
        })
        .await;

        // Now, and only now: the write is parked where nothing but cancellation
        // can reach it.
        clients.begin_closing();
        let wrote = guarded("a parked write ends when the runtime closes", writing)
            .await
            .expect("a cancelled write ends cleanly rather than erroring");
        assert_eq!(
            wrote,
            Wrote::Ended,
            "the write could not have completed, so `Sent` here would mean the \
             control was not testing a parked writer at all"
        );

        // Non-vacuity: the same value, the same admission, on a socket somebody
        // is draining -- and it goes out as itself.
        let live = crate::ipc::ClientRegistry::default();
        let cancel = ConnectionCancel::runtime(&live);
        let (mut daemon_side, client_side) = tokio::io::duplex(4096);
        let wrote = guarded(
            "an unblocked write completes",
            write_line(
                &mut daemon_side,
                &frames,
                &cancel,
                ControlOut::Response(&response),
            ),
        )
        .await
        .expect("an admitted write succeeds");
        assert_eq!(wrote, Wrote::Sent);
        drop(daemon_side);
        let mut drained = Vec::new();
        let mut client_side = client_side;
        guarded(
            "the client half drains",
            tokio::io::AsyncReadExt::read_to_end(&mut client_side, &mut drained),
        )
        .await
        .expect("the duplex half reads to end");
        assert!(
            drained.ends_with(b"\n"),
            "and it is a whole line: {}",
            String::from_utf8_lossy(&drained)
        );
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
    use std::num::NonZeroUsize;
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

    fn connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        let capacity = NonZeroUsize::new(16).expect("fixture capacity is nonzero");
        let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
            myownmesh_core::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
            myownmesh_core::ConnectorCallbackServiceWeights::data_only(capacity, capacity),
            myownmesh_core::RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture callback policy is consistent");
        let profile = myownmesh_core::WebRtcConnectorProfile::new(
            callbacks,
            myownmesh_core::PendingRemoteCandidatePolicy::elastic(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), profile)
    }

    async fn connector_mesh() -> MeshHandle {
        myownmesh_core::Mesh::open_connector_capable_with_identity(
            myownmesh_core::MeshConfig::default(),
            Arc::new(myownmesh_core::Identity::ephemeral()),
            connector_policy(),
        )
        .await
        .expect("the daemon test grant opens a connector-capable mesh")
    }

    fn network_config(id: &str, network_id: &str) -> myownmesh_core::NetworkConfig {
        myownmesh_core::NetworkConfig {
            id: id.to_string(),
            network_id: network_id.to_string(),
            label: id.to_string(),
            kind: Default::default(),
            topology: myownmesh_core::TopologyMode::FullMesh,
            signaling: myownmesh_core::config::SignalingConfig::default(),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            roster_path: None,
            pinned_peers: Vec::new(),
            auto_approve: true,
        }
    }

    #[tokio::test]
    async fn v4_r2_daemon_a_parked_rpc_is_withdrawn_before_socket_shutdown_completes() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let near_mesh = connector_mesh().await;
        let far_mesh = connector_mesh().await;
        let near = near_mesh
            .join(network_config("near-control", "terminal-rpc-mesh"))
            .await
            .expect("near network joins");
        let far = far_mesh
            .join(network_config("far-control", "terminal-rpc-mesh"))
            .await
            .expect("far network joins");
        let (handler_entered_tx, handler_entered_rx) = tokio::sync::oneshot::channel();
        let handler_entered = std::sync::Mutex::new(Some(handler_entered_tx));
        let _parked_handler = far
            .rpc()
            .prepare_serve("park", move |_call| {
                let entered = handler_entered
                    .lock()
                    .expect("the handler-entry witness is not poisoned")
                    .take()
                    .expect("the parked handler is entered exactly once");
                entered
                    .send(())
                    .expect("the handler-entry witness remains observed");
                async {
                    std::future::pending::<Result<myownmesh_core::rpc::RpcResponse, String>>().await
                }
            })
            .expect("the far gateway prepares the parked handler")
            .commit()
            .into_result()
            .expect("the far gateway installs the parked handler");
        let link = near.install_promoted_peer_over_real_link(&far).await;
        let peer = link.peer_device_id().to_string();

        let directory = tempfile::tempdir().expect("temporary control root");
        let socket = directory.path().join("private").join("control.sock");
        let (registry_tx, registry_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let networks = NetworkRegistry::new();
        assert!(
            networks.insert(near, None).into_refusal().is_none(),
            "the near network is reachable by the control registry"
        );
        let observed = networks
            .get("near-control")
            .expect("the inserted network is visible");
        let services = ServiceManager::new(near_mesh.clone(), networks.clone());
        let serving = tokio::spawn(serve_with_hooks(
            near_mesh,
            networks.clone(),
            services,
            Some(socket.clone()),
            RealtimeAdvert {
                supported: false,
                encodings: Vec::new(),
                flow_ceiling: None,
            },
            shutdown_rx,
            ControlHooks {
                before_events_subscribe_commit: None,
                registry: Some(registry_tx),
                at_events_stream_entry: None,
            },
        ));
        let clients = guarded("serve publishes its registry", registry_rx)
            .await
            .expect("serve publishes the registry it built");
        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is valid");
        let stream = guarded("RPC client connects", async {
            loop {
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => return stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        let (mut client_reader, mut client_writer) = stream.split();
        let request = Request::RpcCall {
            network: "near-control".to_string(),
            peer: peer.clone(),
            method: "park".to_string(),
            payload: serde_json::Value::Null,
        };
        let mut encoded = serde_json::to_vec(&request).expect("the RPC request encodes");
        encoded.push(b'\n');
        client_writer
            .write_all(&encoded)
            .await
            .expect("the client sends the RPC");

        guarded("the RPC is filed under the promoted session", async {
            loop {
                if observed.pending_call_count_for_test(&peer) == Some(1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        guarded("the remote parked handler is entered", handler_entered_rx)
            .await
            .expect("the far handler reports its first entry");
        shutdown_tx
            .send(())
            .expect("the shutdown broadcast is live");
        guarded("serve begins closing", clients.closing()).await;
        guarded("the parked RPC is withdrawn", async {
            loop {
                if observed.pending_call_count_for_test(&peer) == Some(0) {
                    break;
                }
                assert!(
                    observed.pending_call_count_for_test(&peer).is_some(),
                    "the promoted session must remain present while withdrawal is observed"
                );
                tokio::task::yield_now().await;
            }
        })
        .await;
        guarded("serve returns", serving)
            .await
            .expect("the serve task did not panic")
            .expect("serve returns without error");
        assert_eq!(
            clients.residue(),
            crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed)
        );
        drop(client_writer);
        let mut terminal = Vec::new();
        guarded(
            "the socket reaches a typed terminal answer or EOF",
            tokio::io::AsyncReadExt::read_to_end(&mut client_reader, &mut terminal),
        )
        .await
        .expect("the client reads the terminal socket state");
        if !terminal.is_empty() {
            let response: Response = serde_json::from_slice(&terminal)
                .expect("a non-EOF terminal answer is a typed response");
            assert!(!response.ok, "a cancelled parked RPC cannot report success");
        }
        let _ = networks.shutdown_all().await;
        let _ = link.retire().await;
        drop(far);
    }

    /// A live `EventsSubscribe` ends with the runtime, and `serve` returns
    /// having joined it and closed.
    ///
    /// The ordinary terminal case, and the one the review names first. A
    /// subscribed connection is parked in the stream loop with nothing to send
    /// it, which is the state a `serve` that returned on the shutdown signal
    /// alone would abandon: the socket would still be open, the client still in
    /// the registry, and the daemon would report itself closed while a
    /// connection task it accepted was still running.
    ///
    /// Four claims, none of them timed:
    ///
    /// 1. the connection is really subscribed before anything is asked of it —
    ///    one client, one accepted task, `Running`;
    /// 2. the drain begins, observed through the registry's own signal;
    /// 3. `serve` returns — which it cannot do until the connection task it
    ///    accepted has ended and been joined;
    /// 4. and the registry is `Closed` holding nothing.
    ///
    /// The client's halves are held across `serve`'s return on purpose. Dropping
    /// them first would let the client's own close end the connection, and this
    /// control would then pass against a `serve` that cancelled nothing. End of
    /// file is read afterwards, as the witness that the daemon closed its end.
    #[tokio::test]
    async fn v4_r2_daemon_a_live_events_subscriber_ends_with_the_runtime() {
        let directory = tempfile::tempdir().expect("temporary control root");
        let socket = directory.path().join("private").join("control.sock");
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
                before_events_subscribe_commit: None,
                registry: Some(registry_tx),
                at_events_stream_entry: None,
            },
        ));
        let clients = guarded("serve publishes its registry", registry_rx)
            .await
            .expect("serve publishes the registry it built");

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let stream = guarded("client connects", async {
            loop {
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

        // (1) The ack is the causal barrier: past it the connection is in the
        // registry and parked in the stream loop.
        let mut ack = String::new();
        guarded(
            "the subscription is acked",
            client_reader.read_line(&mut ack),
        )
        .await
        .expect("the daemon answers the subscribe");
        let ack: Response =
            serde_json::from_str(ack.trim()).expect("the ack is a control response");
        assert!(ack.ok, "the subscription succeeded: {:?}", ack.error);
        let residue = clients.residue();
        assert_eq!(residue.clients, 1, "non-vacuity: one live subscriber");
        assert_eq!(residue.live_tasks, 1, "carried by one accepted task");
        assert_eq!(residue.lifecycle, crate::ipc::Lifecycle::Running);

        // (2) The drain begins.
        shutdown_tx
            .send(())
            .expect("the shutdown broadcast is live");
        guarded("serve begins closing", clients.closing()).await;

        // (3) And `serve` returns, which it cannot do with an accepted task
        // still live.
        guarded("serve returns", serving)
            .await
            .expect("the serve task did not panic")
            .expect("serve returns without error");

        // (4) Holding nothing.
        assert_eq!(
            clients.residue(),
            crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed),
            "no client, flow, handler, subscription, pending call or task lease remains"
        );

        // The socket witness, read only now.
        drop(client_writer);
        let mut rest = Vec::new();
        guarded(
            "the client's connection ended",
            tokio::io::AsyncReadExt::read_to_end(&mut client_reader, &mut rest),
        )
        .await
        .expect("the client's half reads to end");
    }

    /// A padded `EventsSubscribe` holds none of its line's parse capacity once
    /// the stream it opened is live.
    ///
    /// The integration half of the padded-request finding, and the half a
    /// decode-level control cannot reach. `decode_request` releasing the work
    /// dimension is one property; the *connection branch* not re-retaining it —
    /// not carrying the decoded request into the stream loop, not holding the
    /// line, not keeping the lease that funded either — is a different one, and
    /// it is the one a client exploits by subscribing and never leaving.
    ///
    /// The barrier is the whole reason this can be asserted at all. It sits past
    /// the ack and before the first poll of the stream loop, which is the one
    /// instant at which the connection is *both* subscribed and finished with
    /// the request that subscribed it. Nothing here waits out a duration: the
    /// stream being live is a `oneshot` the daemon itself sends from that line,
    /// the shutdown transition is the registry's own signal, and the end is
    /// `serve` returning.
    ///
    /// **Ignored, and it has to be.** The reading is the whole binary's grant,
    /// which every other control in this binary also spends from, so a delta
    /// across a step is attributable to that step only when nothing else is
    /// running. `run_exact_control ... --ignored` is what gives it that.
    ///
    /// Three claims:
    ///
    /// 1. the padded line really did reserve parse capacity — otherwise there is
    ///    nothing for the release to be about and the middle claim is vacuous;
    /// 2. at the instant the stream goes live, parse capacity is back exactly
    ///    where it was before the connection existed, while the connection is
    ///    provably subscribed — one client, one accepted task, in a `Running`
    ///    registry;
    /// 3. and the connection is still a real one afterwards: the shutdown ends
    ///    it, `serve` returns, and the registry closes holding nothing.
    #[tokio::test]
    #[ignore = "reads the test binary's shared resource ledger and must run alone"]
    async fn v4_r2_daemon_a_padded_events_subscribe_holds_no_parse_capacity_once_live() {
        // Whitespace, so the line is long and the value it decodes to is empty:
        // `events_subscribe` carries no fields at all, which is the asymmetry a
        // client would reach for.
        let padded = format!("{}{{\"op\":\"events_subscribe\"}}\n", " ".repeat(4096));
        // (1) Non-vacuity, taken from the same function the daemon admits with.
        let padded_work =
            myownmesh_core::application_gateway::json_input_work_claim(padded.len() - 1)
                .expect("the padded line's claim is representable")
                .amount(myownmesh_core::ResourceClass::ParsingOrCpuWork);
        assert!(
            padded_work > 0,
            "non-vacuity: a padded line reserves parse capacity, so there is \
             something for the release below to be about"
        );

        let directory = tempfile::tempdir().expect("temporary control root");
        let socket = directory.path().join("private").join("control.sock");
        let (barrier, live, resume) = DispatchBarrier::paired();
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
                before_events_subscribe_commit: None,
                registry: Some(registry_tx),
                at_events_stream_entry: Some(barrier),
            },
        ));
        let clients = guarded("serve publishes its registry", registry_rx)
            .await
            .expect("serve publishes the registry it built");

        // The reading to compare against: `serve` is up and listening, and no
        // connection exists. Taken after the registry is published so the
        // listener's own acquisitions are already in it.
        let ledger = crate::test_resource_ledger();
        let idle = ledger
            .in_use()
            .amount(myownmesh_core::ResourceClass::ParsingOrCpuWork);

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let stream = guarded("client connects", async {
            loop {
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
            .write_all(padded.as_bytes())
            .await
            .expect("the client sends its padded subscribe");

        // (2) The daemon itself says when the stream is live, from the line
        // between the ack and the first poll of the loop.
        guarded("the subscription goes live", live)
            .await
            .expect("the connection task reached the stream barrier");
        let residue = clients.residue();
        assert_eq!(
            residue.clients, 1,
            "non-vacuity: the padded subscribe really is subscribed"
        );
        assert_eq!(
            residue.live_tasks, 1,
            "and its connection is a live accepted task"
        );
        assert_eq!(
            residue.lifecycle,
            crate::ipc::Lifecycle::Running,
            "with nothing shutting down yet"
        );
        assert_eq!(
            ledger
                .in_use()
                .amount(myownmesh_core::ResourceClass::ParsingOrCpuWork),
            idle,
            "the padded line's parse capacity is back where it was before this \
             connection existed, while the stream it opened is live -- so the \
             connection kept none of it, and a client that subscribes and never \
             leaves pins none of it"
        );

        // (3) And it is a real connection, ended by the runtime rather than by
        // its client. Both halves are held across `serving` deliberately: a
        // control that dropped them first would let the client's own close stand
        // in for the cancellation this asserts, and would pass against a `serve`
        // that never cancelled anything.
        resume.send(()).expect("the paused task is still waiting");
        shutdown_tx
            .send(())
            .expect("the shutdown broadcast is live");
        guarded("serve begins closing", clients.closing()).await;
        guarded("serve returns", serving)
            .await
            .expect("the serve task did not panic")
            .expect("serve returns without error");
        assert_eq!(
            clients.residue(),
            crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed),
            "and the padded subscriber left nothing behind"
        );
        // The socket witness, read only now: the client half was open the whole
        // time, so end of file here is the daemon having closed its end.
        drop(client_writer);
        let mut rest = Vec::new();
        guarded(
            "the client's connection ended",
            tokio::io::AsyncReadExt::read_to_end(&mut client_reader, &mut rest),
        )
        .await
        .expect("the client's half reads to end");
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
    ///
    /// The socket parent is deliberately absent. Production creates it with
    /// owner-only permissions before binding the socket. Using the temporary
    /// directory itself would exercise the refusal path on Unix hosts where
    /// that directory is group- or other-accessible, leaving the client to wait
    /// for a listener that was correctly never created.
    #[tokio::test]
    async fn a_subscribe_barriered_at_its_commit_loses_to_shutdown_and_leaves_nothing() {
        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("private");
        let socket = parent.join("control.sock");
        assert!(
            !parent.exists(),
            "non-vacuity: production must create and secure the socket parent"
        );
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
                at_events_stream_entry: None,
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

/// The variable state reply uses the same real governance engine on both
/// sides of its admission gap. No semantic snapshot crosses that gap: pass
/// zero quotes capacity, while commit remeasures the then-current state and
/// either builds it once or refuses before cloning it.
#[cfg(test)]
mod variable_state_reply_tests {
    use super::*;
    use std::num::NonZeroUsize;

    fn connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        let capacity = NonZeroUsize::new(16).expect("fixture capacity is nonzero");
        let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
            myownmesh_core::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
            myownmesh_core::ConnectorCallbackServiceWeights::data_only(capacity, capacity),
            myownmesh_core::RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture callback policy is consistent");
        let profile = myownmesh_core::WebRtcConnectorProfile::new(
            callbacks,
            myownmesh_core::PendingRemoteCandidatePolicy::elastic(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), profile)
    }

    fn network_config() -> myownmesh_core::NetworkConfig {
        myownmesh_core::NetworkConfig {
            id: "variable-state-control".to_owned(),
            network_id: "variable-state-control".to_owned(),
            label: "variable-state-control".to_owned(),
            kind: Default::default(),
            topology: myownmesh_core::TopologyMode::FullMesh,
            signaling: Default::default(),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            roster_path: None,
            pinned_peers: Vec::new(),
            auto_approve: true,
        }
    }

    #[tokio::test]
    async fn v4_r4_daemon_nonempty_governance_snapshot_pressure_and_drift_refuse_before_build() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = myownmesh_core::Mesh::open_connector_capable_with_identity(
            myownmesh_core::MeshConfig::default(),
            Arc::new(myownmesh_core::Identity::ephemeral()),
            connector_policy(),
        )
        .await
        .expect("the real daemon mesh opens");
        let scope = mesh
            .local_application_resource_scope()
            .expect("the daemon mesh exposes its application scope");
        let joined = mesh
            .join(network_config())
            .await
            .expect("the real network joins");

        joined
            .propose_transition(
                myownmesh_core::TransitionVariant::RoleGrant {
                    target: "first-absent-member".to_owned(),
                    role: myownmesh_core::Role::Member,
                },
                None,
            )
            .await
            .expect("an open network accepts a meaningful Member grant");

        let plan = joined
            .prepare_governance_snapshot()
            .await
            .expect("the nonempty state is measurable");
        let builds_before = joined.governance_snapshot_build_count_for_test();
        let typed = scope
            .acquire(plan.typed_retention_claim())
            .expect("the quoted typed owner is funded");
        let funded = plan
            .commit(typed)
            .await
            .expect("an unchanged nonempty state commits");
        assert_eq!(
            joined.governance_snapshot_build_count_for_test(),
            builds_before + 1,
            "the authoritative funded snapshot is built exactly once"
        );
        assert!(
            !funded.state().member_log.is_empty(),
            "non-vacuity: the funded snapshot contains the real Member grant"
        );
        let variable = FundedVariableReply::Governance(funded);
        let exact = variable
            .exact_line_len()
            .expect("the full wire is measurable");
        let admission = FrameAdmission::new(scope.clone(), None);
        let output = AdmittedLineOut::prepare_capacity(exact, &admission)
            .expect("the full response line is admitted");
        let reply = PreparedReply::Variable(variable);
        let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
            .expect("the nonempty compact wire matches its measurement");
        assert_eq!(line.bytes().len(), exact);
        let wire: serde_json::Value = serde_json::from_slice(&line.bytes()[..exact - 1])
            .expect("the legacy compact response is valid JSON");
        assert_eq!(wire["ok"], true);
        assert!(!wire["data"]["state"]["member_log"]
            .as_array()
            .expect("member_log remains an array")
            .is_empty());
        drop((line, reply));

        let stale = joined
            .prepare_governance_snapshot()
            .await
            .expect("the predecessor state is measurable");
        let builds_before_refusal = joined.governance_snapshot_build_count_for_test();
        let stale_lease = scope
            .acquire(stale.typed_retention_claim())
            .expect("the predecessor typed owner is funded");
        joined
            .propose_transition(
                myownmesh_core::TransitionVariant::RoleGrant {
                    target: format!("second-absent-member-{}", "z".repeat(4096)),
                    role: myownmesh_core::Role::Member,
                },
                None,
            )
            .await
            .expect("the second longer Member grant mutates authoritative state");
        assert!(
            stale.commit(stale_lease).await.is_err(),
            "pass one refuses growth before cloning a successor into the stale grant"
        );
        assert_eq!(
            joined.governance_snapshot_build_count_for_test(),
            builds_before_refusal,
            "stale growth refuses before the production snapshot builder"
        );
    }
}
