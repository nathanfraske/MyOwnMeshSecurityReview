//! Local RPC operations: handler registration, in-flight resolution, the
//! outbound call, and the streaming call with the frame builders that forward
//! it without constructing anything the writer mailbox has not admitted.
//!
//! Four of these carry a `client_id` and the capability that proves it, and
//! every one of those checks it first — before a network lookup, before a
//! reply is measured, before anything is claimed. Registration is the reason
//! this matters most: a method claim is process-wide state, so an
//! unauthenticated caller must not be able to reach the point where one is
//! taken and then released.
//!
//! Like every operation module here, nothing writes. Each function answers
//! with an [`Answer`]: the reply, and the line capacity it was admitted under.
//! The connection loop encodes and writes.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{funded, refused, refused_text, unknown_network, Answer};
use crate::control::framing::{AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    prepare_reply_then, ControlOut, FundedVariableReply, OperationReplyData, PreparedReply,
    ResponseOwner,
};
use crate::control::{ConnectionCancel, ControlState};

/// The refusal shared by every client-scoped operation here.
const BAD_CLIENT: &str = "invalid local client authority";

/// The five coordinates that name one filed inbound call.
///
/// They travel together because they are one thing: `network`, `peer`,
/// `method` and `request_id` are the [`PendingKey`](crate::ipc::clients::PendingKey)
/// the entry was filed under, and `operation_id` is the process-local
/// ownership token for that exact entry. Answering, pushing a chunk, and
/// closing all need the whole set and none of them needs part of it.
pub(in crate::control) struct FiledCall {
    pub network: String,
    pub peer: String,
    pub method: String,
    pub request_id: String,
    pub operation_id: u64,
}

/// Register a local handler for one method on one network.
///
/// The order is the whole operation: the response line is funded, then a
/// generation is taken, then the core-side handler is prepared, and only then
/// is the method claimed. Each step that fails releases the funding it has not
/// used before building its refusal, so a refused registration leaves the
/// connection holding exactly what it held before.
pub(in crate::control) async fn register(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    method: String,
    streaming: bool,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let success = PreparedReply::Bool {
        key: "registered",
        value: true,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&success), admission)
        .context("RPC-register response capacity was not admitted")?;
    let mode = if streaming {
        crate::ipc::clients::HandlerMode::Stream
    } else {
        crate::ipc::clients::HandlerMode::Single
    };
    let key = (network, method);
    let generation = state.clients.next_handler_generation();
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
            return refused_text(format!("rpc register refused: {refusal}"), admission);
        }
    };
    let previous = match state
        .clients
        .claim_method_committing_with_key(key, client_id, mode, generation, prepared)
    {
        Ok(previous) => previous,
        Err(refusal) => {
            drop(output);
            return refused_text(format!("rpc register refused: {refusal}"), admission);
        }
    };
    if let Some((previous, key)) = previous {
        crate::ipc::bridge::notify_displaced(&state.clients, previous, client_id, key.0, key.1);
    }
    Ok((success, output))
}

/// Release a method claim this client holds.
pub(in crate::control) async fn unregister(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    method: String,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    // Funded against the widest boolean the line can carry, so the real answer
    // encodes into capacity taken before the release happened.
    let ceiling = PreparedReply::Bool {
        key: "released",
        value: false,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&ceiling), admission)
        .context("RpcUnregister response capacity was not admitted")?;
    let key = (network, method);
    let release = state.clients.release_method(&key, client_id);
    let released = release.released;
    // Releasing the core registration is the local commit. Output capacity is
    // already held, and cancellation only races the later write.
    drop(release);
    Ok((
        PreparedReply::Bool {
            key: "released",
            value: released,
        },
        output,
    ))
}

/// Build the identity of one in-flight inbound request.
fn pending_key(
    network: String,
    method: String,
    peer: String,
    request_id: String,
    class: crate::ipc::clients::HandlerMode,
) -> crate::ipc::clients::PendingKey {
    crate::ipc::clients::PendingKey {
        network,
        method,
        remote_peer: peer,
        remote_request_id: request_id,
        class,
    }
}

/// Resolve one in-flight single-response request.
pub(in crate::control) async fn respond(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    call: FiledCall,
    ok: Option<serde_json::Value>,
    error: Option<String>,
) -> Result<Answer> {
    let FiledCall {
        network,
        peer,
        method,
        request_id,
        operation_id,
    } = call;
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let success = PreparedReply::Bool {
        key: "resolved",
        value: true,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Single,
    );
    let result = error.map_or_else(|| Ok(ok.unwrap_or(serde_json::Value::Null)), Err);
    let (resolved, output) = prepare_reply_then(&success, admission, || {
        state
            .clients
            .resolve_exact_single(&key, client_id, operation_id, result)
    })
    .context("RPC-resolve response capacity was not admitted")?;
    if resolved {
        return Ok((success, output));
    }
    drop(output);
    refused_text(
        format!("no in-flight inbound RPC for '{}'", key.remote_request_id),
        admission,
    )
}

/// Push one chunk onto an in-flight streaming response.
pub(in crate::control) async fn stream_chunk(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    call: FiledCall,
    payload: serde_json::Value,
) -> Result<Answer> {
    let FiledCall {
        network,
        peer,
        method,
        request_id,
        operation_id,
    } = call;
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let success = PreparedReply::Bool {
        key: "delivered",
        value: true,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Stream,
    );
    let (accepted, output) = prepare_reply_then(&success, admission, || {
        state
            .clients
            .push_exact_stream(&key, client_id, operation_id, payload)
    })
    .context("stream-chunk response capacity was not admitted")?;
    if accepted {
        return Ok((success, output));
    }
    drop(output);
    refused_text(
        format!(
            "no in-flight inbound stream for '{}'",
            key.remote_request_id
        ),
        admission,
    )
}

/// Close an in-flight streaming response, cleanly or with an error.
///
/// Unlike the chunk push, "there was no such stream" is not a refusal here: a
/// close that finds nothing to close answers `closed: false`. The line is
/// funded against the widest boolean before the close is attempted, so both
/// answers encode into the same admitted capacity.
pub(in crate::control) async fn stream_end(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    call: FiledCall,
    error: Option<String>,
) -> Result<Answer> {
    let FiledCall {
        network,
        peer,
        method,
        request_id,
        operation_id,
    } = call;
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let ceiling = PreparedReply::Bool {
        key: "closed",
        value: false,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Stream,
    );
    let (closed, output) = prepare_reply_then(&ceiling, admission, || {
        state
            .clients
            .close_exact_stream(&key, client_id, operation_id, error)
    })
    .context("stream-close response capacity was not admitted")?;
    Ok((
        PreparedReply::Bool {
            key: "closed",
            value: closed,
        },
        output,
    ))
}

/// Call a method on a remote peer and answer with whatever came back.
///
/// This is the one operation here that can end the connection rather than
/// answer it, and the `Option` says so in the type: a call cancelled by the
/// connection draining has no reply, because the daemon never learned what the
/// answer would have been. Every other outcome — including a remote error — is
/// a reply. Returning `Answer` and inventing a refusal for the cancelled case
/// would claim a result that was never obtained.
pub(in crate::control) async fn call(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    cancel: &ConnectionCancel,
    network: String,
    peer: String,
    method: String,
    payload: serde_json::Value,
) -> Result<Option<Answer>> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission).map(Some);
    };
    // The result's size is not known until it arrives, so the right to answer is
    // taken before the call is made rather than after it returns.
    let owner =
        ResponseOwner::acquire(admission).context("RpcCall result operation was not admitted")?;
    let rpc = joined.rpc();
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(None),
        result = rpc.call_funded(&peer, &method, payload) => result,
    };
    funded(
        PreparedReply::Variable(FundedVariableReply::rpc_call(result, owner)),
        admission,
    )
    .context("RpcCall response line was not admitted")
    .map(Some)
}

/// One client-requested streaming call, exactly as the request stated it.
///
/// A carrier for the fields the `RpcCallStream` arm destructured. The payload
/// travels by value because the call consumes it; nothing here copies it.
pub(in crate::control) struct StreamCall {
    pub network: String,
    pub peer: String,
    pub method: String,
    pub payload: serde_json::Value,
}

/// One forwarded stream chunk, measured before the frame exists.
///
/// The payload is *moved* into the frame rather than copied, so unlike the
/// inbound-RPC and channel builders this one does not exist to avoid a clone.
/// It exists to keep the outer queue from charging the process grant a second
/// time for a graph core is already holding a reservation on. See
/// [`Self::retained_claim`].
struct StreamChunkBuilder<'a> {
    /// Borrowed from the forwarding task, which owns it for the whole stream.
    /// The frame's owned copy is made by [`Self::build`], past admission.
    request_id: &'a str,
    chunk: myownmesh_core::rpc::RpcStreamChunk,
}

impl myownmesh_core::ResourceMailboxItemBuilder<crate::ipc::ServerOut> for StreamChunkBuilder<'_> {
    fn retained_claim(
        &self,
    ) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
        let outer = myownmesh_core::serialized_mailbox_item_claim_as::<crate::ipc::ServerOut>(
            &crate::ipc::wire::ServerOutView::RpcCallStreamChunk {
                request_id: self.request_id,
                payload: self.chunk.value(),
            },
        )?;
        // What core still holds for this exact payload, recomputed from the
        // same value by the same function that funded it, so it cannot drift
        // from the reservation it names.
        //
        // The subtraction cannot underflow. The frame's encoding contains the
        // payload's encoding verbatim, so every dimension of the inner claim is
        // bounded by the same dimension of the outer one, and the outer claim
        // carries strictly more besides: `size_of::<ServerOut>()`, the queue's
        // parsing/CPU term, and one further allocation for the frame itself.
        //
        // The queue node is deliberately *not* subtracted. `pop` already
        // returned it, so it is not part of what is still outstanding, and
        // `send_building` acquires the new node separately anyway.
        let already_funded = self.chunk.funded_claim()?;
        Ok(outer.checked_sub(already_funded)?)
    }

    fn build(self) -> crate::ipc::ServerOut {
        crate::ipc::ServerOut::RpcCallStreamChunk {
            request_id: self.request_id.to_owned(),
            payload: self.chunk,
        }
    }
}

/// One end-of-stream marker, measured before the frame exists.
///
/// Both kinds of reason are held as something that already exists rather than
/// as a `String`: a remote terminal is peer-sized text core is still funding,
/// and a local refusal has no business being formatted before the writer
/// mailbox has agreed to hold it. Either way the owned field is made by
/// [`Self::build`], past admission.
struct StreamEndBuilder<'a> {
    request_id: &'a str,
    reason: crate::ipc::wire::TerminalReasonView<'a>,
}

impl myownmesh_core::ResourceMailboxItemBuilder<crate::ipc::ServerOut> for StreamEndBuilder<'_> {
    fn retained_claim(
        &self,
    ) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
        myownmesh_core::serialized_mailbox_item_claim_as::<crate::ipc::ServerOut>(
            &crate::ipc::wire::ServerOutView::RpcCallStreamEnd {
                request_id: self.request_id,
                error: self.reason,
            },
        )
    }

    fn build(self) -> crate::ipc::ServerOut {
        crate::ipc::ServerOut::RpcCallStreamEnd {
            request_id: self.request_id.to_owned(),
            error: self.reason.into_owned(),
        }
    }
}

/// Start a streaming RPC call and forward its chunks to the client's writer.
///
/// The call's coordinates arrive as [`StreamCall`] rather than as a `Request`,
/// so the signature is the claim about who may call this, checked, rather than
/// a runtime `unreachable!`.
pub(in crate::control) async fn call_stream_funded(
    state: &Arc<ControlState>,
    cancel: &ConnectionCancel,
    owner: ResponseOwner,
    call: StreamCall,
    client_id: crate::ipc::ClientId,
    client_capability: String,
) -> FundedVariableReply {
    let StreamCall {
        network,
        peer,
        method,
        payload,
    } = call;
    let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
        return owner.finish(Err("invalid local client authority".to_owned()));
    };
    let Some(net) = state.registry.get(&network) else {
        return owner.finish(Err(format!("unknown network: {network}")));
    };
    let request_id = format!("ipc-stream-{}", state.clients.next_call_stream_id());
    let task = match state.clients.lease_task_retaining(request_id.len()) {
        Ok(task) => task,
        Err(refusal) => return owner.finish(Err(format!("rpc call stream refused: {refusal}"))),
    };
    let rpc = net.rpc();
    let started = tokio::select! {
        biased;
        () = cancel.cancelled() => return owner.finish(Err("control connection closing".to_owned())),
        result = rpc.call_stream(&peer, &method, payload) => result,
    };
    let mut rx = match started {
        Ok(rx) => rx,
        Err(error) => return owner.finish(Err(error.to_string())),
    };
    let writer_tx = client.writer_tx.clone();
    let stream_owner = client.clone();
    let req_id_for_task = request_id.clone();
    tokio::spawn(async move {
        let _task = task;
        loop {
            // `recv_funded`, not `recv`: the ordinary public `recv` converts a
            // terminal into an application-owned `String` and releases core's
            // lease in the same expression. The daemon is not at that boundary
            // until it has forwarded the value, so it takes the funded form and
            // reads the text by borrow.
            let chunk = tokio::select! {
                () = stream_owner.wait_disconnected() => return,
                chunk = rx.recv_funded() => chunk,
            };
            let Some(chunk) = chunk else { break };
            match chunk {
                Ok(payload) => {
                    if let Err(refusal) = writer_tx.send_building(StreamChunkBuilder {
                        request_id: &req_id_for_task,
                        chunk: payload,
                    }) {
                        // Still only a cause. It becomes a message inside
                        // `build`, past this second admission.
                        let _ = writer_tx.send_building(StreamEndBuilder {
                            request_id: &req_id_for_task,
                            reason: crate::ipc::wire::TerminalReasonView::LocalChunkRefusal(
                                &refusal,
                            ),
                        });
                        return;
                    }
                }
                Err(terminal) => {
                    // `terminal` is alive across measurement, admission and the
                    // build, so core's session lease is paying for the
                    // peer-sized text for the whole time the daemon is deciding
                    // whether it may forward it. It is dropped only once the
                    // write-side owner exists.
                    let _ = writer_tx.send_building(StreamEndBuilder {
                        request_id: &req_id_for_task,
                        reason: crate::ipc::wire::TerminalReasonView::Remote(&terminal),
                    });
                    return;
                }
            }
        }
        let _ = writer_tx.send_building(StreamEndBuilder {
            request_id: &req_id_for_task,
            reason: crate::ipc::wire::TerminalReasonView::Clean,
        });
    });
    owner.finish(Ok(OperationReplyData::RpcStreamStarted(request_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::{ResourceMailboxItem as _, ResourceMailboxItemBuilder as _};

    /// The borrowed mirrors must encode byte-for-byte as the frames they stand
    /// in for. If they ever diverge the mailbox admitted one frame and queued a
    /// different one, and every measurement in this module would be about
    /// something that never gets sent.
    ///
    /// All three arms are covered, including `Remote` — that is the one whose
    /// width a peer chooses, so it is the one a mirror is most likely to get
    /// wrong and the one that matters most. Its terminal comes from a real
    /// stream that ends rather than a fabricated value.
    #[tokio::test]
    async fn v4_r5_daemon_a_measured_stream_frame_matches_the_frame_it_becomes() {
        let refusal = myownmesh_core::ResourceMailboxAdmissionError::Closed;
        let scope = crate::test_application_scope();
        let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
        inbox
            .finish_owned(&scope, "w".repeat(4096))
            .expect("the fixture scope funds one terminal of this width");
        let terminal = match inbox.recv_funded().await {
            Some(Err(terminal)) => terminal,
            _ => panic!("the stream ends with the terminal it was finished with"),
        };
        for reason in [
            crate::ipc::wire::TerminalReasonView::Clean,
            crate::ipc::wire::TerminalReasonView::LocalChunkRefusal(&refusal),
            crate::ipc::wire::TerminalReasonView::Remote(&terminal),
        ] {
            let builder = StreamEndBuilder {
                request_id: "ipc-stream-7",
                reason,
            };
            let measured = serde_json::to_vec(&crate::ipc::wire::ServerOutView::RpcCallStreamEnd {
                request_id: builder.request_id,
                error: builder.reason,
            })
            .expect("the mirror encodes");
            let measured_claim = builder
                .retained_claim()
                .expect("the mirror's claim is representable");

            let built = builder.build();
            let built_bytes = serde_json::to_vec(&built).expect("the frame encodes");
            let built_claim = built
                .retained_claim()
                .expect("the frame's claim is representable");

            assert_eq!(
                String::from_utf8(measured).expect("JSON is UTF-8"),
                String::from_utf8(built_bytes).expect("JSON is UTF-8"),
                "the borrowed mirror must encode exactly as the frame it measured"
            );
            assert_eq!(
                measured_claim, built_claim,
                "the admitted claim must be the claim the queued frame retains"
            );
        }
    }

    /// A writer mailbox over a grant of exactly `grant`, and the provider that
    /// answers for it.
    ///
    /// The shared `test_application_scope` cannot be used for pressure: it
    /// draws on the binary-wide provider every other daemon test spends from,
    /// so exhausting it would starve them rather than this control. This builds
    /// a private provider and issues a local-application scope under its own
    /// port, which is the only shape a mailbox can be opened over.
    fn writer_over_grant(
        grant: myownmesh_core::ResourceClaim,
    ) -> (
        myownmesh_core::ResourceMailboxSender<crate::ipc::ServerOut>,
        myownmesh_core::ResourceMailboxReceiver<crate::ipc::ServerOut>,
        myownmesh_core::FiniteResourceProvider,
        myownmesh_core::ResourceProviderPort,
    ) {
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the fixture grant funds its own process scope");
        let mailbox_scope =
            myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
                .expect("the fixture port issues the mailbox's own scope");
        let (tx, rx) = myownmesh_core::resource_mailbox(mailbox_scope)
            .expect("the fixture grant opens one mailbox");
        // The port is returned, not dropped here: the scope the mailbox spends
        // through is a child of it, and a fixture that let the port go would be
        // measuring a provider nothing is still attached to.
        (tx, rx, provider, port)
    }

    /// A pressured writer builds no replacement terminal buffer.
    ///
    /// This is the capacity arm, not the closure arm: the mailbox opens over a
    /// private grant with nothing left after its own planning charge, so
    /// `send_building` gets past the closed check and is refused by the
    /// provider. The terminal is long and real, so what is being refused is a
    /// frame worth refusing.
    ///
    /// What proves the refusal is the ledger, which is what the provider
    /// already exposes to its owner: a refusal that had built its replacement
    /// buffer first would have to charge for it, and the exact return to
    /// baseline says nothing was taken. The grant is private to this control,
    /// so that reading is this call's and no one else's.
    #[tokio::test]
    async fn v4_r5_daemon_a_pressured_writer_builds_no_replacement_terminal_buffer() {
        let scope = crate::test_application_scope();
        let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
        let reason = "y".repeat(64 * 1024);
        inbox
            .finish_owned(&scope, reason.clone())
            .expect("the fixture scope funds one terminal of this width");
        let terminal = match inbox.recv_funded().await {
            Some(Err(terminal)) => terminal,
            _ => panic!("the stream ends with the terminal it was finished with"),
        };

        let (tx, _rx, provider, _port) = writer_over_grant(starved_grant());
        let baseline = provider.in_use();
        let refusal = tx
            .send_building(StreamEndBuilder {
                request_id: "ipc-stream-pressured",
                reason: crate::ipc::wire::TerminalReasonView::Remote(&terminal),
            })
            .expect_err("a writer with no remaining capacity refuses the long terminal");
        assert!(
            matches!(
                refusal,
                myownmesh_core::ResourceMailboxAdmissionError::Pressure(_)
            ),
            "the refusal is capacity, not closure: {refusal:?}"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "a refused admission builds no replacement buffer and returns the exact baseline"
        );
        assert_eq!(
            terminal.reason(),
            reason,
            "core's charge still owns the peer's text after the daemon was refused"
        );
    }

    /// The session charge for a long peer-supplied terminal stays live from the
    /// inbox pop, through writer admission and serialization, and is released
    /// only when the write-side owner lets go.
    ///
    /// On a real two-peer link: the terminal is funded by a real
    /// `SessionCapability` because a real session produced it, not by an
    /// application scope standing in for one.
    ///
    /// `#[ignore]` is load-bearing. The readings are deltas on the daemon test
    /// binary's process-wide provider, which every other daemon control also
    /// spends from, so they are only exact when this runs alone. CI selects it
    /// by exact name with `--ignored`; a full workspace run skips it. An
    /// accounting control whose arithmetic is only usually right is worse than
    /// none, because it fails intermittently and gets dismissed as flake.
    ///
    /// The assertions are deltas rather than a return to an absolute baseline,
    /// deliberately: the link itself is still up at the end, so the ledger does
    /// not go back to where it started and a control claiming it did would be
    /// asserting something false that happened to pass.
    ///
    /// Unix-only, because [`crate::test_resource_ledger`] is. The ledger is the
    /// concrete provider rather than the capability port, and the port erases
    /// it deliberately — there is no reading `in_use` through the port, and a
    /// privately built provider would compile while observing an accounting
    /// nothing under test spends from. The gate belongs on the control rather
    /// than on the helper's caller side so that an all-targets Windows build
    /// still compiles this module.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "reads the process-wide daemon ledger; exact only when run alone"]
    async fn v4_r5_daemon_a_session_funded_long_terminal_stays_live_through_writer_ownership() {
        use myownmesh_core::ResourceClass::AccountedMemoryBytes as Amb;

        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id, drivers) =
            crate::test_link::two_peer_rpc("control-dispatch-terminal").await;

        // Peer-chosen width. The charge under control is text the far end
        // sizes, so a short reason would leave nothing to observe.
        //
        // 32 KiB rather than 64: the data channel's `max_message_size` is
        // 65,536 bytes, and the terminal does not travel bare — it rides
        // inside an RPC envelope. A 64 KiB reason plus that framing exceeds
        // the ceiling, so the link could not carry it and no answer would
        // arrive. Half the ceiling leaves the envelope room while staying far
        // wider than anything a short-string bug could hide behind.
        let reason = "q".repeat(32 * 1024);
        let handler_reason = reason.clone();
        myownmesh_core::rpc::Rpc::attach(&alice_state)
            .expect("the fixture network's application gateway admits an Rpc")
            .serve_stream("terminal_only", move |_call| {
                let reason = handler_reason.clone();
                async move { Err(reason) }
            })
            .expect("the fixture handler claims its method");

        // The ledger, not the port. `in_use` is a figure the concrete provider
        // keeps; the port is the capability and erases it. This is also the
        // instance the engines under test spend through, because
        // `test_application_scope` installs it into the process root.
        let provider = crate::test_resource_ledger();
        let baseline = provider.in_use().amount(Amb);

        // The three link-facing awaits in this control are bounded separately,
        // each with its own message. Unbounded, a stall here does not fail the
        // control — it hangs the CI step that selects this test by exact name,
        // and because those exact-name helpers deliberately run without
        // `--nocapture`, the hang produces no output at all to diagnose from.
        // A named panic per stage is the difference between a silent job that
        // burns its whole limit and one line saying where the link stopped.
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            bob_rpc.call_stream(
                alice_id.public_id(),
                "terminal_only",
                serde_json::json!("go"),
            ),
        )
        .await
        .expect("the peer's stream opens within ten seconds")
        .expect("the real link opens the stream");
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(10), stream.recv_funded())
                .await
                .expect("the peer's terminal arrives within ten seconds");
        let terminal = match received {
            Some(Err(terminal)) => terminal,
            _ => panic!("the handler ends this stream with its error text"),
        };

        // 1. Live after the pop. This is the assertion that fails against the
        //    old shape, where `recv` released the session lease in the same
        //    expression that produced the owned `String`.
        let after_pop = provider.in_use().amount(Amb);
        assert!(
            after_pop >= baseline + reason.len() as u64,
            "the session still funds the peer's text after the inbox pop: \
             {after_pop} < {baseline} + {}",
            reason.len()
        );
        assert_eq!(
            terminal.reason(),
            reason,
            "non-vacuity: the text read by borrow is the one the peer sent"
        );

        // 2. Live through writer admission and serialization.
        let (tx, mut rx) = myownmesh_core::resource_mailbox::<crate::ipc::ServerOut>(
            crate::test_application_scope(),
        )
        .expect("the daemon test grant opens one writer mailbox");
        tx.send_building(StreamEndBuilder {
            request_id: "ipc-stream-session",
            reason: crate::ipc::wire::TerminalReasonView::Remote(&terminal),
        })
        .expect("the writer admits the long terminal");
        let admitted = provider.in_use().amount(Amb);
        assert!(
            admitted >= baseline + reason.len() as u64,
            "the session charge is still live once the frame is admitted and encoded"
        );

        let frame = rx.recv().await.expect("the admitted frame is queued");
        match frame.value() {
            crate::ipc::ServerOut::RpcCallStreamEnd { error, .. } => assert_eq!(
                error.as_deref(),
                Some(reason.as_str()),
                "the forwarded frame carries the peer's text unchanged"
            ),
            other => panic!("the queued frame is the terminal: {other:?}"),
        }

        // 3. The handoff, and the two owners are released one at a time on
        //    purpose. Dropping both together and asserting one combined delta
        //    would pass on the outer frame's own claim alone -- so a session
        //    charge that had leaked, or one that vanished early, would look
        //    exactly like a correct handoff. Separated, each owner has to
        //    account for itself.
        //
        //    First the session terminal, while the queued frame is still alive
        //    and still readable. What comes back here is core's charge for the
        //    peer's text and nothing else.
        let before_terminal = provider.in_use().amount(Amb);
        drop(terminal);
        let after_terminal = provider.in_use().amount(Amb);
        assert!(
            before_terminal.saturating_sub(after_terminal) >= reason.len() as u64,
            "releasing the session terminal returns at least the peer-chosen width: \
             {before_terminal} -> {after_terminal}"
        );
        // The frame is untouched by that release: it owns its own copy, funded
        // by its own claim, and it is still the text the peer sent.
        match frame.value() {
            crate::ipc::ServerOut::RpcCallStreamEnd { error, .. } => assert_eq!(
                error.as_deref(),
                Some(reason.as_str()),
                "the queued frame outlives the session charge that carried its text here"
            ),
            other => panic!("the queued frame is the terminal: {other:?}"),
        }

        //    Then the write-side owner, which must account for its own claim
        //    separately. If this delta were zero the frame had been funded by
        //    the terminal all along, which is the double-ownership the
        //    forwarding seam exists to prevent.
        let before_frame = provider.in_use().amount(Amb);
        drop(frame);
        let after_frame = provider.in_use().amount(Amb);
        assert!(
            before_frame.saturating_sub(after_frame) >= reason.len() as u64,
            "releasing the write-side owner returns its own copy of the text: \
             {before_frame} -> {after_frame}"
        );

        drop((tx, rx, stream));
        tokio::time::timeout(std::time::Duration::from_secs(10), drivers.shutdown())
            .await
            .expect("both engine drivers end within ten seconds");
    }

    /// A grant large enough for the mailbox and nothing else.
    /// Exactly enough to open the writer, and not one item's worth more.
    ///
    /// Three things must fit, and they are the three the fixture builds before
    /// it sends anything:
    ///
    /// - two `scope_planning_charge`s — one for the process scope
    ///   [`myownmesh_core::ResourceProviderPort::new`] opens, one for the child
    ///   scope `transport_lab_child_of` issues. A finite provider retains a
    ///   bookkeeping record per scope, and there are two scopes, not one;
    /// - the mailbox's shared root, priced through
    ///   `reservation_planning_charge` rather than as a bare claim, because the
    ///   provider also keeps a record of holding that reservation. Comparing or
    ///   funding against the bare `root_claim` would be short by exactly that
    ///   record.
    ///
    /// What is deliberately absent is capacity for a single queued item. That
    /// is the whole point of the control: the mailbox opens, and then the first
    /// `send_building` finds nothing left, so it refuses with real `Pressure`
    /// before `build` runs. Any terminal or item slack here would turn the
    /// control into one that proves a frame can be queued.
    fn starved_grant() -> myownmesh_core::ResourceClaim {
        let scopes = myownmesh_core::FiniteResourceProvider::scope_planning_charge()
            .checked_scale(2)
            .expect("two scope bookkeeping records are representable");
        let root = myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
            myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::root_claim()
                .expect("the mailbox root claim is representable"),
        )
        .expect("the mailbox root reservation is priceable");
        scopes
            .checked_add(root)
            .expect("the fixture grant is representable")
    }
}
