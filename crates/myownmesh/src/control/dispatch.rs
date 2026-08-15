//! The operations behind the control protocol's request match.
//!
//! The exhaustive `match` over [`Request`](super::Request) lives with the
//! connection loop in `control.rs`, and stays there: totality is a property of
//! one match over one enum, and per-domain sub-enums would need a `_ =>`
//! somewhere to glue them back together. What lives here is the work an arm
//! delegates to — the per-domain operation modules, the funded realtime and
//! RPC-stream operations, and the frame builders that forward a stream without
//! constructing anything the writer mailbox has not admitted.
//!
//! No function here takes a `Request`. Each takes the fields its arm
//! destructured, so nothing below the total match can be handed a variant it
//! does not handle — the case the `unreachable!` arms used to stand for.
//!
//! This file used to also carry a second, all-`unreachable!` match over every
//! variant, left behind when the real routing moved into the connection loop.
//! It is gone: the loop's match is total, so the compiler enforces what that
//! shell was standing in for.

use std::sync::Arc;

use anyhow::{Context, Result};
use myownmesh_core::{realtime::RealtimeRefusal, transport as core_webrtc};

pub(super) mod channel;
pub(super) mod governance;
pub(super) mod identity;
pub(super) mod network;
pub(super) mod rpc;
pub(super) mod services;
pub(super) mod updater;

use super::{ConnectionCancel, ControlState};
use crate::control::framing::{AdmittedLineOut, FrameAdmission, PreparedLineCapacity};
use crate::control::reply::{
    ControlOut, FundedVariableReply, OperationReplyData, PreparedReply, PreparedText,
    VariableOperationPlan,
};

/// One admitted answer: what to say, and the funding that lets it be said.
///
/// Every operation module hands this back rather than a bare reply, because
/// the reply alone would leave its line to be funded afterwards — the ordering
/// the funding work exists to remove. Handing back the capacity the reply was
/// admitted under makes "this was measured before the operation committed" a
/// property of the return type instead of a convention each arm re-enacts.
///
/// The pairing is also why the connection loop stays the only encoder and the
/// only writer. An operation that could write would need the socket, the
/// cancellation token and the loop's `continue`/`break` control flow; one that
/// answers only says what it wants said, and cannot get the sequence wrong.
pub(in crate::control) type Answer = (PreparedReply, PreparedLineCapacity);

/// Fund the line for a reply that is already decided.
///
/// Most success paths fund *before* committing, which is the whole ordering
/// property, and do not come through here. What does: refusals, which have
/// nothing left to commit because the operation already failed, and the few
/// answers that are pure reads of local state with nothing to commit at all.
/// For both, measuring here is exactly the sequence `write_line` ran when
/// these arms were inline, and no earlier.
pub(in crate::control) fn funded(
    reply: PreparedReply,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&reply), admission)
        .context("control response line was not admitted")?;
    Ok((reply, output))
}

/// Fund a refusal whose text is a fixed string.
pub(in crate::control) fn refused(
    message: &'static str,
    admission: &FrameAdmission,
) -> Result<Answer> {
    funded(PreparedReply::StaticError(message), admission)
}

/// The refusal every network-scoped operation shares: no such joined network.
pub(in crate::control) fn unknown_network(
    network: &str,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let text = PreparedText::unknown_network(network, admission)
        .context("unknown-network refusal text was not admitted")?;
    funded(PreparedReply::Error(text), admission)
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
        #[cfg(test)]
        STREAM_END_BUILDS.with(|builds| builds.set(builds.get().saturating_add(1)));
        crate::ipc::ServerOut::RpcCallStreamEnd {
            request_id: self.request_id.to_owned(),
            error: self.reason.into_owned(),
        }
    }
}

// Terminal frames constructed *on the constructing thread*. A refused write
// must not move it: that is the whole claim of the pressure control below.
//
// Ordinary comments, not doc comments: rustdoc cannot document a macro
// invocation, so `///` here is a doc comment attached to nothing and rustc
// warns about it.
//
// Thread-local rather than a process-wide atomic, and that is the whole of the
// observation's correctness. A shared counter made the reading un-attributable
// in a full workspace run: every other daemon control that drives a stream to
// its end builds terminal frames through this same builder, in parallel, so a
// delta taken across one `send_building` was measuring the whole binary.
// It read 3 where the control under test had built nothing.
//
// A thread-local restores attribution without weakening anything, because
// `send_building` constructs *inline on its caller's thread* — it measures,
// acquires, and only then calls `build`. So a build caused by the call under
// test lands on the thread that made it, and a build caused by anything else
// lands elsewhere and is correctly invisible. The control still asserts a
// delta rather than an absolute zero: a test thread is reused, so what it
// starts at is not this control's business.
#[cfg(test)]
thread_local! {
    static STREAM_END_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn realtime_refusal(plan: VariableOperationPlan, refusal: RealtimeRefusal) -> FundedVariableReply {
    plan.finish(Ok(OperationReplyData::RealtimeRefused {
        error: refusal.to_string(),
        code: refusal.code().to_owned(),
    }))
}

/// Open one realtime flow to a peer and issue the capability that names it.
///
/// The parameters are the request's fields rather than the request, because
/// this used to take a whole `Request` and re-match it under a
/// `_ => unreachable!()`. A caller that got the variant wrong reached a panic;
/// now it cannot compile.
#[allow(clippy::too_many_arguments)]
pub(super) async fn realtime_flow_open(
    state: &Arc<ControlState>,
    plan: VariableOperationPlan,
    network: String,
    peer: String,
    flow_label: String,
    direction: myownmesh_core::realtime::RealtimeFlowDirection,
    rtp_kind: core_webrtc::WebRtcRtpKind,
    mime: String,
    clock_rate: u32,
    channels: u16,
    client_id: crate::ipc::ClientId,
    client_capability: String,
) -> FundedVariableReply {
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
/// Close a realtime flow the client still holds a capability for.
pub(super) async fn realtime_flow_close(
    state: &Arc<ControlState>,
    plan: VariableOperationPlan,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    flow_capability: String,
) -> FundedVariableReply {
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

/// Start a streaming RPC call and forward its chunks to the client's writer.
///
/// Fields, not a `Request`: the let-else this replaced ended in
/// `unreachable!`, which is a runtime claim about who calls it. The signature
/// is now the same claim, checked.
#[allow(clippy::too_many_arguments)]
pub(super) async fn rpc_call_stream_funded(
    state: &Arc<ControlState>,
    cancel: &ConnectionCancel,
    plan: VariableOperationPlan,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    peer: String,
    method: String,
    payload: serde_json::Value,
) -> FundedVariableReply {
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
    plan.finish(Ok(OperationReplyData::RpcStreamStarted(request_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::{ResourceMailboxItem as _, ResourceMailboxItemBuilder as _};

    /// Terminal frames this thread has constructed so far.
    ///
    /// Only ever meaningful as the two ends of a delta taken with no `.await`
    /// between them, which is how the pressure control uses it. Read across a
    /// suspension point it would be measuring a thread rather than a call.
    fn builds() -> usize {
        STREAM_END_BUILDS.with(std::cell::Cell::get)
    }

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
    /// frame worth refusing, and the build counter proves the refusal landed
    /// before construction rather than after it.
    ///
    /// Everything from the first counter read to the last assertion runs with
    /// no `.await` between, deliberately: [`builds`] counts this thread, and a
    /// suspension in the middle would let the reading describe a thread rather
    /// than this call. Nothing here is shared with another control — the grant
    /// is private, and the counter is now per-thread — so the whole control is
    /// safe to run in parallel with the rest of the binary.
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
        let before = builds();
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
            builds(),
            before,
            "the refused terminal frame was never constructed"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "a refused admission returns the exact ledger baseline"
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
    /// This is the review's sentence, on a real two-peer link: the terminal is
    /// funded by a real `SessionCapability` because a real session produced it,
    /// not by an application scope standing in for one.
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

        // Peer-chosen width. The finding is about text the far end sizes, so a
        // short reason would leave nothing to observe.
        //
        // 32 KiB rather than 64: the data channel's `max_message_size` is
        // 65,536 bytes, and the terminal does not travel bare — it rides
        // inside an RPC envelope. A 64 KiB reason plus that framing exceeds
        // the ceiling, so the old fixture was not a control over a wide
        // terminal at all. It asked the link to carry something the link
        // cannot carry, and the answer simply never arrived. Half the ceiling
        // leaves the envelope room while staying far wider than anything a
        // short-string bug could hide behind.
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
