//! Acknowledged channel delivery — the engine's drive loop over state a
//! promoted session owns.
//!
//! The plain send path ([`super::send_to_peer`]) is best-effort: "send now or
//! error". This is the acknowledged contract: a frame is retained until the
//! peer's engine says it arrived, and the caller's wait resolves on that rather
//! than on a local write succeeding.
//!
//! **This module is a driver and holds no state.** Everything retained lives in
//! [`PeerSessionState`](peer_session::PeerSessionState), a field of the peer's
//! promoted session. Each operation resolves an owner, enters the registry
//! fence, and acts on the record the fence lends it.
//!
//! The contract that follows:
//!
//! * **Submission acquires the current session first.** A caller whose peer has
//!   no live session, or whose peer does not speak the acknowledged contract, or
//!   whose frame the provider will not fund retaining, is refused with that
//!   reason. A frame is retained under a session or not at all.
//! * **A frame ends on acknowledgement or with its session.** Session end
//!   resolves the caller with the truth and the application decides whether the
//!   payload still means anything — which it is in a position to know and this
//!   layer is not.
//! * **Revocation and replacement need no code here.** Both drop the promoted
//!   session; the record goes with it and answers every wait on the way out.
//!
//! Delivery is exactly-once within a session: frames ride a `(stream, seq)`
//! pair, the receiver drops seqs at or below its high-water mark and
//! acknowledges cumulatively, so a retransmit cannot double-deliver. `stream` is
//! minted per session, which is what lets a late acknowledgement for a replaced
//! session be recognised and discarded rather than applied to the replacement's
//! frames.
//!
//! Everything here runs on the engine driver task (via the command queue and the
//! state-watch tick), so the record is mutated serially; the fence it is reached
//! through orders it against replacement.

use std::sync::Arc;

use tokio::sync::oneshot;
use tracing::trace;

use crate::error::Result;
use crate::protocol::{features, MeshMessage};
use crate::runtime::peer_session;

use super::peer_registry::PeerOwnerToken;
use super::state::NetworkState;
use super::traffic;

/// Retain one frame for acknowledged delivery to `peer`, or tell the caller why
/// not, then try once to put it on the wire.
///
/// The caller's wait is answered by exactly one place: the session record it is
/// handed to. Every refusal here happens *before* that hand-off and answers it
/// directly, so there is no arm on which a caller is answered twice or not at
/// all.
///
/// The feature read is deliberately outside the fence and deliberately allowed
/// to be one instant stale. It decides whether this peer speaks the
/// acknowledged contract at all — a property of the peer's build, not of its
/// admission — and nothing is written on the strength of it. Every fact that
/// authorizes the retention is read inside the fence, at the moment of use.
pub(crate) async fn submit(
    state: &Arc<NetworkState>,
    peer: &str,
    channel: &str,
    payload: serde_json::Value,
    reply: oneshot::Sender<Result<()>>,
) {
    let Some(owner) = state.peers.owner(peer) else {
        let _ = reply.send(Err(peer_session::no_session_error(peer)));
        return;
    };
    let acked_contract = state
        .peers
        .get_if_current(&owner)
        .map(|entry| {
            let data = entry.state.read();
            features::peer_supports(&data.features, features::Feature::RELIABLE_CHANNELS)
        })
        .unwrap_or(false);
    if !acked_contract {
        // Refused, not downgraded: local send success is an answer about this
        // process's socket, and this caller asked about the peer's application
        // layer.
        let _ = reply.send(Err(peer_session::unsupported_error(peer)));
        return;
    }
    // Both the payload and the caller's wait are lent to the closure through
    // `Option`s rather than moved into it. A fence that refuses never runs the
    // closure, and a `oneshot::Sender` that is merely dropped resolves its
    // caller with a bare receive error that names nothing — so the values have
    // to come back out on that arm to be answered here. The closure runs at most
    // once, so each `take` is unconditional when it does.
    let mut handoff = Some((payload, reply));
    state.peers.with_live_session_state(
        &owner,
        state.session_broker.as_ref(),
        &state.network_id,
        |session, record| {
            let (payload, reply) = handoff
                .take()
                .expect("the fence runs this closure at most once");
            record.submit(session, channel, payload, reply);
        },
    );
    if let Some((_payload, reply)) = handoff {
        let _ = reply.send(Err(peer_session::no_session_error(peer)));
        return;
    }
    flush_owner(state, &owner).await;
}

/// Drain the frames the peer's live session still owes the wire, in order.
///
/// One frame per fence entry, deliberately. The write leaves the fence, so a
/// batch collected under one acquisition would be a list of frames authorized by
/// a session that may not be current by the time the second one goes out.
/// Re-entering per frame re-proves the session per frame, and the cost of that
/// is a mutex acquisition against a write that already crosses the network.
///
/// Stops at the first failure rather than skipping ahead: the receiver's
/// contract is in-order, and a gap would stall its high-water mark behind a
/// frame that never arrives. Whatever is left stays retained until the peer
/// acknowledges it or the session ends.
pub(super) async fn flush_owner(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    loop {
        let next = state
            .peers
            .with_live_session_state(
                owner,
                state.session_broker.as_ref(),
                &state.network_id,
                |_session, record| record.next_unsent(),
            )
            .flatten();
        let Some((seq, frame)) = next else {
            return;
        };
        if let Err(e) =
            super::send_application_bytes(state, owner, frame, traffic::FrameClass::App).await
        {
            trace!(
                peer = %super::short_peer(owner.device_id()),
                "reliable flush paused: {e}"
            );
            return;
        }
        // Recorded through the fence again rather than on a handle held across
        // the send: if the session was replaced during the write, there is no
        // record to mark, and the frame that was written belonged to a session
        // that has since resolved its callers. Marking through a stale handle
        // would set `sent` on a replacement's frame that was never sent.
        state.peers.with_live_session_state(
            owner,
            state.session_broker.as_ref(),
            &state.network_id,
            |_session, record| record.mark_sent(seq),
        );
    }
}

/// What the admission fence already settled for one inbound reliable frame.
///
/// Carries removed entries, not a verdict: nothing decided under the fence is
/// re-decided outside it. In particular it carries **no boolean**.
///
/// The receive side's own state — the inbound high-water mark — is deliberately
/// absent from this type. Advancing the mark and delivering the payload have to
/// be one step, and the payload is only available on the dispatch side, so both
/// happen together there under
/// [`AdmittedInboundDispatch::with_captured_session_state`](super::peer_registry::AdmittedInboundDispatch::with_captured_session_state).
pub(super) enum InboundReliableAdmission {
    /// Nothing was settled under the fence — either not a reliable-stream frame
    /// at all, or a `ChannelSeq`, whose mark and delivery move together on the
    /// dispatch side instead.
    Nothing,
    /// A `ChannelAck`. The frames it settles were released under the fence,
    /// together with their leases; these are the caller waits still to resolve.
    Ack(Vec<oneshot::Sender<Result<()>>>),
}

impl InboundReliableAdmission {
    /// Resolve the caller waits a fenced acknowledgement settled.
    ///
    /// Deferred out of the fence deliberately, and safely: these receivers are
    /// local caller futures, not peer state and not anything a replacement can
    /// observe.
    pub(super) fn settle(self) {
        if let Self::Ack(replies) = self {
            for reply in replies {
                let _ = reply.send(Ok(()));
            }
        }
    }
}

/// Release the frames one inbound acknowledgement settles, **inside the
/// registry admission fence**.
///
/// Called from the fence rather than after it because an acknowledgement
/// admitted for installation A and applied after A was replaced would settle
/// frames installation B retained. It cannot do that now — B's session has a
/// different stream and the record is not shared — but the ordering is what
/// makes the acknowledgement and the release one act, so no reader observes
/// frames released for an acknowledgement that was refused.
///
/// A `ChannelSeq` is deliberately not handled here. Its receive-side effect is
/// two things that must be indivisible — advancing the high-water mark and
/// handing the payload to the subscribers — and the payload leaves this fence
/// with the frame, so the dispatch side runs both, together, under its own
/// fence.
pub(super) fn admit_inbound_reliable(
    admitted: &super::peer_registry::AdmittedSessionOperation<'_>,
    msg: &MeshMessage,
) -> InboundReliableAdmission {
    match msg {
        MeshMessage::ChannelAck { stream, up_to } => admitted
            .with_session_state(|_session, record| {
                InboundReliableAdmission::Ack(record.take_acknowledged(*stream, *up_to))
            })
            .unwrap_or(InboundReliableAdmission::Nothing),
        _ => InboundReliableAdmission::Nothing,
    }
}

/// Receive one inbound `channel_seq`: move the high-water mark, deliver,
/// acknowledge.
///
/// The first two are one fenced step, and now one *borrow*: the mark lives in
/// the same record the delivery is authorized by, so they are reached together
/// or not at all. Combined with
/// [`PeerSessionState::advance_inbound_and_deliver`](peer_session::PeerSessionState::advance_inbound_and_deliver)'s
/// own biconditional, this session's mark records a seq exactly when its payload
/// was handed to the subscribers.
///
/// Both sides of the ordering against replacement are truthful:
///
/// * A replacement landing **before** the fence refuses the closure outright.
///   Nothing is marked, delivered or acknowledged — so the sender retransmits
///   and the frame is still fresh when it arrives.
/// * A replacement landing **after** it may make the owner-bound acknowledgement
///   fail, since the send refuses to go through a replacement under the same
///   device id. The sender then retransmits, and that retransmit really is a
///   duplicate: the payload was already delivered under the installation it was
///   admitted for.
///
/// A duplicate is re-acknowledged and not re-delivered, which is what stops a
/// sender whose earlier acknowledgement was lost.
pub(super) async fn on_channel_seq_admitted(
    state: &Arc<NetworkState>,
    dispatch: &super::peer_registry::AdmittedInboundDispatch,
    stream: u64,
    seq: u64,
    channel: String,
    payload: serde_json::Value,
) {
    let owner = dispatch.owner();
    // Delivery is an application effect whose escape is visible outside the
    // engine: a subscriber reads `from` as a device identity, so a payload
    // admitted for one installation and delivered after that installation was
    // replaced is attributed to whoever holds the id now. Both the attribution
    // and the mark are therefore settled inside the fence.
    //
    // `dispatch_channel_frame` is a broadcast hand-off: it never blocks on a
    // subscriber and never re-enters the registry, so it is safe under the
    // mutation lock.
    let Some(ack_up_to) = dispatch.with_captured_session_state(&state.peers, |_session, record| {
        record.advance_inbound_and_deliver(stream, seq, payload, |payload| {
            state.dispatch_channel_frame(&channel, owner.device_id(), payload)
        })
    }) else {
        // Superseded installation, or one holding no live session: the frame
        // moved nothing and reached nobody, so there is nothing to acknowledge
        // either. Acknowledging here would tell the sender a payload had been
        // received that no subscriber ever saw.
        return;
    };
    let msg = MeshMessage::ChannelAck {
        stream,
        up_to: ack_up_to,
    };
    if let Err(e) = super::send_to_peer_owner(state, owner, &msg).await {
        trace!(
            peer = %super::short_peer(owner.device_id()),
            "channel_ack send failed: {e}"
        );
    }
}

/// State-watch tick: re-attempt flushes for peers whose session still holds
/// unsent frames.
///
/// Flush only, and there is nothing here to expire against: a retained frame
/// ends when the peer acknowledges it or when the session retaining it ends, and
/// this loop is the arbiter of neither. A deadline enforced here would report a
/// choice this process made as though it were a fact about the peer.
pub(crate) async fn tick(state: &Arc<NetworkState>) {
    for owner in state.peers.owners_with_unsent_reliable_frames() {
        flush_owner(state, &owner).await;
    }
}

/// The exact encoded frame one submission retains, for controls that must send
/// or size a frame the record would actually accept.
#[cfg(all(test, feature = "transport-lab"))]
pub(super) fn encoded_frame_for_test(
    stream: u64,
    seq: u64,
    channel: &str,
    payload: &str,
) -> bytes::Bytes {
    bytes::Bytes::from(
        serde_json::to_vec(&MeshMessage::ChannelSeq {
            stream,
            seq,
            channel: channel.to_string(),
            payload: serde_json::json!(payload),
        })
        .expect("a control frame of owned strings serializes"),
    )
}
