//! Acknowledged channel delivery — the engine's queue-until-delivered
//! contract for application frames.
//!
//! The plain send path ([`super::send_to_peer`]) is best-effort by
//! design: "send now or error". Every embedder that needed more built
//! its own retransmit loop on top (a 2 s connect-request beat, presence
//! re-beacons, re-assert-on-reconnect phases). This module is that
//! contract, built once where the connection state actually lives:
//!
//! * **Enqueue any time.** A send to a peer whose link isn't up yet —
//!   or that just dropped — parks in the per-peer outbox instead of
//!   erroring.
//! * **Flush on link-up.** The moment a peer goes ACTIVE the outbox
//!   drains in order. A session rebuild marks in-flight entries unsent,
//!   so they retransmit on the next ACTIVE — the entry, not the caller,
//!   survives the reconnect.
//! * **Exactly-once delivery.** Frames ride a `(stream, seq)` pair;
//!   the receiver drops seqs at or below its high-water mark and acks
//!   cumulatively, so a retransmit can't double-deliver. `stream` is
//!   minted per outbox lifetime, so a daemon restart (fresh seq=1) is
//!   distinguishable from a replay.
//! * **Bounded.** Outboxes cap at [`OUTBOX_CAP`] entries and every
//!   entry carries a TTL ([`DEFAULT_TTL_MS`] unless the caller picks);
//!   expiry resolves the caller's wait with an error instead of
//!   pretending.
//!
//! Peers that don't advertise [`Feature::RELIABLE_CHANNELS`] get the
//! best available degradation: entries still queue until the link is
//! up, then ride a plain `channel` frame — the caller's wait resolves
//! on successful *send* rather than acknowledged *delivery*.
//!
//! Everything here runs on the engine driver task (via the command
//! queue and the state-watch tick), so outbox mutation is serial; that
//! mutex only guards against snapshot readers. The inbound mark's mutex
//! carries one real invariant on top of that: `advance_inbound_mark_and_deliver`
//! advances a mark and hands the payload on under a single acquisition,
//! so the two can never be observed apart.
//!
//! Both tables are keyed by *device id*, so successive peer installations
//! under one id share them. That is deliberate — a reconnect must not
//! lose a queued outbox or re-deliver everything the previous
//! installation already acked — and it is why every inbound mutation
//! here is called from inside a registry fence rather than after one.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

use crate::error::{Error, Result};
use crate::protocol::{features, MeshMessage};

use super::state::{NetworkState, PeerOwnerToken};

/// Default time an entry may wait for acknowledged delivery before its
/// caller is told the truth. Long enough to ride out a reconnect (ICE
/// rebuild lands well inside it), short enough that "the peer is gone"
/// isn't discovered minutes later.
pub const DEFAULT_TTL_MS: u64 = 60_000;

/// Per-peer outbox ceiling. A caller that outruns delivery this far is
/// backpressured with an error instead of growing memory unboundedly.
pub const OUTBOX_CAP: usize = 256;

/// One queued frame awaiting acknowledged delivery.
struct Pending {
    seq: u64,
    channel: String,
    payload: serde_json::Value,
    /// When the entry lapses; expiry resolves `reply` with an error.
    expires_at: Instant,
    /// Whether the frame is on the wire for the *current* session.
    /// Reset to `false` on session rebuild so the retransmit happens.
    sent: bool,
    /// The caller's wait, resolved on ack (or send, for a fallback
    /// peer), TTL expiry, or terminal peer failure.
    reply: Option<oneshot::Sender<Result<()>>>,
}

/// The per-peer send side: one stream id for this outbox's lifetime and
/// the in-order queue of pending entries.
pub(crate) struct Outbox {
    stream: u64,
    next_seq: u64,
    entries: VecDeque<Pending>,
}

impl Outbox {
    fn new() -> Self {
        use rand::Rng;
        Self {
            // Random per outbox lifetime — a daemon restart mints a new
            // stream, which is what lets the receiver treat "seq went
            // backwards" as a reset instead of a replay.
            stream: rand::thread_rng().gen::<u64>() | 1,
            next_seq: 0,
            entries: VecDeque::new(),
        }
    }

    /// Entries currently queued (sent-but-unacked included).
    pub(crate) fn depth(&self) -> usize {
        self.entries.len()
    }

    /// This outbox's stream id. Controls need it to build an ack frame that
    /// this outbox would actually accept, so a refusal under test is provably
    /// the admission fence and not a stale-stream mismatch.
    #[cfg(test)]
    pub(super) fn stream_for_test(&self) -> u64 {
        self.stream
    }
}

/// Receiver-side high-water mark for one peer's inbound stream.
#[derive(Clone, Copy, Default)]
pub(crate) struct InboundMark {
    stream: u64,
    last_seq: u64,
}

impl InboundMark {
    /// The seq this mark records as received. Controls in the engine's own
    /// module assert it in the same breath as delivery, because the contract
    /// [`advance_inbound_mark_and_deliver`] holds is that the two move together
    /// — a mark read alone would prove only half of it.
    #[cfg(test)]
    pub(super) fn last_seq_for_test(&self) -> u64 {
        self.last_seq
    }
}

/// Queue a frame for acknowledged delivery to `peer`, then try to flush
/// immediately (a no-op if the link isn't up — the ACTIVE transition
/// and the state-watch tick pick it up later).
pub(crate) async fn enqueue(
    state: &Arc<NetworkState>,
    peer: &str,
    channel: &str,
    payload: serde_json::Value,
    ttl_ms: Option<u64>,
    reply: oneshot::Sender<Result<()>>,
) {
    {
        let mut out = state.reliable_out.lock();
        let outbox = out.entry(peer.to_string()).or_insert_with(Outbox::new);
        if outbox.entries.len() >= OUTBOX_CAP {
            drop(out);
            let _ = reply.send(Err(Error::Transport(format!(
                "reliable outbox for {peer} is full ({OUTBOX_CAP} frames pending)"
            ))));
            return;
        }
        outbox.next_seq += 1;
        let seq = outbox.next_seq;
        let ttl = Duration::from_millis(ttl_ms.unwrap_or(DEFAULT_TTL_MS));
        outbox.entries.push_back(Pending {
            seq,
            channel: channel.to_string(),
            payload,
            expires_at: Instant::now() + ttl,
            sent: false,
            reply: Some(reply),
        });
    }
    flush_peer(state, peer).await;
}

/// Whether `peer`'s link can carry frames right now, and whether it
/// speaks the acked contract. `None` = not sendable yet.
fn link_ready(state: &Arc<NetworkState>, peer: &str) -> Option<bool> {
    let entry = state.peers.get(peer)?;
    // Readiness is transport liveness only. Admission is deliberately *not*
    // snapshotted here: this answer is read before the batch is collected and
    // acted on after several awaits, so an admission decision taken at this
    // point would be stale by the time anything is written. Each frame is
    // authorized where it is actually sent, by the witness `send_to_peer`
    // requires — so a peer that loses admission mid-flush stops sending there,
    // not because a boolean read earlier happened to be false.
    let data = entry.state.read();
    if !data.data_channel_open {
        return None;
    }
    Some(features::peer_supports(
        &data.features,
        features::Feature::RELIABLE_CHANNELS,
    ))
}

/// The transport-liveness answer, for controls that must state it explicitly.
///
/// Read-only and non-authoritative: it reports whether the link can carry
/// frames, which is exactly the fact an outbound-admission control has to pin
/// down before it can claim the refusal came from admission rather than from a
/// link that was never up.
#[cfg(test)]
pub(super) fn link_ready_for_test(state: &Arc<NetworkState>, peer: &str) -> Option<bool> {
    link_ready(state, peer)
}

/// Drain `peer`'s unsent entries onto the wire, in order. Safe to call
/// any time; does nothing when the link is down. Called on the ACTIVE
/// transition, after each enqueue, on inbound acks, and from the
/// state-watch tick.
pub(crate) async fn flush_peer(state: &Arc<NetworkState>, peer: &str) {
    let acked_peer = link_ready(state, peer);
    flush_peer_inner(state, peer, None, acked_peer).await;
}

/// Drain only through the exact peer installation that completed admission.
/// A replacement under the same public device id cannot receive this batch.
pub(crate) async fn flush_peer_owner(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    let peer = owner.device_id();
    // Transport liveness only, for the same reason as `link_ready`: the actual
    // send consumes the admission witness.
    let acked_peer = state.peers.get_if_current(owner).and_then(|entry| {
        let data = entry.state.read();
        data.data_channel_open
            .then(|| features::peer_supports(&data.features, features::Feature::RELIABLE_CHANNELS))
    });
    flush_peer_inner(state, peer, Some(owner), acked_peer).await;
}

async fn flush_peer_inner(
    state: &Arc<NetworkState>,
    peer: &str,
    owner: Option<&PeerOwnerToken>,
    acked_peer: Option<bool>,
) {
    let Some(acked_peer) = acked_peer else {
        return;
    };

    // Collect what needs sending without holding the lock across awaits.
    let (stream, to_send): (u64, Vec<(u64, String, serde_json::Value)>) = {
        let mut out = state.reliable_out.lock();
        let Some(outbox) = out.get_mut(peer) else {
            return;
        };
        let stream = outbox.stream;
        let batch: Vec<_> = outbox
            .entries
            .iter()
            .filter(|p| !p.sent)
            .map(|p| (p.seq, p.channel.clone(), p.payload.clone()))
            .collect();
        (stream, batch)
    };
    if to_send.is_empty() {
        return;
    }

    for (seq, channel, payload) in to_send {
        let msg = if acked_peer {
            MeshMessage::ChannelSeq {
                stream,
                seq,
                channel: channel.clone(),
                payload: payload.clone(),
            }
        } else {
            // Fallback peer: plain frame, no ack coming. The entry
            // resolves on send success below.
            MeshMessage::Channel {
                channel: channel.clone(),
                payload: payload.clone(),
            }
        };
        let send_result = match owner {
            Some(owner) => super::send_to_peer_owner(state, owner, &msg).await,
            None => super::send_to_peer(state, peer, &msg).await,
        };
        match send_result {
            Ok(()) => {
                let mut out = state.reliable_out.lock();
                let Some(outbox) = out.get_mut(peer) else {
                    return;
                };
                if acked_peer {
                    if let Some(p) = outbox.entries.iter_mut().find(|p| p.seq == seq) {
                        p.sent = true;
                    }
                } else {
                    // Best-effort degradation: successful local send is the
                    // strongest result this compatibility peer can report.
                    if let Some(pos) = outbox.entries.iter().position(|p| p.seq == seq) {
                        if let Some(reply) = outbox.entries.remove(pos).and_then(|p| p.reply) {
                            let _ = reply.send(Ok(()));
                        }
                    }
                }
            }
            Err(e) => {
                // Link wobbled mid-flush — leave the entry unsent; the
                // tick or the next ACTIVE retries. In-order delivery
                // means we stop rather than skip ahead.
                trace!(peer = %super::short_peer(peer), "reliable flush paused: {e}");
                break;
            }
        }
    }
}

/// What the admission fence already settled for one inbound reliable frame.
///
/// Both reliable-stream tables are keyed by *device id*, so successive
/// installations under one id share them. A frame admitted for installation A,
/// applied after A was replaced, would drain an outbox that installation B then
/// reads as its own — so the outbox removal happens inside the registry
/// admission fence, under the same acquisition that admitted the frame, and
/// only its *result* travels out.
///
/// Nothing decided here is re-decided outside: this carries removed entries, not
/// a verdict. In particular it carries **no boolean**. The receive side's own
/// state — the inbound high-water mark — is deliberately absent from this type
/// for that reason: advancing the mark and delivering the payload have to be one
/// step, and the payload is only available on the dispatch side, so both happen
/// together there under [`super::state::AdmittedInboundDispatch::with_captured_peer`].
/// See [`advance_inbound_mark_and_deliver`].
pub(crate) enum InboundReliableAdmission {
    /// Nothing was settled under the fence — either not a reliable-stream frame
    /// at all, or a `ChannelSeq`, whose mark and delivery move together on the
    /// dispatch side instead.
    Nothing,
    /// A `ChannelAck`. The outbox entries it settles were already removed under
    /// the fence; these are the caller waits still to resolve.
    Ack(Vec<oneshot::Sender<Result<()>>>),
}

impl InboundReliableAdmission {
    /// Resolve the caller waits a fenced ack settled.
    ///
    /// Deferred out of the fence deliberately, and safely: these receivers are
    /// local caller futures, not peer state and not anything a replacement can
    /// observe. Firing a oneshot under the registry mutation lock would let a
    /// waiter's continuation run inside it.
    pub(crate) fn settle(self) {
        if let Self::Ack(replies) = self {
            for reply in replies {
                let _ = reply.send(Ok(()));
            }
        }
    }
}

/// Move the device-id-keyed *send*-side reliable state for one inbound frame.
///
/// **Call only from inside the registry admission fence.** See
/// [`InboundReliableAdmission`] for why this cannot be deferred to the async
/// dispatch. Takes `&NetworkState` rather than the peer, because what it moves
/// is per-device-id stream state, not per-installation peer state.
///
/// A `ChannelSeq` is deliberately not handled here. Its receive-side effect is
/// two things that must be indivisible — advancing the high-water mark and
/// handing the payload to the subscribers — and the payload leaves this fence
/// with the frame, so it is the dispatch side that runs both, together, under
/// its own fence. Answering a `deliver` verdict here and delivering there is
/// precisely the gap this shape removes.
pub(crate) fn admit_inbound_reliable(
    state: &NetworkState,
    peer: &str,
    msg: &MeshMessage,
) -> InboundReliableAdmission {
    match msg {
        MeshMessage::ChannelAck { stream, up_to } => {
            InboundReliableAdmission::Ack(take_acked_replies(state, peer, *stream, *up_to))
        }
        _ => InboundReliableAdmission::Nothing,
    }
}

/// Advance `peer`'s inbound high-water mark and hand a fresh payload to
/// `deliver` as one indivisible step, answering the cumulative mark to ack.
///
/// The mark advances **iff** `deliver` is invoked: both happen under one
/// acquisition of the mark table, so no reader — and no later frame on this
/// stream — can observe a seq recorded as received that was never handed on.
/// That biconditional is the whole point. A mark advanced without delivery
/// makes the sender's retransmit look like a duplicate, so it is acked, and the
/// caller's `enqueue` resolves `Ok` for a payload delivered nowhere.
///
/// **Call only from inside the registry fence**, so that the installation the
/// payload was admitted for is still the installed one for the whole step. That
/// makes `deliver` a synchronous, non-reentrant closure by construction: it may
/// hand a value off (a broadcast send), but it must not await, run embedder
/// code, or call back into [`super::state::PeerRegistry`].
///
/// A duplicate — a seq at or below the mark — is not delivered and moves
/// nothing, but still answers the mark, because a duplicate usually means our
/// previous ack was lost and re-acking is what stops the retransmits.
pub(super) fn advance_inbound_mark_and_deliver(
    state: &NetworkState,
    peer: &str,
    stream: u64,
    seq: u64,
    payload: serde_json::Value,
    deliver: impl FnOnce(serde_json::Value),
) -> u64 {
    let mut marks = state.reliable_in.lock();
    let mark = marks.entry(peer.to_string()).or_default();
    if mark.stream != stream {
        // New outbox lifetime on the sender (restart) — adopt it.
        *mark = InboundMark {
            stream,
            last_seq: 0,
        };
    }
    if seq > mark.last_seq {
        mark.last_seq = seq;
        deliver(payload);
    }
    mark.last_seq
}

/// Remove every outbox entry of `stream` at or below `up_to` and hand back the
/// caller waits they owe. Split from the send so the removal can happen inside
/// the admission fence while the resolution happens outside it.
fn take_acked_replies(
    state: &NetworkState,
    peer: &str,
    stream: u64,
    up_to: u64,
) -> Vec<oneshot::Sender<Result<()>>> {
    let mut out = state.reliable_out.lock();
    let Some(outbox) = out.get_mut(peer) else {
        return Vec::new();
    };
    if outbox.stream != stream {
        // Ack for a previous outbox lifetime — nothing it can settle.
        return Vec::new();
    }
    let mut done = Vec::new();
    while let Some(front) = outbox.entries.front() {
        if front.seq > up_to {
            break;
        }
        if let Some(reply) = outbox.entries.pop_front().and_then(|p| p.reply) {
            done.push(reply);
        }
    }
    if outbox.entries.is_empty() {
        out.remove(peer);
    }
    done
}

/// Receive one inbound `channel_seq`: move the high-water mark, deliver, ack.
///
/// The first two are one fenced step. `with_captured_peer` holds the registry
/// mutation lock across the whole closure, and replacement takes that same lock,
/// so it orders strictly before or after — never between the mark and the
/// delivery. Combined with [`advance_inbound_mark_and_deliver`]'s own
/// biconditional, this peer's mark records a seq exactly when its payload was
/// handed to the subscribers.
///
/// The two sides of that ordering are both truthful:
///
/// * A replacement landing **before** the fence refuses the closure outright.
///   Nothing is marked, nothing is delivered, and nothing is acked — so the
///   sender retransmits and the frame is still fresh when it arrives.
/// * A replacement landing **after** it may make the owner-bound ack fail, since
///   `send_to_peer_owner` refuses to ack through a replacement under the same
///   device id. The sender then retransmits, and that retransmit really is a
///   duplicate: the payload was already delivered under the installation it was
///   admitted for.
///
/// A duplicate is re-acked and not re-delivered, which is what stops a sender
/// whose earlier ack was lost.
pub(super) async fn on_channel_seq_admitted(
    state: &Arc<NetworkState>,
    dispatch: &super::state::AdmittedInboundDispatch,
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
    // mutation lock and under the mark table's.
    let Some(ack_up_to) = dispatch.with_captured_peer(&state.peers, |_peer| {
        advance_inbound_mark_and_deliver(
            state,
            owner.device_id(),
            stream,
            seq,
            payload,
            |payload| state.dispatch_channel_frame(&channel, owner.device_id(), payload),
        )
    }) else {
        // Superseded installation: the frame moved nothing and reached nobody,
        // so there is nothing to acknowledge either. Acking here would tell the
        // sender a payload had been received that no subscriber ever saw.
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

/// Session rebuild for `peer`: everything on the wire for the old
/// session may or may not have landed — mark it unsent so the next
/// ACTIVE retransmits, and let the receiver's high-water mark absorb
/// any double.
pub(crate) fn mark_unsent(state: &NetworkState, peer: &str) {
    let mut out = state.reliable_out.lock();
    if let Some(outbox) = out.get_mut(peer) {
        for p in outbox.entries.iter_mut() {
            p.sent = false;
        }
    }
}

/// Terminal failure for `peer` (denied, auth failure, deliberate
/// removal): the queue has no future — resolve every pending wait with
/// the reason and drop the outbox.
pub(crate) fn fail_peer(state: &NetworkState, peer: &str, reason: &str) {
    let entries: Vec<Pending> = {
        let mut out = state.reliable_out.lock();
        match out.remove(peer) {
            Some(outbox) => outbox.entries.into_iter().collect(),
            None => return,
        }
    };
    let n = entries.len();
    for p in entries {
        if let Some(reply) = p.reply {
            let _ = reply.send(Err(Error::Transport(format!(
                "reliable send to {peer} abandoned: {reason}"
            ))));
        }
    }
    if n > 0 {
        debug!(peer = %super::short_peer(peer), dropped = n, reason, "reliable outbox abandoned");
    }
}

/// State-watch tick: expire lapsed entries (their callers get an error,
/// not silence) and re-attempt flushes for peers holding unsent frames.
pub(crate) async fn tick(state: &Arc<NetworkState>) {
    let now = Instant::now();
    // Expiry pass.
    let mut expired: Vec<(String, oneshot::Sender<Result<()>>)> = Vec::new();
    let mut flush_candidates: Vec<String> = Vec::new();
    {
        let mut out = state.reliable_out.lock();
        out.retain(|peer, outbox| {
            let mut i = 0;
            while i < outbox.entries.len() {
                if outbox.entries[i].expires_at <= now {
                    if let Some(p) = outbox.entries.remove(i) {
                        if let Some(reply) = p.reply {
                            expired.push((peer.clone(), reply));
                        }
                    }
                } else {
                    i += 1;
                }
            }
            if outbox.entries.iter().any(|p| !p.sent) {
                flush_candidates.push(peer.clone());
            }
            !outbox.entries.is_empty()
        });
    }
    for (peer, reply) in expired {
        warn!(peer = %super::short_peer(&peer), "reliable send expired before delivery");
        let _ = reply.send(Err(Error::Transport(format!(
            "reliable send to {peer} expired before delivery"
        ))));
    }
    for peer in flush_candidates {
        flush_peer(state, &peer).await;
    }
}

/// Total frames awaiting delivery across all peers — surfaced in the
/// network's traffic/status snapshot.
pub(crate) fn pending_total(state: &NetworkState) -> usize {
    state.reliable_out.lock().values().map(Outbox::depth).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::connection::PeerStatus;
    use crate::engine::{build_test_state, insert_session_less_peer};

    fn recv_now(rx: &mut oneshot::Receiver<Result<()>>) -> Option<Result<()>> {
        rx.try_recv().ok()
    }

    /// One application-class send through the exact function `flush_peer_inner`
    /// calls, asserted to be refused by the admission fence itself.
    ///
    /// Both halves matter: the error must be the fence's, and the fence must
    /// mint no witness. A control that only checked the string would still pass
    /// if some later layer happened to produce a similar message.
    async fn assert_admission_refuses_the_flush_send(
        state: &Arc<NetworkState>,
        owner: &PeerOwnerToken,
        frame: &MeshMessage,
    ) {
        let error = crate::engine::send_to_peer_owner(state, owner, frame)
            .await
            .expect_err("an unadmitted owner cannot carry application traffic");
        assert!(
            error
                .to_string()
                .contains("no live promoted session for application traffic"),
            "the refusal must come from the session gate, got: {error}"
        );
        assert!(
            state
                .peers
                .with_admitted_current(
                    owner,
                    state.session_broker.as_ref(),
                    &state.network_id,
                    |_| ()
                )
                .is_none(),
            "and the fence must mint no witness for it"
        );
    }

    #[tokio::test]
    async fn v4_arc03_reliable_flush_requires_authenticated_admission() {
        // Readiness and admission are now separate contracts: `link_ready`
        // answers transport liveness only, and every frame is authorized where
        // it is actually sent. So this fixture holds readiness *true* at every
        // step and varies only admission — which makes each refusal below
        // attributable to the gate rather than to a link that was never up.
        let state = build_test_state("arc03-reliable-admission");
        insert_session_less_peer(&state, "peer", None);
        {
            let peer = state.peers.get("peer").expect("peer is installed");
            let mut data = peer.state.write();
            data.status = PeerStatus::Active;
            data.data_channel_open = true;
            data.features = vec![features::Feature::RELIABLE_CHANNELS.to_string()];
            data.authenticated = false;
        }
        let owner = state.peers.owner("peer").expect("peer is installed");
        let frame = MeshMessage::Channel {
            channel: "reliable-negative".to_string(),
            payload: serde_json::json!("must-not-send"),
        };

        // Unauthenticated: the link is ready and speaks the acked contract, and
        // the send is still refused.
        assert_eq!(
            link_ready(&state, "peer"),
            Some(true),
            "non-vacuity: the link is ready and acked-capable before authentication"
        );
        assert_admission_refuses_the_flush_send(&state, &owner, &frame).await;

        // The reliable path itself, not just the primitive underneath it:
        // `enqueue`'s immediate flush runs `flush_peer` — the device-id branch,
        // with `owner: None` — and readiness lets it reach the send, so the
        // entry can only stay queued because admission refused it.
        let (reply, mut waiter) = oneshot::channel();
        enqueue(
            &state,
            "peer",
            "reliable-negative",
            serde_json::json!("must-not-send"),
            None,
            reply,
        )
        .await;
        assert_eq!(
            pending_total(&state),
            1,
            "the entry stays queued: a ready link could not carry it without admission"
        );
        assert!(
            recv_now(&mut waiter).is_none(),
            "and the caller is neither resolved nor failed — the entry is retriable"
        );

        // The legacy bool alone is no longer sufficient: the Arc 04 gate
        // requires a live authenticated-channel capability, so this stays
        // refused. Keeping it as an explicit negative is the point — it is the
        // case that would silently regress if the gate fell back to the bool.
        state
            .peers
            .get("peer")
            .expect("peer is installed")
            .state
            .write()
            .authenticated = true;
        assert!(
            state
                .peers
                .get("peer")
                .expect("peer is installed")
                .state
                .read()
                .is_admitted(),
            "non-vacuity: legacy policy really does consider this peer admitted"
        );
        assert_eq!(
            link_ready(&state, "peer"),
            Some(true),
            "readiness is unchanged, so it explains nothing about the refusal"
        );
        assert_admission_refuses_the_flush_send(&state, &owner, &frame).await;

        // The exact-owner flush branch, driven explicitly this time, on the
        // same still-queued entry.
        flush_peer_owner(&state, &owner).await;
        assert_eq!(
            pending_total(&state),
            1,
            "policy alone does not drain the outbox either"
        );
        assert!(
            recv_now(&mut waiter).is_none(),
            "and the caller is still waiting"
        );

        // A real capability is installed, and the fence *still* mints nothing —
        // which is the point after the session cutover. A capability plus policy
        // no longer opens admission by itself; a promoted session does, and this
        // fixture has neither a connector worker to promote from nor a broker,
        // since it installs no resource provider.
        //
        // Stated rather than papered over: this control can no longer witness
        // admission opening. That property moved to the broker's own positive
        // control, which promotes with every conjunct satisfied. What is still
        // proven here is the part that belongs to this layer — the entry stays
        // retriable across all three states and never silently drops.
        state
            .peers
            .get("peer")
            .expect("peer is installed")
            .install_authenticated_channel_for_test();
        assert_eq!(
            link_ready(&state, "peer"),
            Some(true),
            "readiness still unchanged across the whole control"
        );
        assert!(
            state
                .peers
                .with_admitted_current(
                    &owner,
                    state.session_broker.as_ref(),
                    &state.network_id,
                    |admitted| admitted.device_id().to_string()
                )
                .is_none(),
            "an installed capability alone mints no witness without a session"
        );
        // The send itself still cannot complete on this fixture. It now needs a
        // promoted session, and this peer has neither a connector worker to
        // promote from nor a broker on a fixture with no resource provider.
        // Both refusals fold into the same `Option`, which is why the advance is
        // asserted at the fence above rather than by comparing error strings.
        assert!(
            state
                .peers
                .admit_application_operation(
                    &owner,
                    state.session_broker.as_ref(),
                    &state.network_id
                )
                .is_none(),
            "an admitted peer with no promoted session has nothing to write through"
        );
        // Stated plainly rather than dressed up: this last flush also leaves the
        // entry queued. Admission opened — the fence above says so — but a
        // session-less fixture has no connector to write through, so what is
        // proven here is that the entry stayed *retriable* across all three
        // states, not that a send ever succeeded. The successful-send half of
        // this contract belongs to a control with a live connector.
        flush_peer_owner(&state, &owner).await;
        assert_eq!(
            pending_total(&state),
            1,
            "the entry is still queued and still retriable, not failed and not sent"
        );
        assert!(
            recv_now(&mut waiter).is_none(),
            "the caller has been neither resolved nor failed at any point"
        );
        assert_eq!(
            state.traffic.snapshot().app_tx.frames,
            0,
            "no application frame left this node in any of the three states"
        );
    }

    #[tokio::test]
    async fn enqueue_parks_when_link_is_down_and_expires_on_tick() {
        let state = build_test_state("rel-park");
        let (tx, mut rx) = oneshot::channel();
        enqueue(
            &state,
            "peer-a",
            "app.control",
            serde_json::json!({"n": 1}),
            Some(0), // expire immediately on the next tick
            tx,
        )
        .await;
        assert_eq!(pending_total(&state), 1, "entry parked, nothing to send to");
        assert!(recv_now(&mut rx).is_none(), "caller still waiting");

        tick(&state).await;
        assert_eq!(pending_total(&state), 0, "expired entry removed");
        match recv_now(&mut rx) {
            Some(Err(_)) => {}
            other => panic!("expected expiry error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn outbox_cap_backpressures() {
        let state = build_test_state("rel-cap");
        for _ in 0..OUTBOX_CAP {
            let (tx, _rx) = oneshot::channel();
            enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        }
        let (tx, mut rx) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        match recv_now(&mut rx) {
            Some(Err(e)) => assert!(e.to_string().contains("full"), "got: {e}"),
            other => panic!("expected outbox-full error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbound_dedup_delivers_once_and_reacks() {
        // The dedup decision now lives where the payload does: in
        // `advance_inbound_mark_and_deliver`, which the inbound path calls from
        // inside its dispatch fence. Driving it directly keeps the property
        // under test (deliver once, re-ack a duplicate, adopt a restarted
        // stream) separate from the fence and the ack send, which are proven by
        // the engine's own replacement controls.
        //
        // Every case asserts delivery and mark together, because the contract
        // is a biconditional: a mark that moved without a delivery is the defect
        // this shape exists to prevent.
        let state = build_test_state("rel-dedup");
        insert_session_less_peer(&state, "peer-b", None);
        let mut delivered: Vec<serde_json::Value> = Vec::new();

        // First delivery: fresh, handed on once, and records seq 1.
        let ack_up_to = advance_inbound_mark_and_deliver(
            &state,
            "peer-b",
            7,
            1,
            serde_json::json!(1),
            |payload| delivered.push(payload),
        );
        assert_eq!(ack_up_to, 1);
        assert_eq!(
            delivered,
            vec![serde_json::json!(1)],
            "delivered exactly once"
        );
        assert_eq!(state.reliable_in.lock().get("peer-b").unwrap().last_seq, 1);

        // Duplicate: not delivered, high-water mark unchanged, still re-acked.
        let ack_up_to = advance_inbound_mark_and_deliver(
            &state,
            "peer-b",
            7,
            1,
            serde_json::json!(1),
            |payload| delivered.push(payload),
        );
        assert_eq!(ack_up_to, 1);
        assert_eq!(
            delivered,
            vec![serde_json::json!(1)],
            "a duplicate is re-acked, never re-delivered"
        );
        assert_eq!(state.reliable_in.lock().get("peer-b").unwrap().last_seq, 1);

        // New stream (sender restarted): mark resets and seq 1 delivers.
        let ack_up_to = advance_inbound_mark_and_deliver(
            &state,
            "peer-b",
            9,
            1,
            serde_json::json!(2),
            |payload| delivered.push(payload),
        );
        assert_eq!(ack_up_to, 1);
        assert_eq!(
            delivered,
            vec![serde_json::json!(1), serde_json::json!(2)],
            "a restarted stream is adopted and its first frame delivers"
        );
        let m = *state.reliable_in.lock().get("peer-b").unwrap();
        assert_eq!((m.stream, m.last_seq), (9, 1));
    }

    /// Settle an inbound ack exactly the way production does: mint the
    /// admission under the fence, then resolve the caller waits it owes.
    ///
    /// There is deliberately no non-test entry point doing this. The old
    /// `on_channel_ack` wrapper became unreachable from production once the
    /// outbox began settling inside the admission fence, and keeping a
    /// second, unfenced way to drain an outbox alive purely so tests could
    /// call it would have meant these tests no longer exercised the path that
    /// actually runs.
    fn settle_inbound_ack(state: &NetworkState, peer: &str, stream: u64, up_to: u64) {
        admit_inbound_reliable(state, peer, &MeshMessage::ChannelAck { stream, up_to }).settle();
    }

    #[tokio::test]
    async fn ack_resolves_callers_in_order() {
        let state = build_test_state("rel-ack");
        let (tx1, mut rx1) = oneshot::channel();
        let (tx2, mut rx2) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx1).await;
        enqueue(&state, "peer-a", "c", serde_json::json!(2), None, tx2).await;
        let stream = state.reliable_out.lock().get("peer-a").unwrap().stream;

        settle_inbound_ack(&state, "peer-a", stream, 1);
        assert!(matches!(recv_now(&mut rx1), Some(Ok(()))), "seq 1 acked");
        assert!(recv_now(&mut rx2).is_none(), "seq 2 still pending");

        settle_inbound_ack(&state, "peer-a", stream, 2);
        assert!(matches!(recv_now(&mut rx2), Some(Ok(()))), "seq 2 acked");
        assert_eq!(pending_total(&state), 0, "outbox drained and removed");
    }

    #[tokio::test]
    async fn stale_stream_ack_settles_nothing() {
        let state = build_test_state("rel-stale-ack");
        let (tx, mut rx) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        let stream = state.reliable_out.lock().get("peer-a").unwrap().stream;
        settle_inbound_ack(&state, "peer-a", stream.wrapping_add(1), 1);
        assert!(recv_now(&mut rx).is_none(), "wrong-stream ack ignored");
        assert_eq!(pending_total(&state), 1);
    }

    #[tokio::test]
    async fn rebuild_marks_entries_for_retransmit_and_terminal_failure_resolves() {
        let state = build_test_state("rel-rebuild");
        let (tx, mut rx) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        {
            let mut out = state.reliable_out.lock();
            out.get_mut("peer-a").unwrap().entries[0].sent = true;
        }
        mark_unsent(&state, "peer-a");
        assert!(
            !state.reliable_out.lock().get("peer-a").unwrap().entries[0].sent,
            "rebuild resets in-flight entries for retransmit"
        );

        fail_peer(&state, "peer-a", "denied");
        match recv_now(&mut rx) {
            Some(Err(e)) => assert!(e.to_string().contains("denied")),
            other => panic!("expected terminal failure, got {other:?}"),
        }
        assert_eq!(pending_total(&state), 0);
    }
}
