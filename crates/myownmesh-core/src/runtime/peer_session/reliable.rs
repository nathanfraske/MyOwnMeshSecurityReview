//! Acknowledged-delivery state for one promoted session.
//!
//! Both directions of one reliable stream, owned by the session that carries it:
//! the frames this side retains until the peer acknowledges them, and the mark
//! recording what this side has accepted from the peer.
//!
//! The state machine is deliberately narrow, because every widening of it is a
//! way to report success for data that was never delivered:
//!
//! * **Only sent frames can be acknowledged.** A peer that learns the stream id
//!   from one frame can name any `up_to` it likes; settling on that alone would
//!   resolve callers `Ok` for frames still sitting in this queue.
//! * **Only the next sequence is accepted.** The data channel is ordered, so a
//!   gap is not a slow success — it is a frame that did not arrive, and
//!   advancing past it would let the sender settle everything it skipped.
//! * **One stream per session.** The sender mints its stream once; the receiver
//!   binds the first one it sees and refuses any other. A peer that could hand
//!   over a new stream value could reset this side's mark at will.
//! * **A caller is resolved while its frame is still funded.** Acknowledgement
//!   answers the wait and releases the retention together, so there is no
//!   interval in which the oneshot the retained claim paid for is still alive
//!   with its lease already gone.

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::error::{Error, Result};
use crate::protocol::MeshMessage;
use crate::resource::{
    LeasedQueue, ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease,
};
use crate::runtime::session_broker::SessionCapability;

/// Allocations one retained frame owns, off the queue node, whose overhead has
/// no portable size.
///
/// Two, and exactly two, because the retained representation is chosen to make
/// them countable rather than estimated:
///
/// 1. the boxed encoded frame — one allocation, whose length is its capacity, so
///    there is no slack to account for and no reallocation to observe;
/// 2. the oneshot channel's single shared state, allocated by
///    `oneshot::channel` and kept alive by the sender this frame holds.
///
/// The queue node is not among them: [`LeasedQueue::entry_claim`] adds it, from
/// a size only the queue can read.
const RETAINED_FRAME_SHARED_ALLOCATIONS: u64 = 2;

/// Allocations the transient send copy owns.
///
/// The retained frame is a boxed slice, which cannot be shared with a write
/// without changing what the retention claim measures — a `Bytes` handed out
/// from it would put a second holder on an allocation this queue's accounting
/// says it alone keeps, and the promotion that makes such a share possible
/// allocates a shared state nothing has paid for. So the write gets a copy, and
/// the copy is funded rather than called free.
///
/// Two allocations, counted on the same pattern as the retained frame: the
/// copy's own buffer, and the shared state a clone of it promotes to. The second
/// is counted unconditionally rather than made to depend on whether the write
/// path happens to clone, because a claim that is correct only for today's write
/// implementation goes stale silently.
const TRANSIENT_FRAME_SHARED_ALLOCATIONS: u64 = 2;

/// One frame retained until this session's peer acknowledges it.
///
/// The frame is retained **encoded**, in a canonical boxed buffer. That is an
/// accounting requirement before it is an efficiency one: a boxed slice's length
/// *is* its capacity, so the bytes charged are the bytes kept, exactly, with no
/// slack term to estimate and no growth to observe.
struct PendingFrame {
    seq: u64,
    /// The encoded `ChannelSeq`, exactly as it goes on the wire. Fixed at
    /// submission: `stream` and `seq` are decided there and never change, so a
    /// retransmit is these bytes rather than a re-encode that could differ from
    /// what was paid for.
    frame: Box<[u8]>,
    /// Whether the frame has reached the wire under this session.
    ///
    /// Load-bearing for correctness, not diagnostics: [`ReliableState::acknowledge`]
    /// will not settle a frame this is false for, however large an `up_to` the
    /// peer claims.
    sent: bool,
    /// The caller's wait. Taken by whichever of acknowledgement or drop happens
    /// first, so exactly one of them answers it.
    reply: Option<oneshot::Sender<Result<()>>>,
    /// Funds the boxed frame and oneshot state for this value's full lifetime.
    /// The queue node owns a separate lease and may disappear before a popped
    /// value does.
    _retention: ResourceLease,
}

impl PendingFrame {
    /// Hand the caller their outcome, once.
    fn resolve(&mut self, outcome: Result<()>) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(outcome);
        }
    }
}

impl Drop for PendingFrame {
    /// A frame that reaches here unresolved was never acknowledged, and its
    /// caller is told that.
    ///
    /// This is how revocation, replacement, retirement and shutdown resolve
    /// their callers: each is a drop of the promoted session, the session owns
    /// this queue, so each runs this. An acknowledged frame has already taken
    /// its `reply` and passes through silently.
    ///
    /// Sending on a oneshot stores the value and wakes the waiting task; it does
    /// not run the caller's continuation, and it re-enters neither the registry
    /// nor this module. That is what makes it safe under the locks a session
    /// drop holds — and it is the same property that lets acknowledgement
    /// resolve its callers in place.
    fn drop(&mut self) {
        self.resolve(Err(Error::Transport(
            "reliable send abandoned: the session that retained it is gone".into(),
        )));
    }
}

/// One frame owed to the wire, together with the lease funding the copy handed
/// out for the write.
///
/// The lease lives exactly as long as this value: the caller holds it across the
/// write and drops it when the write returns, which is when the copy dies.
pub(crate) struct UnsentFrame {
    pub(crate) seq: u64,
    pub(crate) bytes: Bytes,
    /// Held for its `Drop`. Not read: its whole job is to outlive the copy by
    /// exactly nothing.
    _lease: ResourceLease,
}

/// Receiver-side high-water mark for the peer's reliable stream.
///
/// Session-local, and bound once. The peer's session lifetime and ours are
/// independent, but a peer cannot tell us its session restarted by changing this
/// value — replacement of *our* session is what creates a fresh mark, because
/// that creates a fresh record.
#[derive(Default)]
struct InboundMark {
    /// The peer's stream, bound on first sight and never rebound.
    ///
    /// `None` until the first inbound frame. Binding on first sight rather than
    /// on first delivery is deliberate: a frame that arrives as a gap still
    /// establishes which stream this session is talking about, so a later
    /// in-order frame on the same stream is accepted normally while a different
    /// stream is refused from the outset.
    stream: Option<u64>,
    last_seq: u64,
}

/// What one inbound reliable frame did to this session's receive state.
///
/// Four outcomes rather than a mark and a convention, because the caller must
/// distinguish "acknowledge this" from "acknowledge nothing", and because a
/// silent reset is exactly the defect this type exists to make impossible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum InboundOutcome {
    /// The next sequence: delivered once, and the mark advanced to it.
    Delivered(u64),
    /// At or below the mark: not delivered, nothing moved. The mark is answered
    /// anyway, because a duplicate usually means our previous acknowledgement
    /// was lost and re-acknowledging is what stops the retransmits.
    Duplicate(u64),
    /// Beyond the next sequence: nothing delivered, nothing advanced. The
    /// current contiguous mark is answered, which tells the sender exactly how
    /// far this side actually is.
    Gap(u64),
    /// A stream this session is not bound to. No delivery, no mark change, and
    /// deliberately no acknowledgement: answering would attribute a mark on our
    /// bound stream to a frame that was not part of it.
    ForeignStream,
}

impl InboundOutcome {
    /// The mark to acknowledge, or `None` where acknowledging would assert
    /// something untrue.
    pub(crate) fn acknowledge(self) -> Option<u64> {
        match self {
            Self::Delivered(mark) | Self::Duplicate(mark) | Self::Gap(mark) => Some(mark),
            Self::ForeignStream => None,
        }
    }
}

/// The acknowledged-delivery state one promoted session owns.
pub(crate) struct ReliableState {
    /// This session's send-side stream id, minted once here.
    ///
    /// Load-bearing across sessions: an acknowledgement that arrives after a
    /// rebuild reaches the replacement's record, whose stream differs, and is
    /// discarded rather than settling frames the new session numbered the same
    /// way.
    stream: u64,
    next_seq: u64,
    /// The retained frames, oldest first.
    ///
    /// One allocation per frame, funded by that frame's own lease and freed with
    /// it, so nothing is retained that no lease pays for and nothing survives a
    /// release. Dropping the queue drops every frame, which is what resolves the
    /// waiting callers when the session ends.
    pending: LeasedQueue<PendingFrame>,
    inbound: InboundMark,
}

impl ReliableState {
    pub(crate) fn new() -> Self {
        use rand::Rng;
        Self {
            // Random rather than counted: a per-session counter starting at the
            // same value every time could not tell a replacement's
            // acknowledgement from its predecessor's.
            stream: rand::thread_rng().gen::<u64>() | 1,
            next_seq: 0,
            pending: LeasedQueue::new(),
            inbound: InboundMark::default(),
        }
    }

    /// Frames retained and not yet acknowledged.
    pub(crate) fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Retain one frame for acknowledged delivery, or tell the caller why not.
    ///
    /// Takes the caller's wait by value and always answers it — here, on
    /// refusal, or later, on acknowledgement or drop. Nothing above this needs a
    /// second resolution site that could disagree with this one.
    ///
    /// `session` is required and unused, deliberately: it is the proof that a
    /// current session authorized this submission. The fence that produced the
    /// `&mut Self` produced it from that same session's own record, so there is
    /// nothing to look up and nothing that could disagree.
    ///
    /// The sequence number is consumed only if the frame is retained, so a
    /// refusal leaves no gap for the receiver's in-order contract to tolerate.
    pub(crate) fn submit(
        &mut self,
        session: &SessionCapability,
        channel: &str,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    ) {
        let Some(seq) = self.next_seq.checked_add(1) else {
            // Unreachable in any run this process could survive, and refused
            // rather than wrapped anyway: a reused seq would be discarded by the
            // receiver as a duplicate, which would resolve this caller `Ok` for
            // a payload nobody saw.
            let _ = reply.send(Err(Error::Transport(
                "reliable stream has no sequence numbers left; the session must be rebuilt".into(),
            )));
            return;
        };
        let encoded = match serde_json::to_vec(&MeshMessage::ChannelSeq {
            stream: self.stream,
            seq,
            channel: channel.to_string(),
            payload,
        }) {
            // Canonicalized before anything is measured or charged. The encoder
            // returns a growable buffer whose capacity it chose; boxing it here
            // makes length and capacity the same number, so the claim below is
            // the retained size rather than a lower bound on it.
            Ok(encoded) => encoded.into_boxed_slice(),
            Err(e) => {
                let _ = reply.send(Err(Error::Serde(e)));
                return;
            }
        };
        let claim = match retained_frame_claim(encoded.len()) {
            Ok(claim) => claim,
            Err(e) => {
                let _ = reply.send(Err(Error::Transport(format!(
                    "reliable frame is not representable as a resource claim: {e:?}"
                ))));
                return;
            }
        };
        let retention = match session.reserve_retained(claim) {
            Ok(lease) => lease,
            Err(e) => {
                // The whole of backpressure: the provider refused the capacity
                // this exact frame would hold, so the frame is not retained and
                // the caller is told the refusal.
                let _ = reply.send(Err(Error::Transport(format!(
                    "reliable send refused: no capacity to retain the frame until it is \
                     acknowledged: {e:?}"
                ))));
                return;
            }
        };
        let node_claim = match LeasedQueue::<PendingFrame>::entry_claim() {
            Ok(claim) => claim,
            Err(e) => {
                let _ = reply.send(Err(Error::Transport(format!(
                    "reliable queue node is not representable as a resource claim: {e:?}"
                ))));
                return;
            }
        };
        let node = match session.reserve_retained(node_claim) {
            Ok(lease) => lease,
            Err(e) => {
                let _ = reply.send(Err(Error::Transport(format!(
                    "reliable send refused: no capacity to retain its queue node: {e:?}"
                ))));
                return;
            }
        };
        // The reservation is taken immediately before the retention it pays for
        // and nothing between the two can fail, so a refusal drops the encoded
        // buffer here and this queue retains nothing that was not funded.
        self.next_seq = seq;
        self.pending.push(
            PendingFrame {
                seq,
                frame: encoded,
                sent: false,
                reply: Some(reply),
                _retention: retention,
            },
            node,
        );
    }

    /// Whether this session still owes the wire anything.
    pub(crate) fn has_unsent(&mut self) -> bool {
        self.pending.iter().any(|frame| !frame.sent)
    }

    /// The next frame this session still owes the wire, in order, with the copy
    /// handed to the write funded for exactly as long as it exists.
    ///
    /// One frame, not a batch. The write that follows leaves the fence, so a
    /// batch collected here would be a list of frames authorized by a session
    /// that may not be current by the time the second one is written.
    ///
    /// The frame is measured, then funded, then copied — in that order, for the
    /// same reason retention is: an allocation that happens before its funding
    /// is an allocation the provider never got to refuse. A refusal answers
    /// `None`, which pauses the flush; the frame stays retained and unsent and
    /// the next tick tries again, so backpressure on the copy delays the wire
    /// rather than losing anything.
    pub(crate) fn next_unsent(&mut self, session: &SessionCapability) -> Option<UnsentFrame> {
        let (seq, len) = {
            let frame = self.pending.iter().find(|frame| !frame.sent)?;
            (frame.seq, frame.frame.len())
        };
        let lease = session
            .reserve_retained(transient_frame_claim(len).ok()?)
            .ok()?;
        let bytes = {
            let frame = self.pending.iter().find(|frame| frame.seq == seq)?;
            Bytes::copy_from_slice(&frame.frame)
        };
        Some(UnsentFrame {
            seq,
            bytes,
            _lease: lease,
        })
    }

    /// Record that `seq` reached the wire under this session.
    ///
    /// Not an acknowledgement: the frame stays retained, and its caller stays
    /// waiting, until the peer says it arrived. It is, however, what makes the
    /// frame eligible to be acknowledged at all.
    pub(crate) fn mark_sent(&mut self, seq: u64) {
        if let Some(frame) = self.pending.iter_mut().find(|frame| frame.seq == seq) {
            frame.sent = true;
        }
    }

    /// Settle the frames this acknowledgement genuinely covers, resolving each
    /// caller in place, and answer how many were settled.
    ///
    /// Only the **contiguous front prefix** that is both already sent and at or
    /// below `up_to`. The scan stops at the first frame failing either test,
    /// however large an `up_to` the peer claims: a peer that has seen one frame
    /// knows this session's stream id, and without the `sent` test could name
    /// `u64::MAX` and settle every frame still queued behind the wire.
    ///
    /// Each caller is resolved while its frame and that frame's entry lease are
    /// still together, and both are released on the same iteration. There is no
    /// interval in which the oneshot the retained claim paid for outlives the
    /// lease that paid for it, and no temporary owner of the senders to build.
    ///
    /// An acknowledgement naming another session's stream settles nothing.
    pub(crate) fn acknowledge(&mut self, stream: u64, up_to: u64) -> usize {
        if stream != self.stream {
            return 0;
        }
        let mut settled = 0usize;
        loop {
            // Resolved through the **live front node**, while the frame and its
            // entry lease are both still in the queue. `pop_front` releases the
            // lease as it hands the value back, so answering the caller after it
            // would leave the oneshot alive with the funding that paid for it
            // already gone — precisely the interval the retained-frame claim
            // says does not exist.
            let Some(frame) = self.pending.iter_mut().next() else {
                break;
            };
            if !(frame.sent && frame.seq <= up_to) {
                break;
            }
            frame.resolve(Ok(()));
            // Now the entry goes, taking its node and its lease. The `reply` has
            // been taken, so the abandon-drop does not fire for a frame that
            // genuinely arrived.
            drop(self.pending.pop_front());
            settled += 1;
        }
        settled
    }

    /// Accept one inbound frame, delivering it only if it is the next one.
    ///
    /// Delivery and the mark move together or not at all: they live behind one
    /// `&mut Self`, so no reader can observe them apart, and every arm below
    /// either does both or neither. A mark advanced without delivery would make
    /// the sender's retransmit look like a duplicate, so it is acknowledged, and
    /// the sender's caller told `Ok` for a payload delivered nowhere.
    ///
    /// `deliver` runs while this record is borrowed, so it must not await, run
    /// embedder code, or re-enter the registry. A broadcast hand-off is the
    /// intended shape.
    pub(crate) fn try_receive<E>(
        &mut self,
        stream: u64,
        seq: u64,
        payload: serde_json::Value,
        deliver: impl FnOnce(serde_json::Value) -> std::result::Result<(), E>,
    ) -> std::result::Result<InboundOutcome, E> {
        match self.inbound.stream {
            None => self.inbound.stream = Some(stream),
            Some(bound) if bound != stream => return Ok(InboundOutcome::ForeignStream),
            Some(_) => {}
        }
        // The successor of the mark, not a saturating one: at the ceiling there
        // is no next sequence, so nothing can be the next frame and nothing is
        // delivered.
        let Some(next) = self.inbound.last_seq.checked_add(1) else {
            return Ok(InboundOutcome::Gap(self.inbound.last_seq));
        };
        if seq == next {
            deliver(payload)?;
            self.inbound.last_seq = seq;
            Ok(InboundOutcome::Delivered(seq))
        } else if seq < next {
            Ok(InboundOutcome::Duplicate(self.inbound.last_seq))
        } else {
            Ok(InboundOutcome::Gap(self.inbound.last_seq))
        }
    }

    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn receive(
        &mut self,
        stream: u64,
        seq: u64,
        payload: serde_json::Value,
        deliver: impl FnOnce(serde_json::Value),
    ) -> InboundOutcome {
        self.try_receive(stream, seq, payload, |payload| {
            deliver(payload);
            Ok::<(), std::convert::Infallible>(())
        })
        .expect("an infallible delivery cannot refuse")
    }

    /// This session's send-side stream id.
    ///
    /// Controls need it to build an acknowledgement this record would actually
    /// accept, so a refusal under test is provably the session fence and not a
    /// stale-stream mismatch.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn stream_for_test(&self) -> u64 {
        self.stream
    }
}

/// What one retained frame costs the provider, derived from the retained
/// representation.
///
/// Exactly one byte term is stated here: `encoded`, the boxed frame buffer,
/// whose length is its capacity — so this is the retained size and not a lower
/// bound on it.
///
/// Everything else is deferred to whoever can read it. The node holding the
/// frame — and with it every handle the frame keeps inline, the boxed-slice
/// pointer and length, the sent flag, the oneshot sender — is added by
/// [`LeasedQueue::entry_claim`], from a size only the queue can take. Restating
/// it here would be an inference about a representation this module does not
/// own, and would double-charge what the node already contains.
///
/// The two allocations themselves expose no portable overhead, so they are
/// counted rather than estimated: see [`RETAINED_FRAME_SHARED_ALLOCATIONS`].
///
/// Nothing here is amortized and nothing is shared between frames, so releasing
/// one frame's lease releases everything that frame's retention was costing.
fn retained_frame_claim(
    encoded: usize,
) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(encoded).map_err(|_| overflow())?,
        ),
        (
            ResourceClass::OpaqueDependencyResidual,
            RETAINED_FRAME_SHARED_ALLOCATIONS,
        ),
    ])
}

/// What the copy handed to one write costs, for exactly as long as the write.
///
/// The same byte term as the retained frame, because it is a copy of it, plus
/// its own allocations. No queue node: this buffer is never entered into the
/// queue, it is handed out and dropped.
fn transient_frame_claim(
    encoded: usize,
) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(encoded).map_err(|_| overflow())?,
        ),
        (
            ResourceClass::OpaqueDependencyResidual,
            TRANSIENT_FRAME_SHARED_ALLOCATIONS,
        ),
    ])
}

/// The full provider charge for retaining one reliable frame, for fixtures that
/// must leave room for the frames they submit.
///
/// The **reservation** charge, not the bare claim, for exactly the reason
/// [`crate::runtime::session_broker::session_reservation_charge_for_test`] is:
/// `reserve_retained` hands the claim to the provider, which charges it together
/// with the record it keeps for the lease carrying it. A fixture that budgets the
/// claim alone is short by one record per retained frame — and short *silently*,
/// so the first retention it believed it had funded is refused instead.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn retained_frame_reservation_charge_for_test(encoded: usize) -> ResourceClaim {
    let retention = retained_frame_claim(encoded)
        .expect("the retained frame claim is `size_of` arithmetic over a bounded length");
    let node = LeasedQueue::<PendingFrame>::entry_claim()
        .expect("the reliable queue node claim is representable");
    let retention = crate::resource::FiniteResourceProvider::reservation_charge_for_test(retention)
        .expect("the value retention plus its provider record is representable");
    let node = crate::resource::FiniteResourceProvider::reservation_charge_for_test(node)
        .expect("the node claim plus its provider record is representable");
    retention
        .checked_add(node)
        .expect("the two independent reliable reservations are representable together")
}

/// The full provider charge for the copy one write borrows, for fixtures that
/// must leave room for a flush as well as for the retention it drains.
///
/// A control that funds only retention starves the flush: `next_unsent` refuses,
/// nothing reaches the wire, and nothing becomes eligible for acknowledgement.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn transient_frame_reservation_charge_for_test(encoded: usize) -> ResourceClaim {
    let claim = transient_frame_claim(encoded)
        .expect("the transient frame claim is arithmetic over a bounded length");
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(claim)
        .expect("one transient frame claim plus the provider's reservation record is representable")
}

#[cfg(test)]
mod gateway_controls {
    use super::*;
    use crate::application_gateway::GatewayRefusal;

    #[test]
    fn refused_gateway_acceptance_neither_advances_nor_turns_retransmit_into_duplicate() {
        let mut reliable = ReliableState::new();
        let refused = reliable.try_receive(7, 1, serde_json::json!("payload"), |_| {
            Err::<(), _>(GatewayRefusal::NoReceiver)
        });
        assert_eq!(refused, Err(GatewayRefusal::NoReceiver));

        let mut delivered = 0;
        let accepted = reliable
            .try_receive(7, 1, serde_json::json!("payload"), |_| {
                delivered += 1;
                Ok::<(), GatewayRefusal>(())
            })
            .expect("a live Application Gateway accepts the retransmit");
        assert_eq!(accepted, InboundOutcome::Delivered(1));
        assert_eq!(delivered, 1);
    }
}
