//! What one promoted peer session owns on the application side.
//!
//! Everything here is reachable only through a live [`SessionCapability`], and
//! everything here dies when that session does. Both halves of that sentence are
//! load-bearing.
//!
//! The record has no key. It is a field of the promoted session, so a
//! replacement cannot name its predecessor's record any more than it can name
//! its predecessor's authority, and there is no map an operation could reach one
//! through.
//!
//! The contract that follows, structurally rather than by discipline:
//!
//! * **Submission requires a current session.** The record does not exist until
//!   promotion creates it, so a caller whose peer has no live session is told
//!   that rather than parked against a session that may never exist.
//! * **Every retained frame holds its exact lease.** The bound is the provider
//!   refusing the next frame's own claim. Nothing is retained unpaid, and
//!   releasing a frame releases everything that frame was costing.
//! * **Revocation, replacement, retirement and shutdown resolve the caller.**
//!   All four are one act — dropping the promoted session — and
//!   [`PendingFrame::drop`] is what answers the waits.
//! * **A peer that does not speak the acknowledged contract is refused.** An
//!   acknowledged-delivery wait is resolved by an acknowledgement or by nothing.

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::error::{Error, Result};
use crate::protocol::{CapabilityAdvert, MeshMessage};
use crate::resource::{
    LeasedQueue, ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease,
};
use crate::runtime::session_broker::SessionCapability;

/// One promoted session and everything promotion built under it.
///
/// Bundled rather than adjacent so their lifetimes cannot separate. The flow
/// set's name namespace and the reliable stream's sequence space are only
/// meaningful for the exact session that owns them, and the session is only
/// reachable while its connector is current — so the three die together or two
/// of them outlive their meaning.
///
/// The fields are private and are lent in pairs, never handed out. An operation
/// therefore cannot pair one session's authority with another session's state:
/// it receives the authority and the state from the same borrow of the same
/// bundle.
pub(crate) struct PromotedSession {
    session: SessionCapability,
    /// Opaque to the engine. Constructed by the worker the session was promoted
    /// from, so the flows draw on that exact connector's registry; the engine
    /// never names a label table, a flow, or a port.
    flows: crate::transport::webrtc::SessionRealtimeFlows,
    app: PeerSessionState,
}

impl PromotedSession {
    /// The post-authentication reservation one promoted session holds, derived
    /// from the record promotion actually builds.
    ///
    /// It lives here, beside [`PromotedSessionSlot::install`], because this is
    /// the module that allocates the thing being paid for. A claim written
    /// anywhere else would be a second statement of this record's shape, and the
    /// two would drift the first time a field is added.
    ///
    /// Two terms, no more:
    ///
    /// * `size_of::<Self>()` — the whole record in one reading. It covers the
    ///   session capability (and with it the authenticated channel it owns by
    ///   value, the shared principal handle, the connector identity and the
    ///   permit carrying this very reservation), the realtime flow set's own
    ///   inline shape, and this session's application state — its stream id,
    ///   sequence, empty queue handle, inbound mark and empty advert slot. One
    ///   `size_of` over the bundle cannot double-count what three `size_of`s
    ///   over its fields might, and cannot miss a field that is added later.
    /// * the heap `SessionRealtimeFlows::new` allocates for the refcounted roots
    ///   the set is built from. Their number and types are the connector's to
    ///   state: `promotion_root_claim` lives beside `new`, so the roots and
    ///   their charge are read and written in one place. Restating either here —
    ///   a count especially — would go stale the first time a root moves.
    ///
    /// The application state contributes no third term, and that is a property
    /// of the record rather than an omission: at promotion its queue is empty
    /// and holds no node, and its advert slot is empty and holds no buffer.
    /// Everything either of them later retains is funded at the moment it is
    /// retained, by [`SessionCapability::reserve_retained`], and released when it
    /// is not. Pre-paying for them here would be the fixed ceiling this design
    /// exists to remove.
    ///
    /// Two exclusions are by design. The flow registry the set holds is the
    /// connector's own and preexisting — promotion clones a handle, it does not
    /// allocate the registry — so charging it would bill a session for something
    /// that outlives it. And every per-flow, queue and payload lease is charged
    /// where it is taken; a session that opens no flow must not pre-pay for
    /// flows.
    ///
    /// Deliberately not derived from anything measured before authentication: a
    /// pre-authentication lease is not proof that this capacity exists.
    pub(crate) fn promotion_claim(
    ) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record = u64::try_from(std::mem::size_of::<Self>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([(ResourceClass::AccountedMemoryBytes, record)])?
            .checked_add(crate::transport::webrtc::SessionRealtimeFlows::promotion_root_claim()?)
    }

    /// The authority and the realtime flow set it owns.
    pub(crate) fn flows_mut(
        &mut self,
    ) -> (
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
    ) {
        (&self.session, &mut self.flows)
    }

    /// The authority and the application state it owns.
    pub(crate) fn app_mut(&mut self) -> (&SessionCapability, &mut PeerSessionState) {
        (&self.session, &mut self.app)
    }
}

/// The one slot a peer entry holds its promoted session in, and the use and
/// revocation rules that govern it.
///
/// The rules live here rather than at each call site because there is exactly
/// one of them and it must be identical everywhere: a session is usable only
/// while every use-time conjunct still holds, and a session that fails one is
/// **dropped**, not merely refused. Refusing alone would leave a revoked session
/// holding its post-authentication reservation and its retained frames, waiting
/// on a peer that will never acknowledge them, until some unrelated path
/// happened to notice.
///
/// Dropping the bundle is also the only retirement signal there is: it closes
/// the flow-owned queues, resolves every caller still waiting on a retained
/// frame, and releases the reservation. There is no separate retirement event
/// and no second place that has to remember.
pub(crate) struct PromotedSessionSlot {
    slot: parking_lot::Mutex<Option<PromotedSession>>,
}

impl PromotedSessionSlot {
    pub(crate) fn new() -> Self {
        Self {
            slot: parking_lot::Mutex::new(None),
        }
    }

    /// Whether a session is installed at all.
    ///
    /// Says nothing about whether it is still usable — that question is only
    /// answerable together with the conjuncts, which is what [`Self::with_live`]
    /// is for. Callers wanting "is this peer past promotion" want this; callers
    /// wanting to *do* something want the lender.
    pub(crate) fn is_installed(&self) -> bool {
        self.slot.lock().is_some()
    }

    /// Drop whatever is installed.
    ///
    /// The connector-retirement and entry-teardown edge. A session promoted
    /// under a retired connector must not survive into its replacement, and
    /// dropping it is what releases its reservation and answers its callers.
    pub(crate) fn clear(&self) {
        drop(self.slot.lock().take());
    }

    /// Install a freshly promoted session, replacing anything present.
    ///
    /// Replacement is correct rather than merely tolerated: the only caller
    /// promotes after this slot was found empty or revoked under the registry's
    /// mutation lock, which serializes promotion, and anything that appeared in
    /// the meantime would be a session this one supersedes.
    pub(crate) fn install(
        &self,
        session: SessionCapability,
        flows: crate::transport::webrtc::SessionRealtimeFlows,
    ) {
        *self.slot.lock() = Some(PromotedSession {
            session,
            flows,
            app: PeerSessionState::new(),
        });
    }

    /// Whether the installed session may still be reused, dropping it if not.
    ///
    /// `current` is the caller's use-time conjunction, evaluated under this
    /// slot's lock against the session's own record. `false` means either
    /// nothing was installed or what was installed has been revoked and is now
    /// gone.
    pub(crate) fn reuse_or_revoke(
        &self,
        current: impl FnOnce(&SessionCapability) -> bool,
    ) -> Reuse {
        let mut slot = self.slot.lock();
        match slot.as_ref() {
            None => Reuse::Vacant,
            Some(bundle) if current(&bundle.session) => Reuse::Current,
            Some(_) => {
                drop(slot.take());
                Reuse::Revoked
            }
        }
    }

    /// Lend the installed session if every use-time conjunct still holds, and
    /// drop it if not.
    ///
    /// Non-promoting: it uses what exists and creates nothing, so a diagnostic
    /// read cannot bring a session into being. It is still not passive — a
    /// revoked session is destroyed here, because observing that a session is no
    /// longer admitted and leaving it installed is what lets a revocation take
    /// effect at a time no caller controls.
    ///
    /// `effect` runs under this slot's lock. Anything it reads that is not in
    /// the bundle must be lockable *after* this slot, never before.
    pub(crate) fn with_live<R>(
        &self,
        current: impl FnOnce(&SessionCapability) -> bool,
        effect: impl FnOnce(&mut PromotedSession) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        if !slot.as_ref().is_some_and(|bundle| current(&bundle.session)) {
            drop(slot.take());
            return None;
        }
        Some(effect(slot.as_mut().expect(
            "the conjunction above answered true, which requires an installed session",
        )))
    }
}

/// What [`PromotedSessionSlot::reuse_or_revoke`] found.
///
/// Three answers rather than a boolean, because the caller acts differently on
/// each: a current session is reused, a vacant slot is promoted into, and a
/// revoked one is refused outright — attempting to re-promote a peer whose
/// admission was just withdrawn would take a fresh reservation for authority the
/// mesh has already refused.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reuse {
    /// A session is installed and every conjunct still holds.
    Current,
    /// Nothing was installed.
    Vacant,
    /// Something was installed, failed a conjunct, and has been dropped.
    Revoked,
}

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
/// a size only the queue can read. Nothing is charged for handing the frame to a
/// write, because a write borrows the bytes into a transient buffer that is
/// released when the write returns and is never retained.
///
/// The byte term in [`retained_frame_claim`] measures what this module owns and
/// can read a size from; these count the allocations themselves, on the same
/// pattern the connector's `Arc`-rooted claims use.
const RETAINED_FRAME_SHARED_ALLOCATIONS: u64 = 2;

/// One frame retained until this session's peer acknowledges it.
///
/// The frame is retained **encoded**, in a canonical boxed buffer. That is an
/// accounting requirement before it is an efficiency one: a boxed slice's length
/// *is* its capacity, so the bytes charged are the bytes kept, exactly, with no
/// slack term to estimate and no growth to observe. A growable buffer would
/// retain whatever the encoder happened to over-reserve, and a claim taken from
/// its length would understate what the queue holds.
struct PendingFrame {
    seq: u64,
    /// The encoded `ChannelSeq`, exactly as it goes on the wire. Fixed at
    /// submission: `stream` and `seq` are decided there and never change, so a
    /// retransmit is these bytes rather than a re-encode that could differ from
    /// what was paid for.
    frame: Box<[u8]>,
    /// Whether the frame has reached the wire under this session.
    sent: bool,
    /// The caller's wait. Taken by whichever of acknowledgement or drop happens
    /// first, so exactly one of them answers it.
    reply: Option<oneshot::Sender<Result<()>>>,
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
    /// drop holds.
    fn drop(&mut self) {
        self.resolve(Err(Error::Transport(
            "reliable send abandoned: the session that retained it is gone".into(),
        )));
    }
}

/// The one allocation a retained advertisement owns.
///
/// The boxed encoded buffer, whose length is its capacity. Nothing else: the
/// handle to it is inline in the session record and was paid for at promotion.
const RETAINED_ADVERT_ALLOCATIONS: u64 = 1;

/// The peer's advertisement, retained as canonical encoded bytes under a lease.
///
/// Retained **encoded** rather than as a decoded `CapabilityAdvert` for one
/// reason: a decoded advert is a tree of application-controlled `Vec`s and
/// `String`s whose heap this module cannot measure without walking a foreign
/// representation and guessing at its internals. Canonical bytes have exactly
/// one size, and it is the number this lease was taken for.
///
/// The peer controls the size, which is precisely why it must be funded. A
/// refused reservation retains nothing.
struct LeasedCapabilityAdvert {
    encoded: Box<[u8]>,
    /// Held for its `Drop`. The reservation lasts exactly as long as the bytes,
    /// and both end when the session does or when a replacement advertisement
    /// takes their place.
    _lease: ResourceLease,
}

/// What one retained advertisement costs, derived from the retained
/// representation.
///
/// One byte term — the boxed buffer, whose length is its capacity — and one
/// residual for that allocation. The `Option` holding it is inline in the
/// session record and was already charged by
/// [`PromotedSession::promotion_claim`]; charging it again here would bill the
/// same bytes twice.
fn retained_advert_claim(
    encoded: usize,
) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(encoded).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        ),
        (
            ResourceClass::OpaqueDependencyResidual,
            RETAINED_ADVERT_ALLOCATIONS,
        ),
    ])
}

/// Receiver-side high-water mark for the peer's reliable stream.
///
/// Session-local. A remote restart mints a fresh `stream` and is adopted below:
/// the peer's session lifetime and ours are independent, so ours ending is not
/// what tells us theirs did.
#[derive(Clone, Copy, Default)]
struct InboundMark {
    stream: u64,
    last_seq: u64,
}

/// The application state one promoted session owns.
///
/// Created by promotion, dropped with the session. Not `Clone` and not
/// serializable: a copy would be a second retained truth about a peer, which is
/// what having one owner exists to prevent.
pub(crate) struct PeerSessionState {
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
    /// What the peer advertised over this session.
    ///
    /// Owned here so it cannot outlive the session that heard it. A replacement
    /// answers `None` until its own peer advertises, which is the truthful
    /// answer: nothing has been advertised over this session yet.
    capabilities: Option<LeasedCapabilityAdvert>,
}

impl PeerSessionState {
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
            capabilities: None,
        }
    }

    /// The peer's advertisement as heard over **this** session.
    ///
    /// Decoded on demand, into a value the caller owns and this record does not.
    /// The retained form is bytes; a decoded copy kept beside them would be a
    /// second representation of one fact, and an unfunded one. Callers wanting
    /// to publish an advert take it from here and it lives as long as they hold
    /// it, not as long as the session.
    ///
    /// A decode failure answers `None`. These bytes were produced by
    /// [`Self::set_capabilities`] from a value of this very type, so a failure
    /// would mean the encoding is not round-tripping — a defect to fix in the
    /// type, not a condition for a snapshot path to panic on.
    pub(crate) fn capabilities(&self) -> Option<CapabilityAdvert> {
        let retained = self.capabilities.as_ref()?;
        serde_json::from_slice(&retained.encoded).ok()
    }

    /// Record what the peer advertised over this session, replacing any earlier
    /// advertisement it made over the same one.
    ///
    /// Fallible, and the failure is a refusal rather than a degraded write. The
    /// advertisement is peer-controlled data of peer-chosen size, so retaining
    /// it is a resource acquisition like any other: the encoded form is measured
    /// exactly, funded through the session that will own it, and only then
    /// installed.
    ///
    /// **On refusal nothing changes.** The previous advertisement — including
    /// none — stays exactly as it was, the transient encoding is dropped, and
    /// the caller must not announce a change, because none happened. The
    /// ordering is what guarantees it: the replacement is the last step and
    /// nothing after it can fail.
    ///
    /// `session` is the funding authority and the proof that a current session
    /// authorized this. Taking it makes both unforgeable rather than
    /// conventional.
    pub(crate) fn set_capabilities(
        &mut self,
        session: &SessionCapability,
        advert: &CapabilityAdvert,
    ) -> Result<()> {
        let encoded = serde_json::to_vec(advert)
            .map_err(Error::Serde)?
            .into_boxed_slice();
        let claim = retained_advert_claim(encoded.len()).map_err(|e| {
            Error::Transport(format!(
                "capability advertisement is not representable as a resource claim: {e:?}"
            ))
        })?;
        let lease = session.reserve_retained(claim).map_err(|e| {
            Error::Transport(format!(
                "capability advertisement refused: no capacity to retain it for this session: {e:?}"
            ))
        })?;
        // The old advertisement stays installed while the new one is serialized
        // and funded — that overlap is what lets a refusal above leave the
        // previous value untouched. This assignment is the only state change,
        // and it releases the old bytes and the old lease together.
        self.capabilities = Some(LeasedCapabilityAdvert {
            encoded,
            _lease: lease,
        });
        Ok(())
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
    /// nothing to look up and nothing that could disagree. Taking it makes the
    /// requirement unforgeable rather than conventional.
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
            // rather than wrapped anyway: a reused seq would be silently
            // discarded by the receiver as a duplicate, which would resolve this
            // caller `Ok` for a payload nobody saw.
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
        let lease = match session.reserve_retained(claim) {
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
            },
            lease,
        );
    }

    /// Whether this session still owes the wire anything.
    pub(crate) fn has_unsent(&mut self) -> bool {
        self.pending.iter().any(|frame| !frame.sent)
    }

    /// The next frame this session still owes the wire, in order.
    ///
    /// One frame, not a batch. The write that follows leaves the fence, so a
    /// batch collected here would be a list of frames authorized by a session
    /// that may not be current by the time the second one is written.
    /// The buffer handed out is a copy, and deliberately so: it exists for the
    /// duration of one write and is released when the write returns, so it is
    /// not retained state and owes no lease. Handing out a share of the retained
    /// buffer instead would put a second holder on an allocation this queue's
    /// accounting says it alone keeps.
    pub(crate) fn next_unsent(&mut self) -> Option<(u64, Bytes)> {
        self.pending
            .iter()
            .find(|frame| !frame.sent)
            .map(|frame| (frame.seq, Bytes::copy_from_slice(&frame.frame)))
    }

    /// Record that `seq` reached the wire under this session.
    ///
    /// Not an acknowledgement: the frame stays retained, and its caller stays
    /// waiting, until the peer says it arrived.
    pub(crate) fn mark_sent(&mut self, seq: u64) {
        if let Some(frame) = self.pending.iter_mut().find(|frame| frame.seq == seq) {
            frame.sent = true;
        }
    }

    /// Settle every frame `stream` acknowledges through `up_to`, handing back
    /// the caller waits they owe.
    ///
    /// The waits travel out so the caller can answer them outside whatever fence
    /// it holds. The frames themselves — their nodes, their buffers and their
    /// leases — are released here, under it.
    ///
    /// An acknowledgement naming another session's stream settles nothing.
    pub(crate) fn take_acknowledged(
        &mut self,
        stream: u64,
        up_to: u64,
    ) -> Vec<oneshot::Sender<Result<()>>> {
        if stream != self.stream {
            return Vec::new();
        }
        let mut settled = Vec::new();
        while self.pending.front().is_some_and(|frame| frame.seq <= up_to) {
            let Some(mut frame) = self.pending.pop_front() else {
                break;
            };
            if let Some(reply) = frame.reply.take() {
                settled.push(reply);
            }
            // `frame` drops here, and its node and lease are released with it.
            // Its `reply` has been taken, so the abandon-drop does not fire for
            // a frame that genuinely arrived.
        }
        settled
    }

    /// Advance the inbound high-water mark and hand a fresh payload to
    /// `deliver` as one indivisible step, answering the mark to acknowledge.
    ///
    /// The mark advances **iff** `deliver` is invoked. That biconditional is the
    /// contract: a mark advanced without delivery makes the sender's retransmit
    /// look like a duplicate, so it is acknowledged, and the sender's caller is
    /// told `Ok` for a payload delivered nowhere. Both live behind one
    /// `&mut Self`, so no reader can observe them apart.
    ///
    /// `deliver` runs while this record is borrowed, so it must not await, run
    /// embedder code, or re-enter the registry. A broadcast hand-off is the
    /// intended shape.
    ///
    /// A duplicate — a seq at or below the mark — is not delivered and moves
    /// nothing, but still answers the mark, because a duplicate usually means
    /// our previous acknowledgement was lost and re-acknowledging is what stops
    /// the retransmits.
    pub(crate) fn advance_inbound_and_deliver(
        &mut self,
        stream: u64,
        seq: u64,
        payload: serde_json::Value,
        deliver: impl FnOnce(serde_json::Value),
    ) -> u64 {
        if self.inbound.stream != stream {
            // A fresh stream on the sender: their session was rebuilt, ours was
            // not. Their sequence restarting is not a replay.
            self.inbound = InboundMark {
                stream,
                last_seq: 0,
            };
        }
        if seq > self.inbound.last_seq {
            self.inbound.last_seq = seq;
            deliver(payload);
        }
        self.inbound.last_seq
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
    let off_node = ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(encoded).map_err(|_| overflow())?,
        ),
        (
            ResourceClass::OpaqueDependencyResidual,
            RETAINED_FRAME_SHARED_ALLOCATIONS,
        ),
    ])?;
    LeasedQueue::<PendingFrame>::entry_claim(off_node)
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
///
/// Mechanically the submission path's own arithmetic composed with the
/// provider's own, so a fixture budgets the number the provider will actually be
/// asked for rather than a restatement of it.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn retained_frame_reservation_charge_for_test(encoded: usize) -> ResourceClaim {
    let claim = retained_frame_claim(encoded)
        .expect("the retained frame claim is `size_of` arithmetic over a bounded length");
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(claim)
        .expect("one retained frame claim plus the provider's reservation record is representable")
}

/// The full provider charge for retaining one advertisement, for fixtures that
/// must fund a known number of them.
///
/// The update path's own arithmetic composed with the provider's, for the same
/// reason as the frame charge above: a fixture that restates either half funds a
/// different number from the one the provider is asked for, and a pressure
/// control built on the difference proves nothing.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn retained_advert_reservation_charge_for_test(encoded: usize) -> ResourceClaim {
    let claim = retained_advert_claim(encoded)
        .expect("the retained advert claim is arithmetic over a bounded length");
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(claim)
        .expect("one retained advert claim plus the provider's reservation record is representable")
}

/// The encoded size the advert path will charge for `advert`, so a fixture can
/// fund exactly one of *this* advertisement rather than a guess at its size.
///
/// Encoded by the same call the update path uses, so the number is the one that
/// will actually be asked for and not an estimate of it.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn encoded_advert_len_for_test(advert: &CapabilityAdvert) -> usize {
    serde_json::to_vec(advert)
        .expect("a control advertisement serializes")
        .len()
}

/// Why a reliable submission reached no session.
///
/// One value, deliberately: the caller learns that no current session would
/// carry the frame, and nothing finer. Distinguishing "no session" from "policy
/// refused" from "connector superseded" here would republish, to the
/// application, the admission reasoning the fence keeps inside itself.
pub(crate) fn no_session_error(peer: &str) -> Error {
    Error::Network(format!(
        "no live promoted session to carry a reliable send to {peer}"
    ))
}

/// The refusal a peer that does not advertise the acknowledged contract earns.
///
/// Acknowledged delivery is answered by an acknowledgement or by nothing; there
/// is no send-success answer that would mean anything about the peer's
/// application layer.
pub(crate) fn unsupported_error(peer: &str) -> Error {
    Error::Transport(format!(
        "{peer} does not advertise reliable channels, and acknowledged delivery is not \
         downgraded to a best-effort send"
    ))
}
