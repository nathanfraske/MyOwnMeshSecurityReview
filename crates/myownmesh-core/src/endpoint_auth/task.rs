//! The endpoint-authentication task: one owner, one exchange, one channel.
//!
//! The task owns the whole cryptographic exchange — the immutable context, one
//! CSPRNG draw, the first peer contribution, the one cached local proof, the
//! verified peer proof, and a terminal state — and it owns the signer, so the
//! engine never signs. The engine translates wire values into typed inputs,
//! sends the task's outputs, and installs the capability the task returns.
//!
//! One attempt has one immutable bilateral contribution pair. The first
//! canonical peer contribution binds the attempt and produces exactly one
//! proof; an exact duplicate returns that cached proof with no draw and no
//! signature; a conflicting value is
//! [`EndpointAuthError::ConflictingPeerContribution`], which retires this exact
//! task through the handoff's own owner path. There is no engine-level
//! "already authenticated" exception: duplicate versus conflict is decided
//! here, by comparing against the bound value.
//!
//! The conflict has its own cause rather than borrowing the currentness one.
//! Retirement follows a conflict, but it is the consequence; what the task
//! keeps is what actually refused it, so a peer sending a value it cannot be
//! sending is never filed under the same cause as this endpoint closing up.
//!
//! # One lifecycle transition
//!
//! The task has exactly one way to end: [`EndpointAuthTask::terminalize`],
//! which runs with the exchange mutex already held and is the only writer of
//! both the terminal state and the `retired` observation cache. Everything
//! follows from that single writer:
//!
//! - **Retirement linearizes through the exchange lock.** `retire` takes the
//!   lock *first* and marks nothing before it. There is no window in which the
//!   task reports itself retired while another thread, holding the lock, is
//!   still free to sign a transcript or move the handoff out.
//! - **Every task-owned terminal path is a retirement.** A refused proof, a
//!   conflicting contribution, an unfresh or non-mutual pair, a proof that
//!   arrived before anything was bound, and a genuine currentness failure all
//!   go through the same transition, so each of them immediately answers
//!   `is_retired() == true` and `belongs_to(..) == false`. A caller cannot find
//!   a dead attempt that still claims its connector.
//! - **The cache never leads the state.** `retired` is written inside the same
//!   critical section that writes `ExchangeState::Terminal`, so an observer
//!   that reads the atomic without the lock still cannot see a retirement that
//!   a locked transition has not committed.
//!
//! Promotion is deliberately *not* one of those paths. A promoted task still
//! belongs to its connector, still answers a retransmitted Hello from its
//! cache, and still vouches for what it issued. A second promotion is not a
//! refusal either: it is the closed non-error
//! [`PeerProofAcceptance::AlreadyPromoted`], so `Promoted` never collapses into
//! `Terminal` and nothing has to infer "benign duplicate" from a terminal cause.
//!
//! That is what makes the error type readable on its own. An
//! [`EndpointAuthError`] out of this module — `ChannelNotCurrent` included —
//! means the attempt was *terminalized*, by this call or by an earlier one. It
//! never means "this call had nothing to do". A caller can therefore treat every
//! `Err` as the end of the attempt without asking a second question of its own
//! state to find out which sense was meant.
//!
//! Nor does it ever mean "this input was unusable". The transitions here are the
//! only source of an [`EndpointAuthError`], and every one of them goes through
//! [`EndpointAuthTask::terminalize`]. Refusing a malformed wire value, an
//! unadvertised profile, or an empty identifier happens at a boundary that holds
//! no task at all, so those causes are the separate
//! [`super::EndpointAuthSetupError`] and are not expressible here. That is why
//! this module names no parser and no negotiator: the type it returns is a
//! lifecycle statement, and a value that could also carry a parse failure could
//! not be one.

use super::capability::{AuthenticatedBindingRecord, AuthenticatedChannelCapability};
use super::context::EndpointAuthContext;
use super::contribution::{LocalContribution, PeerContribution};
use super::{transcript, EndpointAuthError};
use crate::connector::{ConnectedChannelHandoff, ConnectorIncarnation};
use crate::runtime::RuntimeIncarnation;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// The minimal private identity of what this task actually issued.
///
/// Retained at promotion so `issued` can compare a capability against the exact
/// proof this task completed, not merely against its context. Every value is
/// derived here from the task's own verified state; none is ever taken from a
/// caller, and none is exposed outside this module.
struct IssuedIdentity {
    transcript_digest: String,
    binding_digest: String,
    runtime: RuntimeIncarnation,
}

/// The local signing owner a task holds for its whole life.
///
/// Held by the task so the engine never signs and never supplies a signature.
/// Scoped to exactly one operation: producing this endpoint's half of an
/// endpoint-authentication transcript.
///
/// A **handle, not a copy.** The mesh identity already owns the Device signing
/// key and is already shared as an `Arc`, so this borrows that one key rather
/// than cloning secret material into every concurrent attempt. There is no new
/// owner here and no custody machinery: the number of copies of the key in
/// memory is unchanged by how many channels are authenticating at once.
///
/// The identity is held solely to borrow its key. The field is private, `sign`
/// is private, and this type deliberately exposes no identity accessor, so
/// holding the whole identity does not widen what any caller can reach — the
/// key is immutable on `Identity` (only its label is interior-mutable), so a
/// task's signer cannot be swapped under it either.
pub(crate) struct LocalIdentitySigner {
    identity: Arc<crate::identity::Identity>,
}

impl LocalIdentitySigner {
    /// Borrow the mesh identity's existing Device signing key.
    ///
    /// The engine already holds this identity and used to sign with its key
    /// directly. Handing the identity here is the whole cutover: signing moves
    /// into the task's ownership at construction, and the engine never signs
    /// again.
    pub(crate) fn for_identity(identity: Arc<crate::identity::Identity>) -> Self {
        Self { identity }
    }

    fn sign(&self, message: &[u8]) -> String {
        crate::signing::sign_with(self.identity.signing_key(), message)
    }
}

/// This endpoint's half of the proof, produced once and cached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointAuthProof(String);

impl EndpointAuthProof {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// How this task classified an accepted Hello, with the proof to send back.
///
/// The classification is the task's answer, not something the engine infers.
/// Both variants carry the same one cached proof — a retransmission is still
/// answered — so the engine cannot reply correctly while ignoring which case it
/// is in. That matters because a duplicate Hello must not rewrite the peer
/// metadata the first one established: deciding "first or repeat" from engine
/// state is exactly the coupling Arc 04B removes, and a bare boolean would
/// invite the same inference back.
///
/// A conflicting contribution is not represented here. It is terminal and
/// returns [`EndpointAuthError::ConflictingPeerContribution`] instead, so no
/// caller can treat it as an accepted Hello carrying a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AcceptedPeerHello {
    /// The first canonical peer contribution: it bound this attempt and
    /// produced the one local proof.
    FirstBinding(EndpointAuthProof),
    /// An exact retransmission of the bound contribution. The cached proof,
    /// with no draw, no transcript rebuild, and no second signature.
    ExactDuplicate(EndpointAuthProof),
}

impl AcceptedPeerHello {
    /// The proof to send back, identical in both cases.
    pub(crate) fn proof(&self) -> &EndpointAuthProof {
        match self {
            Self::FirstBinding(proof) | Self::ExactDuplicate(proof) => proof,
        }
    }
}

/// What became of an attempt handed a peer proof.
///
/// The counterpart to [`AcceptedPeerHello`] on the second frame, and closed for
/// the same reason: the classification is the task's answer, not something the
/// engine infers. Both variants describe an attempt that is **alive** —
/// `Err(EndpointAuthError)` is reserved for an attempt this call terminalized or
/// found already terminal — so a caller can read the two apart without consulting
/// its own state.
///
/// Named for the *attempt's* outcome rather than the proof's. Only
/// [`Self::Promoted`] means a proof was verified;
/// [`Self::AlreadyPromoted`] is reached before any verification and says nothing
/// about the bytes that produced it. A name like "accepted proof" would assert
/// across both variants what only one of them holds.
///
/// A second promotion used to be reported as
/// [`EndpointAuthError::ChannelNotCurrent`]. That made a live, intact, still
/// promoted task claim a terminal cause it never took, and it forced the engine
/// to read a terminal cause and then work out from its own state which of the
/// two senses was meant — the exact inference the task exists to remove.
///
/// It replaces that inference; it does not remove every question. The lifecycle
/// fact is decided here, so a caller that loses a race to promote is *told* it
/// lost. What became of the one capability is still the promoting caller's
/// business, so a consumer that needs it installed must corroborate that
/// separately — see [`Self::AlreadyPromoted`].
///
/// [`Self::AlreadyPromoted`] deliberately carries nothing. There is exactly one
/// capability per attempt and it went to whoever promoted; handing it out again
/// here — or lending a reference to it — would give a second caller authority
/// over a channel it did not promote.
pub(crate) enum PeerProofAcceptance {
    /// This call verified the peer's half and moved the channel out. The one
    /// capability this attempt will ever issue.
    ///
    /// Boxed purely for size. The capability carries the whole binding record
    /// and is the substantially larger of the two variants, so inlining it
    /// would size every `AlreadyPromoted` — the common outcome on a
    /// retransmission — to the promotion it is not. Nothing about the
    /// indirection is semantic: the box is opened at the single production
    /// consumer, which receives exactly the capability
    /// [`AuthenticatedChannelCapability::from_verified_exchange`] built, and no
    /// caller can observe the difference.
    Promoted(Box<AuthenticatedChannelCapability>),
    /// This attempt had already promoted: there was no channel left to move.
    ///
    /// **Non-terminal.** The task stays `Promoted`, keeps belonging to its
    /// connector, keeps answering a retransmitted Hello from its cache, and
    /// keeps vouching for what it issued.
    ///
    /// A lifecycle statement and nothing more, and a caller must not read more
    /// into it. In particular it does **not** say:
    ///
    /// - **That the supplied proof is valid.** The state is read before any
    ///   verification, and a promoted attempt has no handoff left to promote
    ///   even if it were, so `peer_signature` is never examined on this path.
    ///   Any bytes at all produce this outcome.
    /// - **That the capability was installed.** Promotion issues the capability
    ///   to whoever promoted; what that caller then did with it is outside this
    ///   task. A consumer that needs installation to have happened has to
    ///   corroborate it against its own state, and fail closed when it cannot —
    ///   otherwise a promotion that moved the channel and then failed to install
    ///   would be indistinguishable here from one that completed.
    AlreadyPromoted,
}

#[cfg(test)]
impl PeerProofAcceptance {
    /// The capability, if this outcome was the promotion that issued it.
    ///
    /// **Controls only.** Production matches the closed set exhaustively, which
    /// is the whole point of the type: the duplicate arm has to be handled, not
    /// unwrapped away.
    ///
    /// Hands back the capability itself, not the box it travelled in. The
    /// indirection is a size decision on the enum and has no bearing on what a
    /// control is asserting about, so it stops here.
    pub(crate) fn into_promoted(self) -> Option<AuthenticatedChannelCapability> {
        match self {
            Self::Promoted(capability) => Some(*capability),
            Self::AlreadyPromoted => None,
        }
    }
}

/// What the exchange has bound so far.
enum ExchangeState {
    /// Local draw made, no peer contribution seen yet.
    AwaitingPeerContribution,
    /// Bound to exactly one peer contribution, with one cached proof.
    Bound {
        peer_contribution: PeerContribution,
        local_proof: EndpointAuthProof,
    },
    /// Terminal: this attempt can never authenticate.
    Terminal(EndpointAuthError),
    /// Promoted: the handoff has moved out to its authenticated owner.
    ///
    /// The bound pair and the cached proof are **kept**. Promotion does not
    /// erase what this attempt bound, so a retransmitted Hello carrying the
    /// same contribution is still answerable from the cache, and a conflicting
    /// one is still terminal for this task. Losing them here would make a
    /// post-promotion retransmission indistinguishable from a conflict.
    Promoted {
        peer_contribution: PeerContribution,
        local_proof: EndpointAuthProof,
        /// What this task issued, retained so issuance can be proved exactly.
        issued: IssuedIdentity,
    },
}

/// Private exchange state. Not an owner in its own right: the task is the one
/// abstraction, and this is what it holds under its lock.
struct EndpointAuthExchange {
    context: EndpointAuthContext,
    signer: LocalIdentitySigner,
    local_contribution: LocalContribution,
    handoff: Option<ConnectedChannelHandoff>,
    state: ExchangeState,
    #[cfg(test)]
    draws: usize,
    #[cfg(test)]
    signatures: usize,
}

/// The exact points inside a locked lifecycle transition a control can trap.
///
/// Compiled out of production. Every point named here is *inside* the exchange
/// critical section, which is the whole reason the seam exists: the properties
/// under test are interleavings, and one side has to be parked at an exact
/// instruction while still holding the mutex for the other side to be forced to
/// lose. No production behaviour reads this, and no variant changes what a
/// transition does — a trapped transition commits exactly what an untrapped one
/// would, just later.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifecycleTrap {
    /// Inside [`EndpointAuthTask::retire`], holding the exchange lock, one step
    /// before the terminal transition runs.
    Retirement,
    /// Inside [`EndpointAuthTask::accept_peer_hello`], holding the exchange
    /// lock, after the state read and before the one signature commits.
    SignatureCommit,
    /// Inside [`EndpointAuthTask::accept_peer_proof`], holding the exchange
    /// lock, after the peer's half verified and before the handoff moves.
    HandoffMove,
}

/// A one-shot rendezvous between a control and one locked transition.
///
/// Two barriers rather than a flag and a sleep: the control waits for
/// [`Self::await_entry`] to return, which happens only once the trapped
/// transition is genuinely inside the critical section, and the transition
/// resumes only when the control calls [`Self::release`]. Nothing here depends
/// on scheduler timing, and the *other* thread in each control blocks on the
/// real exchange mutex rather than on this type, so the ordering a control
/// establishes is the ordering production would produce.
///
/// One-shot by design. Only the first arrival at the named point is trapped, so
/// a control can drive the same entry point again afterwards — which is exactly
/// what the later-Hello refusal needs — without a second rendezvous hanging it.
#[cfg(test)]
struct LifecycleBarrier {
    at: LifecycleTrap,
    tripped: AtomicBool,
    entered: std::sync::Barrier,
    resume: std::sync::Barrier,
}

#[cfg(test)]
impl LifecycleBarrier {
    fn at(point: LifecycleTrap) -> Arc<Self> {
        Arc::new(Self {
            at: point,
            tripped: AtomicBool::new(false),
            entered: std::sync::Barrier::new(2),
            resume: std::sync::Barrier::new(2),
        })
    }

    /// Block until the trapped transition holds the exchange lock.
    fn await_entry(&self) {
        self.entered.wait();
    }

    /// Let the trapped transition commit and release the exchange lock.
    fn release(&self) {
        self.resume.wait();
    }

    fn trap(&self, point: LifecycleTrap) {
        if self.at != point || self.tripped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.entered.wait();
        self.resume.wait();
    }
}

/// One runtime owner of one endpoint-authentication attempt over one exact
/// connected channel.
pub(crate) struct EndpointAuthTask {
    /// Retained separately from the exchange, so the task still names its exact
    /// connector incarnation after promotion has moved the handoff out.
    incarnation: Arc<ConnectorIncarnation>,
    /// Lock-free **observation cache** for the lifecycle, not an authority.
    ///
    /// Kept separate from handoff presence: a promoted task still belongs to
    /// its connector, while a retired one belongs to none. It exists so
    /// `is_retired` and `belongs_to` can be asked without taking the exchange
    /// lock — install asks it while already holding the peer entry's capability
    /// slot, which is exactly where that recheck has to happen — but it is
    /// never the thing that decides anything.
    /// [`EndpointAuthTask::terminalize`] is its only writer and writes it while
    /// holding the exchange mutex, so it cannot report a retirement the
    /// authoritative state has not committed, and every refusal is still
    /// decided from the state under the lock.
    retired: AtomicBool,
    exchange: Mutex<EndpointAuthExchange>,
    /// Test-only rendezvous, armed before a control starts a second thread.
    #[cfg(test)]
    barrier: std::sync::OnceLock<Arc<LifecycleBarrier>>,
}

impl EndpointAuthTask {
    /// Begin one attempt with full immutable context, drawing once.
    ///
    /// Every fact this task will ever authenticate under is fixed here. The
    /// Hello value the engine sends is [`Self::local_contribution`].
    pub(crate) fn begin(
        context: EndpointAuthContext,
        handoff: ConnectedChannelHandoff,
        signer: LocalIdentitySigner,
    ) -> Self {
        let incarnation = Arc::clone(handoff.incarnation());
        Self {
            incarnation,
            retired: AtomicBool::new(false),
            exchange: Mutex::new(EndpointAuthExchange {
                context,
                signer,
                local_contribution: LocalContribution::generate(),
                handoff: Some(handoff),
                state: ExchangeState::AwaitingPeerContribution,
                #[cfg(test)]
                draws: 1,
                #[cfg(test)]
                signatures: 0,
            }),
            #[cfg(test)]
            barrier: std::sync::OnceLock::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, EndpointAuthExchange> {
        self.exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The one authoritative lifecycle transition.
    ///
    /// This is the **only** writer of [`ExchangeState::Terminal`] and the only
    /// writer of the `retired` cache, and it can only be called with the
    /// exchange guard in hand, because the guard is its argument. Both writes
    /// happen before the caller releases that guard, so the two can never
    /// disagree: there is no ordering in which a task reports itself retired
    /// while its state would still admit a signature or a handoff move, and
    /// none in which a terminal task still claims its connector.
    ///
    /// Dropping the handoff is what runs connector retention, so a terminal
    /// attempt returns the claim rather than stranding it.
    ///
    /// **The first cause wins.** An attempt that already failed keeps the error
    /// that actually refused it. Later teardown reaches this same path — a
    /// refused proof removes the peer, and peer removal retires the task — so
    /// without this guard an ordinary lifecycle event would overwrite
    /// `SignatureInvalid` with `ChannelNotCurrent`, and the recorded cause of a
    /// refusal would depend on scheduling. The claim is likewise returned
    /// exactly once: the handoff was already taken by the first transition, so
    /// re-entering here must not run retention again.
    ///
    /// The same guard is what lets a conflicting contribution keep its own
    /// cause. A conflict retires the task it refused, and retirement reaches
    /// this path with `ChannelNotCurrent`; without the guard the conflict would
    /// be overwritten by the retirement it caused, and every terminal attempt
    /// would report the lifecycle event rather than the reason.
    ///
    /// The cache is written on **both** branches, not only on the first. It is
    /// a statement about the lifecycle rather than about this call, so a second
    /// transition arriving at an already-terminal attempt must still leave the
    /// task observably retired; making the write conditional would put the
    /// invariant at the mercy of which cause happened to land first.
    fn terminalize(
        &self,
        exchange: &mut EndpointAuthExchange,
        cause: EndpointAuthError,
    ) -> EndpointAuthError {
        let recorded = if let ExchangeState::Terminal(existing) = &exchange.state {
            *existing
        } else {
            drop(exchange.handoff.take());
            exchange.state = ExchangeState::Terminal(cause);
            cause
        };
        self.retired.store(true, Ordering::Release);
        recorded
    }

    /// Rendezvous with a control at a named point inside a locked transition.
    ///
    /// A no-op unless a control armed a barrier for exactly this point, and
    /// absent entirely from production builds. It never touches the guard: the
    /// trapped transition keeps holding the exchange mutex across the
    /// rendezvous, which is the point — that is what makes the other thread
    /// lose on the real lock rather than on scheduler timing.
    #[cfg(test)]
    fn trap(&self, point: LifecycleTrap) {
        if let Some(barrier) = self.barrier.get() {
            barrier.trap(point);
        }
    }

    /// Arm the one rendezvous this task will honour, before any race starts.
    #[cfg(test)]
    fn arm_barrier(&self, barrier: Arc<LifecycleBarrier>) {
        assert!(
            self.barrier.set(barrier).is_ok(),
            "a control arms exactly one barrier per task"
        );
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// The exact connector incarnation this task authenticates for.
    pub(crate) fn incarnation(&self) -> &Arc<ConnectorIncarnation> {
        &self.incarnation
    }

    /// Identity, not handoff presence: a promoted task still belongs to its
    /// connector, a retired one to none.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<ConnectorIncarnation>) -> bool {
        !self.is_retired() && self.incarnation.is_same(incarnation)
    }

    /// Whether this task authenticates that exact mesh and remote Device.
    pub(crate) fn context_matches(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.lock().context.matches(mesh_context, remote_device_id)
    }

    /// Whether this exact task issued that capability.
    ///
    /// Install must ask this, not merely whether the task it was handed is the
    /// current one. A caller can always supply the current task alongside a
    /// capability from somewhere else; the answer here comes from the
    /// capability's own private record, compared against this task's immutable
    /// context and its connector incarnation. Mesh, remote Device, runtime, and
    /// connector must all match, so a capability authenticated for another mesh
    /// or another peer cannot be installed here even with a current task in
    /// hand.
    pub(crate) fn issued(&self, capability: &AuthenticatedChannelCapability) -> bool {
        let exchange = self.lock();
        // Only a task that actually promoted has issued anything. A task still
        // awaiting or bound has issued nothing, and a terminal one never will,
        // so neither can vouch for a capability handed to it.
        let ExchangeState::Promoted { issued, .. } = &exchange.state else {
            return false;
        };
        let record = capability.record();
        // Asked of the capability, not reached through its record: the
        // capability is what install actually holds, so the question it answers
        // for itself is the one that must hold. The second conjunct is the same
        // equality asked from the other side — the context judging the record's
        // own stated mesh and remote — and it is deliberately not dropped as
        // redundant: it keeps both readback surfaces live, so neither the
        // capability's answer nor the record's stored identity can drift out of
        // agreement without a control failing.
        capability.authenticated_for(
            exchange.context.mesh_context(),
            exchange.context.expected_remote_device_id(),
        ) && exchange
            .context
            .matches(record.mesh_context(), record.remote_device_id())
            && record.local_device_id() == exchange.context.local_device_id()
            && record.profile() == exchange.context.profile()
            // The rest of the retained context, compared rather than merely
            // recorded. The record is derived from a context, so for a
            // capability this task issued these hold by construction; they are
            // here because the record is *not* only ever presented by the task
            // that built it — install hands this method a caller-supplied
            // capability, and every retained field that is not compared is a
            // field a substituted record could differ in for free.
            //
            // Each of the three becomes discriminating as soon as its closed
            // set has more than one reachable value: role already does (a
            // record proved under the peer's role fails here), and profile and
            // provenance will when a second binding profile or a second
            // provenance variant lands. No fake variant is added to
            // manufacture a negative today.
            && record.local_role() == exchange.context.local_role()
            && record.binding_profile() == exchange.context.binding().profile()
            && record.binding_provenance() == exchange.context.binding().provenance()
            && record.connector().is_same(&self.incarnation)
            // The exact proof this task completed, not merely the same context:
            // a second capability over the same pair and channel would carry a
            // different transcript digest.
            && record.transcript_digest() == issued.transcript_digest
            && record.binding_digest() == issued.binding_digest
            && record.runtime().is_same(&issued.runtime)
    }

    /// This endpoint's Hello contribution.
    pub(crate) fn local_contribution(&self) -> String {
        self.lock().local_contribution.as_str().to_owned()
    }

    /// Retire this task.
    ///
    /// **Linearized through the exchange lock, and nothing is marked before
    /// it.** The lock comes first, then the one transition, which releases the
    /// channel and marks the task retired together. Marking ahead of the lock
    /// is precisely what this must not do: a Hello or a proof already inside
    /// the critical section would then be free to commit its signature or move
    /// the handoff out *after* every observer could already see a retired task,
    /// so a superseded channel could still mint authority behind a lifecycle
    /// that had already said it could not. Now retirement either reaches the
    /// state first — and the operation refuses before signing or moving
    /// anything — or it waits, and the operation it lost to is complete before
    /// the retirement is visible at all.
    ///
    /// Dropping the handoff runs its retention, so a retired task returns the
    /// channel claim rather than stranding it, and can never authenticate
    /// again.
    ///
    /// Retirement is a lifecycle fact, not a cause. A task that already failed
    /// becomes retired while keeping the error that refused it, and its claim
    /// stays returned exactly once. `ChannelNotCurrent` is what an attempt with
    /// no earlier failure records here, and it stays reserved for that and for
    /// the currentness refusals in [`Self::accept_peer_proof`].
    pub(crate) fn retire(&self) {
        let mut exchange = self.lock();
        #[cfg(test)]
        self.trap(LifecycleTrap::Retirement);
        self.terminalize(&mut exchange, EndpointAuthError::ChannelNotCurrent);
    }

    /// Bind the peer contribution and return this endpoint's proof.
    ///
    /// First canonical value binds and signs exactly once. An exact duplicate —
    /// including after promotion — returns the cached proof: no draw, no
    /// transcript rebuild, no second signature. A conflicting value is
    /// [`EndpointAuthError::ConflictingPeerContribution`], terminal for this
    /// exact task and distinct from any currentness failure.
    ///
    /// The returned [`AcceptedPeerHello`] states which of the two it was. The
    /// caller needs that to know whether the Hello it just handled is the one
    /// that establishes this attempt's peer-supplied metadata or a repeat that
    /// must leave it alone; it must not re-derive the answer from its own state.
    pub(crate) fn accept_peer_hello(
        &self,
        peer_contribution: PeerContribution,
    ) -> Result<AcceptedPeerHello, EndpointAuthError> {
        let mut exchange = self.lock();
        // The state is read under the lock and *before* anything is answered
        // from the cache, before the freshness and mutuality rules run, and
        // before any transcript is built or signed. A terminal attempt — for
        // any cause, retirement included — leaves here with the cause it
        // recorded, so no retired task can be made to hand back its cached
        // proof or to produce a new one.
        //
        // Bound and promoted answer identically: promotion moves the channel
        // out, it does not change what this attempt bound. An exact duplicate
        // is answered from the cache in both states; a conflicting value is
        // terminal in both, with the same conflict cause in both. After
        // promotion the handoff is already gone, so a conflict retires this
        // task without touching the capability that was issued from it.
        match &exchange.state {
            ExchangeState::Terminal(error) => return Err(*error),
            ExchangeState::Bound {
                peer_contribution: bound,
                local_proof,
            }
            | ExchangeState::Promoted {
                peer_contribution: bound,
                local_proof,
                ..
            } => {
                if bound == &peer_contribution {
                    return Ok(AcceptedPeerHello::ExactDuplicate(local_proof.clone()));
                }
                // The conflict's own cause, not the currentness one. This
                // channel was current and this attempt was intact; what
                // happened is that a peer offered a second, different
                // contribution for a pair that is already bound. Retirement is
                // the same transition rather than a second step beside it, and
                // it keeps the first cause, so the recorded reason stays the
                // conflict rather than becoming the retirement it triggered.
                return Err(self.terminalize(
                    &mut exchange,
                    EndpointAuthError::ConflictingPeerContribution,
                ));
            }
            ExchangeState::AwaitingPeerContribution => {}
        }

        if peer_contribution.as_str() == exchange.local_contribution.as_str() {
            return Err(self.terminalize(&mut exchange, EndpointAuthError::ContributionNotFresh));
        }
        if exchange.context.local_device_id() == exchange.context.expected_remote_device_id() {
            return Err(self.terminalize(&mut exchange, EndpointAuthError::NotMutual));
        }

        let transcript = transcript::transcript_for_context(
            &exchange.context,
            exchange.context.local_role(),
            exchange.local_contribution.as_str(),
            peer_contribution.as_str(),
        );
        // Past the state read, still holding the lock, with the one signature
        // about to commit. A retirement racing this call is blocked on the
        // exchange mutex here, and stays blocked until the binding below is
        // complete.
        #[cfg(test)]
        self.trap(LifecycleTrap::SignatureCommit);
        let signature = exchange.signer.sign(&transcript);
        #[cfg(test)]
        {
            exchange.signatures += 1;
        }
        let local_proof = EndpointAuthProof(signature);
        exchange.state = ExchangeState::Bound {
            peer_contribution,
            local_proof: local_proof.clone(),
        };
        Ok(AcceptedPeerHello::FirstBinding(local_proof))
    }

    /// Verify the peer's half and promote.
    ///
    /// The whole handoff moves into the capability, so connector retention
    /// travels with the promotion. Refusal is terminal and releases the channel
    /// through the same owner path.
    ///
    /// **`Err` means terminalized.** Every error returned here is either the
    /// cause a terminal attempt already recorded or one this call just recorded
    /// through [`Self::terminalize`], so a caller can read any `Err` as "this
    /// attempt is over" without asking a second question. A second promotion is
    /// not one of them: it is the non-error
    /// [`PeerProofAcceptance::AlreadyPromoted`], because the attempt behind it is
    /// intact.
    ///
    /// Every `ChannelNotCurrent` below is therefore a genuine currentness
    /// refusal *and* a terminal transition: the channel claim is not there to
    /// promote and the attempt is ended here. A terminal task answers with the
    /// cause it recorded instead — so an attempt that a conflicting contribution
    /// retired reports that conflict here, not a currentness failure it never
    /// had.
    pub(crate) fn accept_peer_proof(
        &self,
        peer_signature: &str,
    ) -> Result<PeerProofAcceptance, EndpointAuthError> {
        let mut exchange = self.lock();
        // The same state read, under the same lock, before any verification and
        // long before the handoff moves. A terminal attempt — retirement
        // included — cannot reach the promotion below at all.
        let bound = match &exchange.state {
            ExchangeState::Bound {
                peer_contribution,
                local_proof,
            } => Some((peer_contribution.clone(), local_proof.clone())),
            ExchangeState::Terminal(error) => return Err(*error),
            // One promotion per attempt: the channel has already moved. This is
            // deliberately *not* a terminal transition, and deliberately not an
            // error. `Promoted` stays distinct from `Terminal` — the attempt
            // goes on belonging to its connector, answering a retransmitted
            // Hello from its cache, and vouching for what it issued — so the
            // outcome is stated as the closed non-error rather than borrowed
            // from `EndpointAuthError`. Reporting it as `ChannelNotCurrent` made
            // an intact task claim a terminal cause it never took, and left the
            // caller to re-derive "benign duplicate" from its own state.
            ExchangeState::Promoted { .. } => return Ok(PeerProofAcceptance::AlreadyPromoted),
            ExchangeState::AwaitingPeerContribution => None,
        };
        // A proof for an attempt that has bound nothing is terminal, not merely
        // refused. There is no transcript for it to be a proof *of*: this
        // endpoint has drawn its half and no peer half exists, so the frame
        // cannot become valid later and the attempt has nothing left to do.
        // Leaving it live would keep a channel claim held open by a peer that
        // has already violated the one ordering the exchange has.
        let Some((peer_contribution, local_proof)) = bound else {
            return Err(self.terminalize(&mut exchange, EndpointAuthError::NoBoundTranscript));
        };

        let peer_transcript = transcript::transcript_for_context(
            &exchange.context,
            exchange.context.local_role().peer(),
            exchange.local_contribution.as_str(),
            peer_contribution.as_str(),
        );
        let verified = crate::signing::verify(
            exchange.context.expected_remote_device_id(),
            &peer_transcript,
            peer_signature,
        );
        if !matches!(verified, Ok(true)) {
            return Err(self.terminalize(&mut exchange, EndpointAuthError::SignatureInvalid));
        }

        // Every borrow-checkable condition is satisfied; only now does the
        // handoff move. A retirement racing this call is blocked on the
        // exchange mutex at this point: it either reached the state before the
        // read above — in which case this call already left with the terminal
        // cause — or it waits here and lands after the promotion is complete.
        #[cfg(test)]
        self.trap(LifecycleTrap::HandoffMove);
        // Both currentness refusals below are genuine: the channel claim is not
        // there to promote. Neither is reachable from a `Bound` attempt, which
        // always still holds its handoff — only a terminal or promoted one has
        // given it up, and both were answered above — so they are stated as the
        // fail-closed floor rather than as live paths, and they terminalize
        // through the same one transition as everything else.
        let Some(handoff) = exchange.handoff.take() else {
            return Err(self.terminalize(&mut exchange, EndpointAuthError::ChannelNotCurrent));
        };
        let Some(runtime) = handoff.capability().map(|c| c.runtime().clone()) else {
            // Nothing to promote: dropping the handoff hands the claim back to
            // its owner path.
            drop(handoff);
            return Err(self.terminalize(&mut exchange, EndpointAuthError::ChannelNotCurrent));
        };
        let record = AuthenticatedBindingRecord::from_verified_exchange(
            &exchange.context,
            &peer_transcript,
            Arc::clone(handoff.incarnation()),
            runtime,
        );
        // Retain the minimal identity of what is being issued, derived from the
        // record this task just built, before the record moves into the
        // capability. Nothing here is caller-supplied.
        exchange.state = ExchangeState::Promoted {
            peer_contribution,
            local_proof,
            issued: IssuedIdentity {
                transcript_digest: record.transcript_digest().to_owned(),
                binding_digest: record.binding_digest().to_owned(),
                runtime: record.runtime().clone(),
            },
        };
        Ok(PeerProofAcceptance::Promoted(Box::new(
            AuthenticatedChannelCapability::from_verified_exchange(record, handoff),
        )))
    }

    /// The typed terminal error this task holds, if it has one.
    ///
    /// Read-only and test-only. A control that asserts only "no capability was
    /// installed" also passes when the attempt died for an unrelated reason, so
    /// the live-handler controls read the exact stated cause here. This exposes
    /// no state a caller could act on: the error is `Copy`, the exchange is not
    /// reachable through it, and nothing here can move a task out of terminal.
    #[cfg(test)]
    pub(crate) fn terminal_error(&self) -> Option<EndpointAuthError> {
        match &self.lock().state {
            ExchangeState::Terminal(error) => Some(*error),
            _ => None,
        }
    }

    /// Draws made by this task. Exactly one for its whole life.
    #[cfg(test)]
    pub(crate) fn draw_count(&self) -> usize {
        self.lock().draws
    }

    /// Signatures produced by this task.
    #[cfg(test)]
    pub(crate) fn signature_count(&self) -> usize {
        self.lock().signatures
    }
}

/// One task over a caller-supplied channel, with the canonical fixture
/// identity.
///
/// For lifecycle controls that need a real task on a real handoff and do not
/// exercise the exchange itself. It bundles only construction: a fixed
/// documented identity pair, the closed WebRTC binding profile, and a fixture
/// signer. It exposes no contribution, no proof, no exchange state, no
/// capability, and no provenance, and it is crate-private and test-only, so it
/// cannot become a production path.
///
/// The identity pair is fixed deliberately — seeds 1 and 2, encoded exactly as
/// the crate encodes Device IDs — so no fixture can vary the cryptographic
/// context by accident and then appear to prove something about it.
/// The same fixture task, forced to reuse an exact prior local contribution.
///
/// **Controls only**, compiled out of production. `begin` is unchanged and takes
/// no contribution parameter; the drawn value is replaced here, after
/// construction, so no production path gains a contribution source or setter and
/// the state machine keeps drawing exactly once for itself.
///
/// Exactly one control needs this: two channels between one Device pair that
/// share certificates *and* contributions produce byte-identical transcripts, so
/// a proof from one genuinely verifies on the other. That case cannot be built
/// any other way — the type has no constructor from bytes outside `cfg(test)` —
/// and without it the control degenerates into an ordinary freshness check.
#[cfg(test)]
pub(crate) fn task_reusing_contribution_for_test(
    handoff: ConnectedChannelHandoff,
    local_contribution: LocalContribution,
) -> EndpointAuthTask {
    let task = task_for_test(handoff);
    task.lock().local_contribution = local_contribution;
    task
}

/// A signer over a seeded fixture key, through the same owner production uses.
///
/// Production hands the mesh's shared `Arc<Identity>`; a fixture holds only a
/// seeded key, so it wraps that key in the identity type rather than being
/// given a second constructor that takes a bare key. Keeping exactly one
/// constructor is the point — a bare-key entry point would reintroduce the copy
/// this type exists to stop making, and would do it on the path least likely to
/// be reviewed.
#[cfg(test)]
fn signer_for_test(key: ed25519_dalek::SigningKey) -> LocalIdentitySigner {
    LocalIdentitySigner::for_identity(Arc::new(crate::identity::Identity::from_signing_key(
        key,
        "endpoint-auth-fixture",
    )))
}

#[cfg(test)]
pub(crate) fn task_for_test(handoff: ConnectedChannelHandoff) -> EndpointAuthTask {
    fn device_id(key: &ed25519_dalek::SigningKey) -> String {
        data_encoding::BASE32_NOPAD
            .encode(key.verifying_key().as_bytes())
            .to_lowercase()
    }

    let local_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let remote_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let context = EndpointAuthContext::new(
        "fixture-mesh",
        &device_id(&local_key),
        &device_id(&remote_key),
        crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
            "fixture-local-fp",
            "fixture-remote-fp",
        )
        .expect("both fixture components present"),
    )
    .expect("non-empty fixture identifiers");
    EndpointAuthTask::begin(context, handoff, signer_for_test(local_key))
}

/// The peer's half of the proof for a task, over that task's own context.
///
/// Test-only companion to the state machine, and deliberately the only way a
/// control outside this module can produce a proof that verifies. Every field of
/// the transcript is read from the task's own immutable context and its own
/// drawn contribution; the caller supplies nothing but the signing key. A
/// control therefore cannot describe a different mesh, profile, Device pair,
/// channel binding, or contribution than the one the task actually holds, which
/// is exactly the substitution the deleted all-facts entry point allowed.
///
/// Passing a key other than the expected remote Device's is the intended way to
/// build a proof that must be refused.
#[cfg(test)]
pub(crate) fn peer_proof_for_test(
    task: &EndpointAuthTask,
    peer_contribution: &PeerContribution,
    peer_key: &ed25519_dalek::SigningKey,
) -> String {
    let exchange = task.lock();
    let bytes = transcript::transcript_for_context(
        &exchange.context,
        exchange.context.local_role().peer(),
        exchange.local_contribution.as_str(),
        peer_contribution.as_str(),
    );
    crate::signing::sign_with(peer_key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    // The pre-task refusal type, named here and nowhere else in this module.
    // Production code in `task` cannot reach it — no transition can produce or
    // consume a setup cause — so it is imported only by the controls that hold
    // the two domains apart.
    use super::super::EndpointAuthSetupError;
    use crate::connector::{counted_handoff_for_test, handoff_for_test, EndpointAuthBinding};

    const MESH: &str = "mesh-under-test";
    const LOCAL_FP: &str = "fp-of-local";
    const REMOTE_FP: &str = "fp-of-remote";

    fn fixture_key(seed: u8) -> (ed25519_dalek::SigningKey, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let device_id = data_encoding::BASE32_NOPAD
            .encode(key.verifying_key().as_bytes())
            .to_lowercase();
        (key, device_id)
    }

    fn context_for(mesh: &str, local: &str, remote: &str) -> EndpointAuthContext {
        EndpointAuthContext::new(
            mesh,
            local,
            remote,
            EndpointAuthBinding::webrtc_certificate_fingerprints(LOCAL_FP, REMOTE_FP)
                .expect("both fixture components present"),
        )
        .expect("non-empty fixture identifiers")
    }

    /// One task plus everything a control needs to play the peer against it.
    struct Fixture {
        task: EndpointAuthTask,
        /// An identical context, so a control can derive the exact bytes the
        /// task will verify without reaching into its private state.
        mirror: EndpointAuthContext,
        peer_key: ed25519_dalek::SigningKey,
    }

    fn fixture() -> Fixture {
        let (local_key, local_device) = fixture_key(1);
        let (peer_key, remote_device) = fixture_key(2);
        let task = EndpointAuthTask::begin(
            context_for(MESH, &local_device, &remote_device),
            handoff_for_test(crate::runtime::runtime_for_test()),
            signer_for_test(local_key),
        );
        Fixture {
            task,
            mirror: context_for(MESH, &local_device, &remote_device),
            peer_key,
        }
    }

    fn peer_draw() -> PeerContribution {
        PeerContribution::from_wire(LocalContribution::generate().as_str())
            .expect("a local draw is canonical on the wire")
    }

    /// How many times a fixture channel's claim came back to its owner.
    ///
    /// A closure rather than the retention owner itself: that type is private
    /// to the connector module, and a control helper here must not be the
    /// reason it gets re-exported more widely.
    type ClaimCounter = Box<dyn Fn() -> usize>;

    /// One shared task on a counted channel, its peer key, and a claim counter.
    ///
    /// The `Arc` is what a second thread can own, so the lifecycle controls
    /// below can put two genuine concurrent callers on one real task rather
    /// than simulating the race sequentially.
    fn counted_task() -> (
        Arc<EndpointAuthTask>,
        ed25519_dalek::SigningKey,
        ClaimCounter,
    ) {
        let (local_key, local_device) = fixture_key(1);
        let (peer_key, remote_device) = fixture_key(2);
        let (handoff, retention) = counted_handoff_for_test(crate::runtime::runtime_for_test());
        let task = Arc::new(EndpointAuthTask::begin(
            context_for(MESH, &local_device, &remote_device),
            handoff,
            signer_for_test(local_key),
        ));
        (task, peer_key, Box::new(move || retention.count()))
    }

    /// Everything a task-owned terminal path must agree on, in one place.
    ///
    /// Stated as one predicate because the failure this guards against is
    /// *disagreement*: a path that records a cause but leaves the task looking
    /// live, or retires it while another path still reports a different reason,
    /// or hands the channel claim back twice. Each of the four is asked of the
    /// same attempt at the same moment.
    ///
    /// `belongs_to` is asked with the task's own incarnation, so the connector
    /// half of that predicate is true by construction and the answer can only
    /// be false because the task is retired — it cannot pass vacuously on a
    /// mismatched incarnation.
    fn assert_terminal_agreement(
        task: &EndpointAuthTask,
        cause: EndpointAuthError,
        retained: usize,
    ) {
        assert_eq!(
            task.terminal_error(),
            Some(cause),
            "the attempt keeps the exact cause that refused it"
        );
        assert!(
            task.is_retired(),
            "every task-owned terminal path retires the task immediately"
        );
        assert!(
            !task.belongs_to(task.incarnation()),
            "and a retired task belongs to no connector"
        );
        assert_eq!(
            retained, 1,
            "and the channel claim goes back to its owner exactly once"
        );
    }

    impl Fixture {
        /// The peer's half over the exact bytes this task will verify.
        fn peer_proof_with(
            &self,
            key: &ed25519_dalek::SigningKey,
            peer: &PeerContribution,
        ) -> String {
            let transcript = transcript::transcript_for_context(
                &self.mirror,
                self.mirror.local_role().peer(),
                &self.task.local_contribution(),
                peer.as_str(),
            );
            crate::signing::sign_with(key, &transcript)
        }

        fn peer_proof(&self, peer: &PeerContribution) -> String {
            self.peer_proof_with(&self.peer_key, peer)
        }
    }

    #[test]
    fn v4_arc04_complete_proof_promotes_the_exact_channel() {
        let fixture = fixture();
        let peer = peer_draw();
        fixture
            .task
            .accept_peer_hello(peer.clone())
            .expect("first contribution binds");
        let capability = fixture
            .task
            .accept_peer_proof(&fixture.peer_proof(&peer))
            .expect("a complete mutual proof promotes")
            .into_promoted()
            .expect("the first proof is the promotion that issues the capability");

        assert!(capability.belongs_to(fixture.task.incarnation()));
        assert!(fixture.task.issued(&capability));
    }

    #[test]
    fn v4_arc04_legacy_handshake_signature_is_not_an_accepted_fallback() {
        // Domain separation, not negotiation: a signature over anything other
        // than this transcript simply fails, and there is no downgrade path.
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer).expect("binds");
        let legacy = crate::signing::sign_with(&fixture.peer_key, b"myownmesh-handshake-v1:legacy");

        // Matched rather than compared: the capability is deliberately neither
        // `Debug` nor `PartialEq`, because its private provenance must not be
        // printable or comparable outside its owner.
        assert!(matches!(
            fixture.task.accept_peer_proof(&legacy),
            Err(EndpointAuthError::SignatureInvalid)
        ));
    }

    #[test]
    fn v4_arc04b_retirement_preserves_an_earlier_refusal_and_retains_once() {
        // The live refusal path runs both steps: the proof is refused, which
        // removes the peer, and peer removal retires this same task. If
        // retirement overwrote the cause, the recorded reason a channel was
        // refused would depend on scheduling, and the substituted-fingerprint
        // control could observe either error.
        let (local_key, local_device) = fixture_key(1);
        let (_, remote_device) = fixture_key(2);
        let (handoff, retention) = counted_handoff_for_test(crate::runtime::runtime_for_test());
        let task = EndpointAuthTask::begin(
            context_for(MESH, &local_device, &remote_device),
            handoff,
            signer_for_test(local_key),
        );
        task.accept_peer_hello(peer_draw()).expect("binds");

        assert!(matches!(
            task.accept_peer_proof("not-a-signature"),
            Err(EndpointAuthError::SignatureInvalid)
        ));
        assert_eq!(
            task.terminal_error(),
            Some(EndpointAuthError::SignatureInvalid)
        );
        assert_eq!(
            retention.count(),
            1,
            "the refusal returns the connected claim to its owner exactly once"
        );

        task.retire();

        assert!(task.is_retired(), "retirement is still recorded");
        assert_eq!(
            task.terminal_error(),
            Some(EndpointAuthError::SignatureInvalid),
            "but it must not overwrite the cause that actually refused this attempt"
        );
        assert_eq!(
            retention.count(),
            1,
            "and it must not return the same claim a second time"
        );
    }

    #[test]
    fn v4_arc04b_retiring_a_live_attempt_reports_channel_not_current() {
        // The other direction, so the guard above cannot be satisfied by a task
        // that simply never records retirement: an attempt with no earlier
        // failure does take ChannelNotCurrent, and returns its claim once.
        //
        // This is also the reservation twin for the conflict cause. Retirement
        // keeps `ChannelNotCurrent` here; only an attempt with no earlier cause
        // records it. If the conflict site ever borrowed this cause again, this
        // control would still pass — which is exactly why the conflict controls
        // assert the cause and not merely that the attempt died.
        let (local_key, local_device) = fixture_key(1);
        let (_, remote_device) = fixture_key(2);
        let (handoff, retention) = counted_handoff_for_test(crate::runtime::runtime_for_test());
        let task = EndpointAuthTask::begin(
            context_for(MESH, &local_device, &remote_device),
            handoff,
            signer_for_test(local_key),
        );

        task.retire();

        assert_eq!(
            task.terminal_error(),
            Some(EndpointAuthError::ChannelNotCurrent)
        );
        assert_eq!(retention.count(), 1);
    }

    #[test]
    fn v4_arc04_stale_contribution_does_not_verify() {
        // A proof over a different contribution than the bound one is not this
        // attempt's proof.
        let fixture = fixture();
        let bound = peer_draw();
        let stale = peer_draw();
        fixture.task.accept_peer_hello(bound).expect("binds");

        assert!(matches!(
            fixture.task.accept_peer_proof(&fixture.peer_proof(&stale)),
            Err(EndpointAuthError::SignatureInvalid)
        ));
    }

    #[test]
    fn v4_arc04_wrong_remote_identity_does_not_verify() {
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let (impostor, _) = fixture_key(9);

        assert!(matches!(
            fixture
                .task
                .accept_peer_proof(&fixture.peer_proof_with(&impostor, &peer)),
            Err(EndpointAuthError::SignatureInvalid)
        ));
    }

    #[test]
    fn v4_arc04b_proof_before_any_peer_contribution_is_refused() {
        // Migrated from the engine, where it used to be expressed by writing a
        // local contribution into peer state and leaving the peer's slot empty.
        // The pair belongs to the task now, so the property is stated here: an
        // attempt that has bound nothing has no transcript to verify against
        // and cannot promote.
        let fixture = fixture();

        assert_eq!(
            fixture.task.accept_peer_proof("premature").err(),
            Some(EndpointAuthError::NoBoundTranscript)
        );
        assert_eq!(fixture.task.signature_count(), 0);
    }

    #[test]
    fn v4_arc04_malformed_signature_fails_closed() {
        let fixture = fixture();
        fixture.task.accept_peer_hello(peer_draw()).expect("binds");

        assert!(matches!(
            fixture.task.accept_peer_proof("not-a-signature"),
            Err(EndpointAuthError::SignatureInvalid)
        ));
    }

    #[test]
    fn v4_arc04_self_authentication_is_not_mutual() {
        let (key, device) = fixture_key(1);
        let task = EndpointAuthTask::begin(
            context_for(MESH, &device, &device),
            handoff_for_test(crate::runtime::runtime_for_test()),
            signer_for_test(key),
        );

        assert_eq!(
            task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::NotMutual)
        );
        assert_eq!(task.signature_count(), 0);
    }

    #[test]
    fn v4_arc04_shared_contribution_is_not_fresh() {
        let fixture = fixture();
        let shared = PeerContribution::from_wire(&fixture.task.local_contribution())
            .expect("the local draw is canonical");

        assert_eq!(
            fixture.task.accept_peer_hello(shared),
            Err(EndpointAuthError::ContributionNotFresh)
        );
        assert_eq!(fixture.task.signature_count(), 0);
    }

    #[test]
    fn v4_arc04_empty_transcript_field_is_refused() {
        // Refused where the field is first fixed, so no attempt can exist with
        // a field that would produce an ambiguous signed record.
        let binding = EndpointAuthBinding::webrtc_certificate_fingerprints(LOCAL_FP, REMOTE_FP)
            .expect("both components present");

        assert_eq!(
            EndpointAuthContext::new("", "device-a", "device-b", binding).err(),
            Some(EndpointAuthSetupError::MissingIdentityField)
        );
    }

    #[test]
    fn v4_arc04_local_proof_is_produced_by_the_task_signer() {
        // Replacement for the deleted caller-supplied local-half control: no
        // caller can supply that half at all now, so the property under test is
        // that the task's own signer produced it, over the task's own context.
        let fixture = fixture();
        let peer = peer_draw();
        let accepted = fixture
            .task
            .accept_peer_hello(peer.clone())
            .expect("first contribution binds");
        let proof = accepted.proof();
        let expected = transcript::transcript_for_context(
            &fixture.mirror,
            fixture.mirror.local_role(),
            &fixture.task.local_contribution(),
            peer.as_str(),
        );
        let (_, local_device) = fixture_key(1);

        assert!(
            crate::signing::verify(&local_device, &expected, proof.as_str())
                .expect("a well-formed signature verifies or refuses, it does not error")
        );
        // The same proof does not verify over the peer-role transcript, so the
        // role tag in the signed bytes is load-bearing.
        let peer_role = transcript::transcript_for_context(
            &fixture.mirror,
            fixture.mirror.local_role().peer(),
            &fixture.task.local_contribution(),
            peer.as_str(),
        );
        assert!(
            !crate::signing::verify(&local_device, &peer_role, proof.as_str()).unwrap_or(false)
        );
    }

    #[test]
    fn v4_arc04_duplicate_hello_returns_the_cached_proof() {
        // Migrated retry control: a retransmitted Hello carrying the bound
        // value is answered from the cache.
        let fixture = fixture();
        let peer = peer_draw();
        let first = fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let again = fixture
            .task
            .accept_peer_hello(peer)
            .expect("an exact duplicate is idempotent");

        // Same proof, different classification: the caller must be able to tell
        // a repeat from the Hello that established the attempt, while still
        // sending the identical proof back.
        assert_eq!(first.proof(), again.proof());
        assert!(matches!(first, AcceptedPeerHello::FirstBinding(_)));
        assert!(matches!(again, AcceptedPeerHello::ExactDuplicate(_)));
    }

    #[test]
    fn v4_arc04b_exact_duplicate_hello_draws_and_signs_nothing_further() {
        // Ed25519 is deterministic, so equal proof bytes prove nothing about
        // re-signing. The counters do.
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let draws = fixture.task.draw_count();
        let signatures = fixture.task.signature_count();

        fixture.task.accept_peer_hello(peer).expect("idempotent");

        assert_eq!(fixture.task.draw_count(), draws);
        assert_eq!(fixture.task.signature_count(), signatures);
    }

    #[test]
    fn v4_arc04b_task_never_signs_twice() {
        let fixture = fixture();
        let peer = peer_draw();
        for _ in 0..3 {
            fixture
                .task
                .accept_peer_hello(peer.clone())
                .expect("idempotent");
        }

        assert_eq!(fixture.task.draw_count(), 1);
        assert_eq!(fixture.task.signature_count(), 1);
    }

    #[test]
    fn v4_arc04_conflicting_hello_terminally_retires_the_task() {
        // Migrated retry control, corrected: a different contribution is not a
        // retransmission. It is terminal for this exact task, with its own
        // cause — the channel was current and the attempt intact, so this is
        // not a currentness failure and must not be recorded as one.
        let fixture = fixture();
        fixture.task.accept_peer_hello(peer_draw()).expect("binds");

        assert_eq!(
            fixture.task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::ConflictingPeerContribution)
        );
        assert!(fixture.task.is_retired());
        // Retirement is the consequence; the recorded cause is the conflict.
        assert_eq!(
            fixture.task.terminal_error(),
            Some(EndpointAuthError::ConflictingPeerContribution)
        );
        assert_eq!(fixture.task.signature_count(), 1);
    }

    #[test]
    fn v4_arc04e_a_conflict_keeps_its_cause_through_later_retirement() {
        // The conflict retires the task it refused, and retirement itself takes
        // `ChannelNotCurrent`. Without the first-cause guard the conflict would
        // be overwritten by the retirement it caused, and every conflicting
        // Hello would report a currentness failure it never had.
        let fixture = fixture();
        fixture.task.accept_peer_hello(peer_draw()).expect("binds");
        assert_eq!(
            fixture.task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::ConflictingPeerContribution)
        );

        fixture.task.retire();

        assert_eq!(
            fixture.task.terminal_error(),
            Some(EndpointAuthError::ConflictingPeerContribution),
            "an explicit retirement must not overwrite the conflict that refused this attempt"
        );
    }

    #[test]
    fn v4_arc04e_later_frames_on_a_conflicted_task_report_the_conflict() {
        // Both entry points, after the conflict. A later Hello — even an exact
        // retransmission of the value that *was* bound — and a later proof both
        // answer with the cause that actually refused the attempt.
        //
        // The proof half is load-bearing beyond bookkeeping. `on_auth_response`
        // has one arm that does not tear the peer down, and it is reached by an
        // *outcome*, not by a cause: a conflicted attempt is terminal, so it can
        // only ever answer `Err` here. Answering with a cause a live attempt
        // could also take would put the two one refactor apart; keeping the
        // conflict's own cause keeps them separable at this boundary.
        let fixture = fixture();
        let bound = peer_draw();
        fixture
            .task
            .accept_peer_hello(bound.clone())
            .expect("binds");
        assert_eq!(
            fixture.task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::ConflictingPeerContribution)
        );

        assert_eq!(
            fixture.task.accept_peer_hello(bound.clone()),
            Err(EndpointAuthError::ConflictingPeerContribution),
            "the bound value is no longer answerable from the cache: the attempt is terminal"
        );
        // `err()` rather than a comparison: the capability is deliberately
        // neither `Debug` nor `PartialEq`, because its private provenance must
        // not be printable or comparable outside its owner.
        assert_eq!(
            fixture
                .task
                .accept_peer_proof(&fixture.peer_proof(&bound))
                .err(),
            Some(EndpointAuthError::ConflictingPeerContribution),
            "and a genuine peer proof cannot promote a conflicted attempt, nor report it as \
             a currentness failure"
        );
        assert_eq!(fixture.task.signature_count(), 1);
    }

    #[test]
    fn v4_arc04_post_promotion_duplicate_hello_returns_the_cached_proof() {
        // Migrated retry control: promotion moves the channel out, it does not
        // erase what the attempt bound, so a late retransmission is still
        // answerable and neither counter moves.
        let fixture = fixture();
        let peer = peer_draw();
        let bound = fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        fixture
            .task
            .accept_peer_proof(&fixture.peer_proof(&peer))
            .expect("promotes");
        let draws = fixture.task.draw_count();
        let signatures = fixture.task.signature_count();

        let late = fixture.task.accept_peer_hello(peer).expect("still cached");

        assert_eq!(late.proof(), bound.proof());
        // Still classified a repeat after promotion, so a late frame cannot be
        // mistaken for the Hello that established this attempt.
        assert!(matches!(late, AcceptedPeerHello::ExactDuplicate(_)));
        assert_eq!(fixture.task.draw_count(), draws);
        assert_eq!(fixture.task.signature_count(), signatures);
    }

    #[test]
    fn v4_arc04b_post_promotion_conflict_leaves_the_issued_capability_intact() {
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let capability = fixture
            .task
            .accept_peer_proof(&fixture.peer_proof(&peer))
            .expect("promotes")
            .into_promoted()
            .expect("the promotion issues the capability");

        // Promotion does not change what a conflict is. The bound pair survives
        // promotion, so a second, different contribution is still a conflict
        // here and still carries the conflict's own cause — and still ends the
        // attempt, which is what separates it from a *second promotion* of this
        // same task, an outcome that is no error at all.
        assert_eq!(
            fixture.task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::ConflictingPeerContribution)
        );
        assert!(fixture.task.is_retired());
        // The capability that was already issued is untouched: it still names
        // its own record and its own connector.
        assert!(capability.authenticated_for(MESH, capability.record().remote_device_id()));
        assert!(capability.belongs_to(fixture.task.incarnation()));
    }

    #[test]
    fn v4_arc04g_second_promotion_is_benign_and_leaves_the_attempt_promoted() {
        // Migrated retry control, corrected: one attempt promotes exactly once,
        // but a second promotion is not a *refusal*. Nothing about this attempt
        // went stale — it is bound, promoted, still its connector's, and still
        // vouching for what it issued — so it answers with the closed non-error
        // outcome instead of borrowing a terminal cause it never took.
        //
        // The paired half is
        // `v4_arc04g_a_currentness_refusal_is_terminal_where_a_duplicate_is_not`,
        // which drives the same frame against an attempt that genuinely is not
        // current and asserts every fact this one denies.
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let proof = fixture.peer_proof(&peer);
        let capability = fixture
            .task
            .accept_peer_proof(&proof)
            .expect("promotes")
            .into_promoted()
            .expect("the first proof is the promotion that issues the capability");

        let again = fixture
            .task
            .accept_peer_proof(&proof)
            .expect("a second promotion is not an error");

        assert!(
            matches!(again, PeerProofAcceptance::AlreadyPromoted),
            "the second proof issues no capability of its own"
        );
        // Non-terminal, stated rather than implied: the whole point of the
        // separate outcome is that none of these four flips.
        assert_eq!(
            fixture.task.terminal_error(),
            None,
            "a second promotion terminalizes nothing"
        );
        assert!(!fixture.task.is_retired());
        assert!(fixture.task.belongs_to(fixture.task.incarnation()));
        assert!(
            fixture.task.issued(&capability),
            "and the attempt goes on vouching for the one capability it issued"
        );
        // The benign duplicate semantics on the other frame survive alongside
        // it, and neither counter moves for either duplicate.
        assert!(matches!(
            fixture.task.accept_peer_hello(peer).expect("still cached"),
            AcceptedPeerHello::ExactDuplicate(_)
        ));
        assert_eq!(fixture.task.draw_count(), 1);
        assert_eq!(fixture.task.signature_count(), 1);
    }

    #[test]
    fn v4_arc04g_a_currentness_refusal_is_terminal_where_a_duplicate_is_not() {
        // The other half of the split. `ChannelNotCurrent` keeps its reserved
        // meaning — the channel really is gone — and it is terminal in every
        // sense the duplicate above is not. Both halves drive the *same* proof
        // bytes against the *same* promoted attempt, so the only thing that
        // differs is whether the attempt is still current: the outcome cannot be
        // an artefact of the frame.
        let (task, peer_key, retained) = counted_task();
        let peer = peer_draw();
        task.accept_peer_hello(peer.clone()).expect("binds");
        let proof = peer_proof_for_test(&task, &peer, &peer_key);
        let capability = task
            .accept_peer_proof(&proof)
            .expect("the fixture proof promotes")
            .into_promoted()
            .expect("the promotion issues the one capability");

        // Non-vacuity: while the attempt is merely promoted, this exact frame is
        // the benign duplicate and nothing about the attempt has changed.
        assert!(matches!(
            task.accept_peer_proof(&proof)
                .expect("a second promotion is not an error"),
            PeerProofAcceptance::AlreadyPromoted
        ));
        assert_eq!(task.terminal_error(), None);
        assert!(task.belongs_to(task.incarnation()));
        assert!(task.issued(&capability));
        assert_eq!(
            retained(),
            0,
            "and the channel claim is still out with the capability"
        );

        task.retire();

        assert_eq!(
            task.accept_peer_proof(&proof).err(),
            Some(EndpointAuthError::ChannelNotCurrent),
            "the same frame on a retired attempt is a refusal, not a duplicate"
        );
        assert_eq!(
            task.terminal_error(),
            Some(EndpointAuthError::ChannelNotCurrent),
            "and the attempt records it as the cause that ended it"
        );
        assert!(task.is_retired());
        assert!(
            !task.belongs_to(task.incarnation()),
            "a retired attempt belongs to no connector"
        );
        assert!(
            !task.issued(&capability),
            "and vouches for nothing, not even the capability it issued"
        );

        let entry = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "arc04g-currentness-refusal".to_string(),
            Arc::clone(&task),
        );

        assert!(
            !entry.install_authenticated_channel(&task, capability),
            "so the real install refuses even the capability this task issued"
        );
        assert!(
            !entry.has_authenticated_channel(),
            "and no authority is installed by the refusal"
        );
        assert_eq!(
            retained(),
            1,
            "the refused capability hands the channel claim back exactly once"
        );
    }

    #[test]
    fn v4_arc04b_task_refuses_a_context_mismatch() {
        let fixture = fixture();
        let (_, remote_device) = fixture_key(2);

        assert!(fixture.task.context_matches(MESH, &remote_device));
        assert!(!fixture.task.context_matches("other-mesh", &remote_device));
        assert!(!fixture.task.context_matches(MESH, "other-device"));
    }

    #[test]
    fn v4_arc04b_capability_from_another_context_cannot_be_claimed_by_this_task() {
        // Cross-context install: a capability proved elsewhere is refused even
        // though the caller holds this exact current task.
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let mine = fixture
            .task
            .accept_peer_proof(&fixture.peer_proof(&peer))
            .expect("promotes")
            .into_promoted()
            .expect("the promotion issues the capability");
        let foreign = super::super::authenticated_for_test(crate::runtime::runtime_for_test());

        assert!(fixture.task.issued(&mine));
        assert!(!fixture.task.issued(&foreign));
    }

    #[test]
    fn v4_arc04b_a_task_that_has_not_promoted_has_issued_nothing() {
        let fixture = fixture();
        let foreign = super::super::authenticated_for_test(crate::runtime::runtime_for_test());

        assert!(!fixture.task.issued(&foreign));
        fixture.task.accept_peer_hello(peer_draw()).expect("binds");
        assert!(!fixture.task.issued(&foreign));
    }

    /// The transition that produces each terminal cause, named exhaustively.
    ///
    /// This `match` is the census, and it is what makes the control below a
    /// statement about the whole closed type rather than about six samples of
    /// it. `EndpointAuthError` is closed to task transitions, so a variant added
    /// to it fails to compile here until it is given a driver — and the control
    /// then has to actually drive that driver and show the attempt is retired
    /// afterwards. A variant no transition can produce would be a terminal cause
    /// that terminalizes nothing, which is precisely the shape splitting the
    /// setup causes out exists to remove.
    ///
    /// The names are distinct on purpose: they are compared for distinctness, so
    /// the census cannot be satisfied by a mapping that collapses several causes
    /// onto one driver and then drives it once.
    fn driver_of(cause: EndpointAuthError) -> &'static str {
        match cause {
            EndpointAuthError::NoBoundTranscript => "accept_peer_proof with nothing bound",
            EndpointAuthError::NotMutual => "accept_peer_hello on a self-paired context",
            EndpointAuthError::ContributionNotFresh => "accept_peer_hello echoing our own draw",
            EndpointAuthError::SignatureInvalid => "accept_peer_proof with an unverifiable half",
            EndpointAuthError::ConflictingPeerContribution => {
                "a second, different accept_peer_hello"
            }
            EndpointAuthError::ChannelNotCurrent => "retire",
        }
    }

    /// Every variant of the closed terminal type.
    ///
    /// Kept beside [`driver_of`] rather than derived from it, because the two
    /// guard different halves: the `match` fails to compile when a variant is
    /// added, and this array is what the control iterates to prove each one was
    /// genuinely observed coming out of a transition.
    const EVERY_TERMINAL_CAUSE: [EndpointAuthError; 6] = [
        EndpointAuthError::NoBoundTranscript,
        EndpointAuthError::NotMutual,
        EndpointAuthError::ContributionNotFresh,
        EndpointAuthError::SignatureInvalid,
        EndpointAuthError::ConflictingPeerContribution,
        EndpointAuthError::ChannelNotCurrent,
    ];

    #[test]
    fn v4_arc04f_every_task_owned_terminal_cause_agrees_on_the_lifecycle() {
        // The unification, stated over the whole closed set at once. Before it,
        // the causes disagreed: a refused proof, an unfresh pair and a
        // non-mutual context all recorded a terminal state while leaving the
        // task reporting itself live and still belonging to its connector, and
        // only explicit retirement wrote the observation cache. A caller could
        // therefore hold a dead attempt that answered `belongs_to` with `true`.
        //
        // Enumerated rather than sampled, because the property is that no cause
        // is special. Every one of these is a *task-owned* refusal, and since
        // the split that is now the only kind there is: the encoding, identity
        // and profile causes are refused at boundaries that hold no task and
        // carry the separate `EndpointAuthSetupError`, so they cannot be spelled
        // with this type at all, let alone driven here.
        //
        // Each block records the cause it actually observed, and the census
        // below closes the enumeration against the type itself.
        let mut observed: Vec<EndpointAuthError> = Vec::new();

        // A peer that echoed our own contribution back.
        {
            let (task, _peer_key, retained) = counted_task();
            let shared = PeerContribution::from_wire(&task.local_contribution())
                .expect("the local draw is canonical");
            assert_eq!(
                task.accept_peer_hello(shared),
                Err(EndpointAuthError::ContributionNotFresh)
            );
            assert_terminal_agreement(&task, EndpointAuthError::ContributionNotFresh, retained());
            observed.push(EndpointAuthError::ContributionNotFresh);
        }

        // A context with no second party. Built directly, because the whole
        // point is a Device pair `counted_task` cannot produce.
        {
            let (key, device) = fixture_key(1);
            let (handoff, retention) = counted_handoff_for_test(crate::runtime::runtime_for_test());
            let task = EndpointAuthTask::begin(
                context_for(MESH, &device, &device),
                handoff,
                signer_for_test(key),
            );
            assert_eq!(
                task.accept_peer_hello(peer_draw()),
                Err(EndpointAuthError::NotMutual)
            );
            assert_terminal_agreement(&task, EndpointAuthError::NotMutual, retention.count());
            observed.push(EndpointAuthError::NotMutual);
        }

        // A peer half that does not verify.
        {
            let (task, _peer_key, retained) = counted_task();
            task.accept_peer_hello(peer_draw()).expect("binds");
            assert_eq!(
                task.accept_peer_proof("not-a-signature").err(),
                Some(EndpointAuthError::SignatureInvalid)
            );
            assert_terminal_agreement(&task, EndpointAuthError::SignatureInvalid, retained());
            observed.push(EndpointAuthError::SignatureInvalid);
        }

        // A second, different contribution for an attempt already bound.
        {
            let (task, _peer_key, retained) = counted_task();
            task.accept_peer_hello(peer_draw()).expect("binds");
            assert_eq!(
                task.accept_peer_hello(peer_draw()),
                Err(EndpointAuthError::ConflictingPeerContribution)
            );
            assert_terminal_agreement(
                &task,
                EndpointAuthError::ConflictingPeerContribution,
                retained(),
            );
            observed.push(EndpointAuthError::ConflictingPeerContribution);
        }

        // A proof for an attempt that has bound nothing.
        {
            let (task, _peer_key, retained) = counted_task();
            assert_eq!(
                task.accept_peer_proof("premature").err(),
                Some(EndpointAuthError::NoBoundTranscript)
            );
            assert_terminal_agreement(&task, EndpointAuthError::NoBoundTranscript, retained());
            observed.push(EndpointAuthError::NoBoundTranscript);
        }

        // And the lifecycle event itself, so the predicate is not one that only
        // the failure causes satisfy.
        {
            let (task, _peer_key, retained) = counted_task();
            task.retire();
            assert_terminal_agreement(&task, EndpointAuthError::ChannelNotCurrent, retained());
            observed.push(EndpointAuthError::ChannelNotCurrent);
        }

        // The census. Every variant of the closed terminal type was produced by
        // a real transition above and shown to leave its attempt retired and
        // belonging to no connector — so "every returned `EndpointAuthError` is
        // terminal" is a statement about the type, not about the six cases
        // somebody remembered to write down.
        for cause in EVERY_TERMINAL_CAUSE {
            assert!(
                observed.contains(&cause),
                "{cause:?} is a terminal cause no transition drove here; its driver \
                 is `{}`, and an undriven variant is an error that terminalizes nothing",
                driver_of(cause)
            );
        }
        assert_eq!(
            observed.len(),
            EVERY_TERMINAL_CAUSE.len(),
            "and nothing was driven twice to stand in for a cause that was not"
        );
        // Distinct drivers, so the census cannot be satisfied by a mapping that
        // collapses several causes onto one transition and drives it once.
        let mut drivers: Vec<&'static str> = EVERY_TERMINAL_CAUSE
            .iter()
            .copied()
            .map(driver_of)
            .collect();
        drivers.sort_unstable();
        let distinct = drivers.len();
        drivers.dedup();
        assert_eq!(
            drivers.len(),
            distinct,
            "each terminal cause names its own transition"
        );
    }

    #[test]
    fn v4_arc04f_a_premature_proof_is_terminal_not_merely_refused() {
        // A proof cannot arrive before the Hello that binds the attempt: both
        // travel from one peer on one ordered channel, and the peer sends its
        // Hello first. So this frame is a peer violating the only ordering the
        // exchange has, and refusing it without ending the attempt left the
        // channel claim held open for a party that had already done something
        // it cannot do.
        let (task, peer_key, retained) = counted_task();

        assert_eq!(
            task.accept_peer_proof("premature").err(),
            Some(EndpointAuthError::NoBoundTranscript)
        );

        assert_terminal_agreement(&task, EndpointAuthError::NoBoundTranscript, retained());
        assert_eq!(
            task.signature_count(),
            0,
            "and nothing was signed for an attempt that had bound nothing"
        );

        // The attempt cannot be restarted. A Hello that would have bound it,
        // and then a genuine peer half over the value that Hello carried, both
        // answer with the cause that ended it.
        let peer = peer_draw();
        assert_eq!(
            task.accept_peer_hello(peer.clone()),
            Err(EndpointAuthError::NoBoundTranscript),
            "a later Hello cannot revive an attempt a premature proof ended"
        );
        assert_eq!(
            task.accept_peer_proof(&peer_proof_for_test(&task, &peer, &peer_key))
                .err(),
            Some(EndpointAuthError::NoBoundTranscript),
            "and neither can a proof that would otherwise have verified"
        );
        assert_eq!(task.signature_count(), 0);
        assert_eq!(retained(), 1, "the claim still goes back exactly once");
    }

    #[test]
    fn v4_arc04f_retirement_holding_the_lock_refuses_the_signature() {
        // Retirement wins. The barrier parks it *inside* the exchange critical
        // section, one step before its transition, and the Hello then blocks on
        // the real mutex — not on scheduler timing, and not on a sleep.
        let (task, _peer_key, retained) = counted_task();
        let barrier = LifecycleBarrier::at(LifecycleTrap::Retirement);
        task.arm_barrier(Arc::clone(&barrier));

        let retiring = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.retire())
        };
        barrier.await_entry();

        // The load-bearing observation, and the exact regression this closes.
        // Retirement holds the lock but has not committed, so nothing may see
        // it yet. When the cache was written *before* the lock, this already
        // read true — while a Hello holding the lock was still free to sign.
        // (Read through the atomic only: taking the exchange lock here would
        // deadlock against the thread the barrier is holding, which is the
        // point.)
        assert!(
            !task.is_retired(),
            "a retirement is not observable before its own transition commits"
        );
        assert!(
            task.belongs_to(task.incarnation()),
            "and the task still belongs to its connector until then"
        );

        let hello = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.accept_peer_hello(peer_draw()))
        };
        barrier.release();
        retiring.join().expect("the retiring thread completes");
        let refused = hello.join().expect("the hello thread completes");

        assert_eq!(
            refused,
            Err(EndpointAuthError::ChannelNotCurrent),
            "the Hello reaches the state after the retirement and is refused by it"
        );
        assert_eq!(
            task.signature_count(),
            0,
            "and it is refused before anything is signed, not after"
        );
        assert_eq!(task.draw_count(), 1, "the one draw is still the only draw");
        assert_terminal_agreement(&task, EndpointAuthError::ChannelNotCurrent, retained());
    }

    #[test]
    fn v4_arc04f_a_hello_holding_the_lock_commits_before_retirement_lands() {
        // The other order over the same pair of callers. The Hello is parked
        // inside the critical section with its signature about to commit, and
        // the retirement blocks on the mutex behind it — so the binding is not
        // lost, and the retirement is not lost either. One order, both facts.
        let (task, _peer_key, retained) = counted_task();
        let barrier = LifecycleBarrier::at(LifecycleTrap::SignatureCommit);
        task.arm_barrier(Arc::clone(&barrier));
        let peer = peer_draw();

        let binding = {
            let task = Arc::clone(&task);
            let peer = peer.clone();
            std::thread::spawn(move || task.accept_peer_hello(peer))
        };
        barrier.await_entry();
        let retiring = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.retire())
        };
        barrier.release();
        let accepted = binding
            .join()
            .expect("the hello thread completes")
            .expect("the Hello that holds the lock binds this attempt");
        retiring.join().expect("the retiring thread completes");

        assert!(
            matches!(accepted, AcceptedPeerHello::FirstBinding(_)),
            "the winning Hello is the one that established the attempt"
        );
        assert_eq!(
            task.signature_count(),
            1,
            "and its one signature committed rather than being torn out from under it"
        );
        assert_terminal_agreement(&task, EndpointAuthError::ChannelNotCurrent, retained());

        // The later Hello, carrying the exact value this attempt bound. The
        // state read precedes the cache, so a retired task answers no Hello
        // from it — a channel that is gone cannot keep replying with the proof
        // it produced while it was still there.
        assert_eq!(
            task.accept_peer_hello(peer),
            Err(EndpointAuthError::ChannelNotCurrent),
            "a retired task answers no Hello from its cache, not even the one it bound"
        );
        assert_eq!(
            task.signature_count(),
            1,
            "and the refused retransmission signs nothing"
        );
        assert_eq!(retained(), 1);
    }

    #[test]
    fn v4_arc04f_retirement_holding_the_lock_refuses_the_handoff_move() {
        // Retirement wins against a proof that would otherwise promote. The
        // handoff is what carries the channel claim, so this is the case where
        // losing the race would mint real authority over a channel the
        // lifecycle had already given up.
        let (task, peer_key, retained) = counted_task();
        let peer = peer_draw();
        task.accept_peer_hello(peer.clone()).expect("binds");
        let proof = peer_proof_for_test(&task, &peer, &peer_key);
        let barrier = LifecycleBarrier::at(LifecycleTrap::Retirement);
        task.arm_barrier(Arc::clone(&barrier));

        let retiring = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.retire())
        };
        barrier.await_entry();
        assert!(!task.is_retired());

        let promoting = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.accept_peer_proof(&proof))
        };
        barrier.release();
        retiring.join().expect("the retiring thread completes");
        let outcome = promoting.join().expect("the promoting thread completes");

        // `err()` rather than a comparison: the capability is deliberately
        // neither `Debug` nor `PartialEq`. If this had wrongly promoted, the
        // assertion fails here — before the retention count below could be
        // satisfied by the capability's own drop instead of by the retirement.
        assert_eq!(
            outcome.err(),
            Some(EndpointAuthError::ChannelNotCurrent),
            "a proof that verifies cannot move a handoff the retirement already released"
        );
        assert_eq!(
            task.signature_count(),
            1,
            "the refusal produces no second signature"
        );
        assert_terminal_agreement(&task, EndpointAuthError::ChannelNotCurrent, retained());
    }

    #[test]
    fn v4_arc04f_promotion_holding_the_lock_issues_a_capability_retirement_cannot_install() {
        // The last order: promotion wins, retirement lands behind it. The
        // capability is genuinely issued — the handoff moved — so the question
        // is what install does with it, and the answer must not depend on which
        // thread got there first.
        //
        // The positive twin runs first, over the identical construction with no
        // retirement, so the refusal below is attributable to the retirement
        // and not to anything about this fixture.
        {
            let (task, peer_key, _retained) = counted_task();
            let peer = peer_draw();
            task.accept_peer_hello(peer.clone()).expect("binds");
            let capability = task
                .accept_peer_proof(&peer_proof_for_test(&task, &peer, &peer_key))
                .expect("the fixture proof promotes")
                .into_promoted()
                .expect("the promotion issues the capability");
            let entry = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
                "arc04f-install-positive".to_string(),
                Arc::clone(&task),
            );

            assert!(
                entry.install_authenticated_channel(&task, capability),
                "non-vacuity: this exact construction installs while the task is live"
            );
            assert!(entry.has_authenticated_channel());
        }

        let (task, peer_key, retained) = counted_task();
        let peer = peer_draw();
        task.accept_peer_hello(peer.clone()).expect("binds");
        let proof = peer_proof_for_test(&task, &peer, &peer_key);
        let barrier = LifecycleBarrier::at(LifecycleTrap::HandoffMove);
        task.arm_barrier(Arc::clone(&barrier));

        let promoting = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.accept_peer_proof(&proof))
        };
        barrier.await_entry();
        assert!(
            !task.is_retired(),
            "the promotion holds the lock with the handoff still in place"
        );
        let retiring = {
            let task = Arc::clone(&task);
            std::thread::spawn(move || task.retire())
        };
        barrier.release();
        let capability = promoting
            .join()
            .expect("the promoting thread completes")
            .expect("the promotion that holds the lock completes")
            .into_promoted()
            .expect("the winning promotion issues the capability");
        retiring.join().expect("the retiring thread completes");

        // The capability is real and names this exact channel: promotion did
        // win, and this control is not quietly asserting that it failed.
        assert!(
            capability.belongs_to(task.incarnation()),
            "the promotion that won the lock issued authority over its own channel"
        );
        // But the task behind it is retired, and a retired task vouches for
        // nothing — including what it issued a moment earlier.
        assert!(task.is_retired());
        assert!(!task.belongs_to(task.incarnation()));
        assert_eq!(
            task.terminal_error(),
            Some(EndpointAuthError::ChannelNotCurrent)
        );
        assert!(
            !task.issued(&capability),
            "a retired task cannot prove it issued anything"
        );

        let entry = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "arc04f-install-after-retirement".to_string(),
            Arc::clone(&task),
        );

        assert!(
            !entry.install_authenticated_channel(&task, capability),
            "the real install refuses a capability whose task retirement already invalidated"
        );
        assert!(
            !entry.has_authenticated_channel(),
            "and no authority is installed by the refusal"
        );
        assert_eq!(
            retained(),
            1,
            "the refused capability hands the channel claim back exactly once"
        );
    }

    #[test]
    fn v4_arc04h_a_setup_refusal_is_not_a_task_terminalization() {
        // The discriminator for the split, asked of a live attempt. Every
        // variant of the closed pre-task refusal type is driven here — all five
        // of them, from the boundaries that actually produce them — while one
        // real task is in flight, and none of them is a lifecycle event: the
        // task is not retired, still belongs to its connector, holds no terminal
        // cause, has signed nothing, and has not handed its channel claim back.
        //
        // Before the split every one of them answered with `EndpointAuthError` —
        // the same type a dead attempt answers with — so a caller holding one could
        // not tell "a task is over" from "a string did not parse" and had to
        // consult its own state to find out. The types are what tell them apart
        // now: none of the values below can even be compared against a terminal
        // cause, let alone recorded as one.
        let (task, peer_key, retained) = counted_task();

        assert_eq!(
            PeerContribution::from_wire(""),
            Err(EndpointAuthSetupError::MissingContribution)
        );
        // Both sides of the width predicate, which one cause covers. Zero bytes
        // encode with clear trailing bits, so each decodes cleanly and is
        // refused on width alone rather than as a malformed spelling.
        let full_width = super::super::contribution::CONTRIBUTION_BYTES;
        for wrong_width in [full_width - 1, full_width + 1] {
            let zeros = vec![0u8; wrong_width];
            let value = data_encoding::BASE32_NOPAD.encode(&zeros).to_lowercase();
            assert_eq!(
                PeerContribution::from_wire(&value),
                Err(EndpointAuthSetupError::ContributionWrongWidth)
            );
        }
        assert_eq!(
            PeerContribution::from_wire("not-base32!"),
            Err(EndpointAuthSetupError::ContributionMalformed)
        );
        assert_eq!(
            super::super::negotiate_profile(&[]),
            Err(EndpointAuthSetupError::IncompatibleProfile)
        );
        assert_eq!(
            EndpointAuthContext::new(
                "",
                "device-a",
                "device-b",
                EndpointAuthBinding::webrtc_certificate_fingerprints(LOCAL_FP, REMOTE_FP)
                    .expect("both fixture components present"),
            )
            .err(),
            Some(EndpointAuthSetupError::MissingIdentityField)
        );

        assert_eq!(
            task.terminal_error(),
            None,
            "a setup refusal records no terminal cause on the attempt in flight"
        );
        assert!(
            !task.is_retired(),
            "and it retires nothing — it holds no task to retire"
        );
        assert!(
            task.belongs_to(task.incarnation()),
            "and the attempt goes on belonging to its connector"
        );
        assert_eq!(
            task.signature_count(),
            0,
            "and nothing was signed on the way through"
        );
        assert_eq!(
            retained(),
            0,
            "and no channel claim went back to its owner, because nothing closed"
        );

        // Non-vacuity, and the load-bearing half: the attempt is not merely
        // un-terminalized, it is still fully usable. It binds, it promotes, and
        // it vouches for exactly what it issued. A control that asserted only
        // "nothing was terminalized" would pass just as well against a fixture
        // that could never have got this far.
        let peer = peer_draw();
        assert!(
            matches!(
                task.accept_peer_hello(peer.clone())
                    .expect("the first canonical contribution binds this attempt"),
                AcceptedPeerHello::FirstBinding(_)
            ),
            "the attempt the setup refusals ran beside is still the one that binds"
        );
        let capability = task
            .accept_peer_proof(&peer_proof_for_test(&task, &peer, &peer_key))
            .expect("and still the one that promotes")
            .into_promoted()
            .expect("the promotion issues the capability");
        assert!(
            task.issued(&capability),
            "and it vouches for the capability it issued"
        );
        assert_eq!(
            retained(),
            0,
            "the claim moved into the capability rather than back to its owner"
        );
    }
}
