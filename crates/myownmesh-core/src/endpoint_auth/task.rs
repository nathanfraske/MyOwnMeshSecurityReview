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
//! signature; a conflicting value is a typed terminal failure that retires this
//! exact task through the handoff's own owner path. There is no engine-level
//! "already authenticated" exception: duplicate versus conflict is decided
//! here, by comparing against the bound value.

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
pub(crate) struct LocalIdentitySigner {
    key: ed25519_dalek::SigningKey,
}

impl LocalIdentitySigner {
    /// Take the caller's existing Device signing key.
    ///
    /// The engine already holds this key and used to sign with it directly.
    /// Handing it here is the whole cutover: the key moves into the task's
    /// ownership at construction, and the engine never signs again.
    pub(crate) fn from_signing_key(key: ed25519_dalek::SigningKey) -> Self {
        Self { key }
    }

    fn sign(&self, message: &[u8]) -> String {
        crate::signing::sign_with(&self.key, message)
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
/// returns a typed error instead, so no caller can treat it as an accepted
/// Hello carrying a proof.
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

impl EndpointAuthExchange {
    /// Enter the terminal state, releasing the channel through its exact owner.
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
    fn retire_terminally(&mut self, error: EndpointAuthError) -> EndpointAuthError {
        if let ExchangeState::Terminal(existing) = &self.state {
            return *existing;
        }
        drop(self.handoff.take());
        self.state = ExchangeState::Terminal(error);
        error
    }
}

/// One runtime owner of one endpoint-authentication attempt over one exact
/// connected channel.
pub(crate) struct EndpointAuthTask {
    /// Retained separately from the exchange, so the task still names its exact
    /// connector incarnation after promotion has moved the handoff out.
    incarnation: Arc<ConnectorIncarnation>,
    /// Explicit lifecycle, kept separate from handoff presence: a promoted task
    /// still belongs to its connector, while a retired one belongs to none.
    retired: AtomicBool,
    exchange: Mutex<EndpointAuthExchange>,
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
        }
    }

    fn lock(&self) -> MutexGuard<'_, EndpointAuthExchange> {
        self.exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    /// Marked before the channel is released, so no observer sees a task that
    /// has lost its channel but still reports itself live. Dropping the handoff
    /// runs its retention, so a retired task returns the channel claim rather
    /// than stranding it, and can never authenticate again.
    ///
    /// Retirement is a lifecycle fact, not a cause. A task that already failed
    /// becomes retired while keeping the error that refused it, and its claim
    /// stays returned exactly once.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.lock()
            .retire_terminally(EndpointAuthError::ChannelNotCurrent);
    }

    /// Bind the peer contribution and return this endpoint's proof.
    ///
    /// First canonical value binds and signs exactly once. An exact duplicate —
    /// including after promotion — returns the cached proof: no draw, no
    /// transcript rebuild, no second signature. A conflicting value is terminal
    /// for this exact task.
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
        // Bound and promoted answer identically: promotion moves the channel
        // out, it does not change what this attempt bound. An exact duplicate
        // is answered from the cache in both states; a conflicting value is
        // terminal in both. After promotion the handoff is already gone, so a
        // conflict retires this task without touching the capability that was
        // issued from it.
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
                let error = exchange.retire_terminally(EndpointAuthError::ChannelNotCurrent);
                self.retired.store(true, Ordering::Release);
                return Err(error);
            }
            ExchangeState::AwaitingPeerContribution => {}
        }

        if peer_contribution.as_str() == exchange.local_contribution.as_str() {
            return Err(exchange.retire_terminally(EndpointAuthError::ContributionNotFresh));
        }
        if exchange.context.local_device_id() == exchange.context.expected_remote_device_id() {
            return Err(exchange.retire_terminally(EndpointAuthError::NotMutual));
        }

        let transcript = transcript::transcript_for_context(
            &exchange.context,
            exchange.context.local_role(),
            exchange.local_contribution.as_str(),
            peer_contribution.as_str(),
        );
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
    pub(crate) fn accept_peer_proof(
        &self,
        peer_signature: &str,
    ) -> Result<AuthenticatedChannelCapability, EndpointAuthError> {
        let mut exchange = self.lock();
        let (peer_contribution, local_proof) = match &exchange.state {
            ExchangeState::Bound {
                peer_contribution,
                local_proof,
            } => (peer_contribution.clone(), local_proof.clone()),
            ExchangeState::Terminal(error) => return Err(*error),
            // One promotion per attempt: the channel has already moved.
            ExchangeState::Promoted { .. } => return Err(EndpointAuthError::ChannelNotCurrent),
            ExchangeState::AwaitingPeerContribution => {
                return Err(EndpointAuthError::MissingTranscriptField)
            }
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
            return Err(exchange.retire_terminally(EndpointAuthError::SignatureInvalid));
        }

        // Every borrow-checkable condition is satisfied; only now does the
        // handoff move.
        let Some(handoff) = exchange.handoff.take() else {
            return Err(exchange.retire_terminally(EndpointAuthError::ChannelNotCurrent));
        };
        let Some(runtime) = handoff.capability().map(|c| c.runtime().clone()) else {
            // Nothing to promote: dropping the handoff hands the claim back to
            // its owner path.
            drop(handoff);
            return Err(exchange.retire_terminally(EndpointAuthError::ChannelNotCurrent));
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
        Ok(AuthenticatedChannelCapability::from_verified_exchange(
            record, handoff,
        ))
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
    EndpointAuthTask::begin(
        context,
        handoff,
        LocalIdentitySigner::from_signing_key(local_key),
    )
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
            LocalIdentitySigner::from_signing_key(local_key),
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
            .expect("a complete mutual proof promotes");

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
            LocalIdentitySigner::from_signing_key(local_key),
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
        let (local_key, local_device) = fixture_key(1);
        let (_, remote_device) = fixture_key(2);
        let (handoff, retention) = counted_handoff_for_test(crate::runtime::runtime_for_test());
        let task = EndpointAuthTask::begin(
            context_for(MESH, &local_device, &remote_device),
            handoff,
            LocalIdentitySigner::from_signing_key(local_key),
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
            Some(EndpointAuthError::MissingTranscriptField)
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
            LocalIdentitySigner::from_signing_key(key),
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
            Some(EndpointAuthError::MissingTranscriptField)
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
        // retransmission. It is terminal for this exact task.
        let fixture = fixture();
        fixture.task.accept_peer_hello(peer_draw()).expect("binds");

        assert_eq!(
            fixture.task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::ChannelNotCurrent)
        );
        assert!(fixture.task.is_retired());
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
            .expect("promotes");

        assert_eq!(
            fixture.task.accept_peer_hello(peer_draw()),
            Err(EndpointAuthError::ChannelNotCurrent)
        );
        assert!(fixture.task.is_retired());
        // The capability that was already issued is untouched: it still names
        // its own record and its own connector.
        assert!(capability.authenticated_for(MESH, capability.record().remote_device_id()));
        assert!(capability.belongs_to(fixture.task.incarnation()));
    }

    #[test]
    fn v4_arc04_duplicate_auth_response_after_promotion_is_refused() {
        // Migrated retry control: one attempt promotes exactly once.
        let fixture = fixture();
        let peer = peer_draw();
        fixture.task.accept_peer_hello(peer.clone()).expect("binds");
        let proof = fixture.peer_proof(&peer);
        fixture.task.accept_peer_proof(&proof).expect("promotes");

        assert!(matches!(
            fixture.task.accept_peer_proof(&proof),
            Err(EndpointAuthError::ChannelNotCurrent)
        ));
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
            .expect("promotes");
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
}
