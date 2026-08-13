//! Live two-connector endpoint-authentication controls.
//!
//! These are basal V4 controls. They are gated on `transport-lab` alone, and
//! they are the only controls that drive the production
//! `engine::handshake::on_auth_response` over a real DTLS link.
//!
//! The fixture opens two real WebRTC connectors, lets them complete ICE and
//! DTLS, and builds each side's [`EndpointAuthTask`] exactly the way the
//! production `DataChannelOpen` path does: the connector states its binding, the
//! context fixes the mesh and the Device pair, and the signing key moves into
//! the task. Nothing here reaches into task state or supplies a proof half.
//!
//! The two controls are twins over that one fixture. They construct identical
//! attempts and differ in exactly one value — the remote fingerprint the peer's
//! proof commits to — so the fingerprint field is load-bearing rather than
//! incidental: the negative fails *because* of the substitution, and the
//! positive proves the same construction promotes when nothing is substituted.
//!
//! [`connect_before_engine_open`] is the second fixture, and it exists because
//! [`connect`] performs the promotion itself. The open-path controls need the
//! production engine arm to be the thing that promotes, so that fixture stops at
//! the left connector's own native open callback and hands it over unconsumed.
//! It is the fixture, not a re-implementation of the arm: it opens the link and
//! nothing else.

use super::contribution::{LocalContribution, PeerContribution};
use super::transcript;
use super::{
    EndpointAuthContext, EndpointAuthError, EndpointAuthSetupError, EndpointAuthTask,
    LocalIdentitySigner,
};
use crate::connector::EndpointAuthBinding;
use crate::engine::state::NetworkState;
use crate::protocol::handshake::AuthResponseMessage;
use crate::transport::webrtc::WebRtcConnectorEventReceiver;
use crate::transport::{
    DataChannelOpenOwnership, Role, TransportEvent, WebRtcConnectorEvent, WebRtcConnectorWorker,
};
use std::sync::Arc;
use std::time::Duration;

/// Two live connectors and the exact task each side owns for that channel.
///
/// `left`, `left_auth` and `right` are read by the twins below and by the
/// engine's captured-send control. The underscore-named fields are read by
/// nothing and are **owned** regardless: dropping a receiver stops that
/// connector's event pump, and dropping a task returns its connected claim,
/// either of which would quietly weaken the live-link controls that keep the
/// right side up. They are lifetime anchors — held, never read, never dropped
/// early.
pub(crate) struct TestLink {
    pub(crate) left: Arc<WebRtcConnectorWorker>,
    pub(crate) _left_events: WebRtcConnectorEventReceiver,
    pub(crate) left_auth: Arc<EndpointAuthTask>,
    pub(crate) right: Arc<WebRtcConnectorWorker>,
    pub(crate) _right_events: Option<WebRtcConnectorEventReceiver>,
    pub(crate) _right_auth: Arc<EndpointAuthTask>,
}

/// Build one endpoint's task the way the production open path builds it.
///
/// Deliberately mirrors `engine::mod`'s `DataChannelOpen` arm: the binding is
/// taken from the connector before the handoff moves, the context is fixed from
/// the mesh and the exact Device pair, the profile is derived inside endpoint
/// authentication rather than selected here, and the signing key moves into the
/// task. A fixture that constructed the context differently could prove nothing
/// about the production transition.
async fn task_for_open_channel(
    state: &Arc<NetworkState>,
    worker: &Arc<WebRtcConnectorWorker>,
    remote_device_id: &str,
    handoff: crate::connector::ConnectedChannelHandoff,
) -> EndpointAuthTask {
    let binding = worker
        .endpoint_auth_binding()
        .await
        .expect("a live DTLS link states both fingerprint components");
    let context = EndpointAuthContext::new(
        &state.network_id,
        state.identity.public_id(),
        crate::signing::pubkey_part(remote_device_id),
        binding,
    )
    .expect("live mesh and Device identifiers are non-empty");
    EndpointAuthTask::begin(
        context,
        handoff,
        LocalIdentitySigner::for_identity(Arc::clone(&state.identity)),
    )
}

/// Open a real offerer/answerer pair and promote both data channels.
pub(crate) async fn connect(
    left_state: &Arc<NetworkState>,
    right_state: &Arc<NetworkState>,
) -> TestLink {
    let left_remote = right_state.identity.public_id().to_string();
    let right_remote = left_state.identity.public_id().to_string();
    let (left, mut left_events) = left_state
        .transport
        .open_connector_peer(
            Role::Offerer,
            &[],
            &[],
            left_state.peer_connection_resource_scope(),
        )
        .await
        .expect("left connector opens");
    let (right, mut right_events) = right_state
        .transport
        .open_connector_peer(
            Role::Answerer,
            &[],
            &[],
            right_state.peer_connection_resource_scope(),
        )
        .await
        .expect("right connector opens");
    let left = Arc::new(left);
    let right = Arc::new(right);

    // `apply_remote_sdp` takes the exact SDP type and the owned string, so
    // provider admission happens before the native dependency parses or retains
    // anything.
    let offer = left.create_offer().await.expect("create offer");
    right
        .apply_remote_sdp(offer.sdp_type, offer.sdp)
        .await
        .expect("apply offer");
    let answer = right.create_answer().await.expect("create answer");
    left.apply_remote_sdp(answer.sdp_type, answer.sdp)
        .await
        .expect("apply answer");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut left_auth = None;
    let mut right_auth = None;
    while (left_auth.is_none() || right_auth.is_none()) && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = left_events.recv() => {
                let event = event.expect("left connector remains live");
                if let Some(event) = left.accept_event(event) {
                    let (event, _callback_resources) = event.into_parts();
                    match event {
                        TransportEvent::LocalIceCandidate(Some(candidate)) => {
                            right.add_remote_candidate(candidate).await.expect("right accepts candidate");
                        }
                        TransportEvent::DataChannelOpen if left_auth.is_none() => {
                            let connected = match left.confirm_data_channel_open() {
                                DataChannelOpenOwnership::Connected(connected) => connected,
                                _ => panic!("left exact candidate promotes once"),
                            };
                            let handoff = connected
                                .into_generic()
                                .expect("a connected handoff carries its capability");
                            left_events.commit_data_channel_open();
                            left_auth = Some(Arc::new(
                                task_for_open_channel(left_state, &left, &left_remote, handoff).await,
                            ));
                        }
                        _ => {}
                    }
                }
            }
            event = right_events.recv() => {
                let event = event.expect("right connector remains live");
                if let Some(event) = right.accept_event(event) {
                    let (event, _callback_resources) = event.into_parts();
                    match event {
                        TransportEvent::LocalIceCandidate(Some(candidate)) => {
                            left.add_remote_candidate(candidate).await.expect("left accepts candidate");
                        }
                        TransportEvent::DataChannelOpen if right_auth.is_none() => {
                            let connected = match right.confirm_data_channel_open() {
                                DataChannelOpenOwnership::Connected(connected) => connected,
                                _ => panic!("right exact candidate promotes once"),
                            };
                            let handoff = connected
                                .into_generic()
                                .expect("a connected handoff carries its capability");
                            right_events.commit_data_channel_open();
                            right_auth = Some(Arc::new(
                                task_for_open_channel(right_state, &right, &right_remote, handoff).await,
                            ));
                        }
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }

    // Both sides are asserted to have come up before either is stored: the
    // fixture's contract is a live link on both ends, and that must not become
    // weaker because nothing reads the right half.
    let left_auth = left_auth.expect("left data channel opens");
    let right_auth = right_auth.expect("right data channel opens");
    TestLink {
        left,
        _left_events: left_events,
        left_auth,
        right,
        _right_events: Some(right_events),
        _right_auth: right_auth,
    }
}

/// A live link whose left data channel is open but **not yet promoted**.
///
/// [`connect`] cannot serve the open-path controls, because it performs the
/// promotion itself: it confirms the left channel and builds the left task, so a
/// control reusing it would find the connector already connected and the
/// production arm would take its duplicate branch without ever installing a
/// task. The positive twin would then prove nothing about installation, and the
/// negative's "no task" assertion would have nothing to be discriminating
/// against.
///
/// So this stops one step earlier. The left connector is live, its data channel
/// is genuinely open, and its own native open callback is held here unconsumed —
/// the real event, not one stamped by a fixture — so the engine's own
/// `DataChannelOpen` arm can be driven with exactly what the native stack
/// produced.
pub(crate) struct LinkBeforeEngineOpen {
    pub(crate) left: Arc<WebRtcConnectorWorker>,
    /// Lifetime anchor. Dropping it stops the connector's event pump, which
    /// would retire the very link the controls are asserting is live.
    pub(crate) _left_events: WebRtcConnectorEventReceiver,
    pub(crate) right: Arc<WebRtcConnectorWorker>,
    /// The far connector's event stream.
    ///
    /// Lifetime anchor first and foremost: dropping it stops that connector's
    /// event pump, which would retire the very link the controls assert is live.
    /// Most controls therefore only ever borrow it, through
    /// [`Self::right_events_mut`], to scan for a frame they expect.
    ///
    /// An `Option` so that a control which needs to *drive* the far side —
    /// feeding its frames into a far engine rather than reading them on its own
    /// thread — can take the receiver out and own it, while the rest of the
    /// fixture stays alive. A fixture whose receiver has been taken is one whose
    /// far side is being pumped by somebody else, and asking it to scan for a
    /// frame is a mistake rather than a wait; that is why taking leaves `None`
    /// and the borrow panics rather than blocking forever.
    right_events: Option<WebRtcConnectorEventReceiver>,
    /// The left connector's genuine `DataChannelOpen` callback, unconsumed.
    ///
    /// An `Option` so a caller can take the event out while the fixture — and
    /// with it both event receivers — stays alive. Destructuring the fixture to
    /// get at the event would drop those receivers, stopping the connectors'
    /// event pumps at the exact moment the control is asserting the link is up.
    left_open_event: Option<WebRtcConnectorEvent>,
}

/// The open-path fixture with its far side proved ready to receive frames.
///
/// The right handoff is retained only as the exact ownership witness produced
/// by that connector's genuine open callback. The left callback remains inside
/// `link`, unconsumed, for the production engine arm to promote.
pub(crate) struct ReceiveReadyLinkBeforeEngineOpen {
    pub(crate) link: LinkBeforeEngineOpen,
    /// The far connector's own ownership witness, from its own open callback.
    ///
    /// Held, not consumed, by every control that only needs the far side to be
    /// *receiving*. An `Option` so that a control which needs the far side to be
    /// a full participant — with its own promoted session, dispatching what it
    /// receives — can take this handoff and install it, which is the one thing
    /// that turns a receiving far side into a responding one.
    right_handoff: Option<crate::connector::ConnectedChannelHandoff>,
}

impl ReceiveReadyLinkBeforeEngineOpen {
    /// Take the far connector's handoff, to promote a session over it. Exactly
    /// once per fixture.
    pub(crate) fn take_right_handoff(&mut self) -> crate::connector::ConnectedChannelHandoff {
        self.right_handoff
            .take()
            .expect("the far handoff is taken exactly once")
    }
}

impl LinkBeforeEngineOpen {
    /// Borrow the near connector's event stream, to read what the far side
    /// sent.
    ///
    /// Only a control that is itself standing in for the near engine has any
    /// business here — an ordinary control's near side is driven by the engine
    /// under test.
    pub(crate) fn left_events_mut(&mut self) -> &mut WebRtcConnectorEventReceiver {
        &mut self._left_events
    }

    /// Borrow the far connector's event stream, to scan it for an expected
    /// frame.
    pub(crate) fn right_events_mut(&mut self) -> &mut WebRtcConnectorEventReceiver {
        self.right_events
            .as_mut()
            .expect("this fixture's far side is being pumped by its own engine, so its events are not this control's to read")
    }

    /// Take the far connector's event stream, to drive a far-side engine with
    /// it. Exactly once per fixture; see [`Self::right_events`].
    pub(crate) fn take_right_events(&mut self) -> WebRtcConnectorEventReceiver {
        self.right_events
            .take()
            .expect("the far event stream is taken exactly once")
    }

    /// Take the genuine native open callback. Exactly once per fixture.
    pub(crate) fn take_open_event(&mut self) -> WebRtcConnectorEvent {
        self.left_open_event
            .take()
            .expect("the open callback is taken exactly once")
    }

    /// Close both control connectors and hand back what each close reported.
    ///
    /// Outcomes are returned rather than unwrapped because at least one control
    /// deliberately makes a native close fail: there, the left connector's close
    /// owner is *supposed* to answer with a retained-claim error, and a fixture
    /// that unwrapped it would turn the behaviour under test into a fixture
    /// panic. A control that expects clean closes asserts that on the returned
    /// outcomes.
    ///
    /// Both connectors are always closed, in the same order, before anything is
    /// returned — a control cannot use this to skip closing one of them.
    pub(crate) async fn close_outcomes(self) -> Vec<crate::Result<()>> {
        let mut outcomes = Vec::with_capacity(2);
        for worker in [&self.left, &self.right] {
            outcomes.push(worker.retire_and_close().await);
        }
        outcomes
    }
}

/// Open a real offerer/answerer pair and stop at the left's open callback.
///
/// Neither side is promoted and no task is built: promotion is what the
/// production engine arm is supposed to perform, so a fixture that performed it
/// first would be standing in for the code under test.
pub(crate) async fn connect_before_engine_open(
    left_state: &Arc<NetworkState>,
    right_state: &Arc<NetworkState>,
) -> LinkBeforeEngineOpen {
    connect_before_engine_open_inner(left_state, right_state, false)
        .await
        .0
}

/// Open the same real pair while also proving the right connector is ready to
/// receive a frame. This is narrower than [`connect_before_engine_open`]: only
/// the controls that assert on bytes reaching the far side need the far-side
/// connected ownership, while the open-path controls deliberately stop without
/// promoting it.
pub(crate) async fn connect_before_engine_open_receive_ready(
    left_state: &Arc<NetworkState>,
    right_state: &Arc<NetworkState>,
) -> ReceiveReadyLinkBeforeEngineOpen {
    let (link, right_handoff) =
        connect_before_engine_open_inner(left_state, right_state, true).await;
    ReceiveReadyLinkBeforeEngineOpen {
        link,
        right_handoff: Some(
            right_handoff.expect("receive-ready construction yields a right handoff"),
        ),
    }
}

async fn connect_before_engine_open_inner(
    left_state: &Arc<NetworkState>,
    right_state: &Arc<NetworkState>,
    require_right_ready: bool,
) -> (
    LinkBeforeEngineOpen,
    Option<crate::connector::ConnectedChannelHandoff>,
) {
    let (left, mut left_events) = left_state
        .transport
        .open_connector_peer(
            Role::Offerer,
            &[],
            &[],
            left_state.peer_connection_resource_scope(),
        )
        .await
        .expect("left connector opens");
    let (right, mut right_events) = right_state
        .transport
        .open_connector_peer(
            Role::Answerer,
            &[],
            &[],
            right_state.peer_connection_resource_scope(),
        )
        .await
        .expect("right connector opens");
    let left = Arc::new(left);
    let right = Arc::new(right);

    // The production V4 ingress entry point, exactly as `connect` uses it.
    let offer = left.create_offer().await.expect("create offer");
    right
        .apply_remote_sdp(offer.sdp_type, offer.sdp)
        .await
        .expect("apply offer");
    let answer = right.create_answer().await.expect("create answer");
    left.apply_remote_sdp(answer.sdp_type, answer.sdp)
        .await
        .expect("apply answer");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut left_open_event = None;
    let mut right_handoff = None;
    while (left_open_event.is_none() || (require_right_ready && right_handoff.is_none()))
        && tokio::time::Instant::now() < deadline
    {
        tokio::select! {
            event = left_events.recv() => {
                let event = event.expect("left connector remains live");
                // Classified before acceptance, never through it: `accept_event`
                // consumes the value, and this is the one event the control has
                // to deliver intact to the production handler.
                if event.is_data_channel_open() {
                    left_open_event = Some(event);
                    continue;
                }
                if let Some(event) = left.accept_event(event) {
                    let (event, _callback_resources) = event.into_parts();
                    if let TransportEvent::LocalIceCandidate(Some(candidate)) = event {
                        right.add_remote_candidate(candidate).await.expect("right accepts candidate");
                    }
                }
            }
            event = right_events.recv() => {
                let event = event.expect("right connector remains live");
                if let Some(event) = right.accept_event(event) {
                    let (event, _callback_resources) = event.into_parts();
                    match event {
                        TransportEvent::LocalIceCandidate(Some(candidate)) => {
                            left.add_remote_candidate(candidate).await.expect("left accepts candidate");
                        }
                        TransportEvent::DataChannelOpen
                            if require_right_ready && right_handoff.is_none() =>
                        {
                            let connected = match right.confirm_data_channel_open() {
                                DataChannelOpenOwnership::Connected(connected) => connected,
                                _ => panic!("right exact candidate promotes once"),
                            };
                            right_handoff = Some(
                                connected
                                    .into_generic()
                                    .expect("a connected right handoff carries its capability"),
                            );
                            right_events.commit_data_channel_open();
                        }
                        // The ordinary fixture needs a live DTLS peer and
                        // nothing more. Its right open remains deliberately
                        // unpromoted because those controls ask for no claim.
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }

    (
        LinkBeforeEngineOpen {
            left,
            _left_events: left_events,
            right,
            right_events: Some(right_events),
            left_open_event: Some(left_open_event.expect("left data channel opens")),
        },
        right_handoff,
    )
}

/// Everything one twin needs to play the peer against a live left-side task.
struct LiveAttempt {
    state_a: Arc<NetworkState>,
    state_b: Arc<NetworkState>,
    link: TestLink,
    owner: crate::engine::peer_registry::PeerOwnerToken,
    /// The peer contribution bound into the left task, so the twin can derive
    /// exactly the bytes that task will verify.
    peer_contribution: PeerContribution,
    observed_local: String,
    observed_remote: String,
}

/// Drive one real link up to the point where only the peer's proof is missing.
///
/// Shared verbatim by both twins: same states, same connectors, same task, same
/// bound contribution pair. Only the fingerprint the peer's proof commits to is
/// chosen afterwards, by the caller, so the twins differ in exactly that value.
async fn live_attempt(suffix_a: &str, suffix_b: &str) -> LiveAttempt {
    let state_a = crate::engine::build_test_state(suffix_a);
    let state_b = crate::engine::build_test_state(suffix_b);
    let id_b = state_b.identity.public_id().to_string();

    let link = connect(&state_a, &state_b).await;
    // Pre-promotion state on purpose: these controls must observe the peer's
    // proof succeed or fail, so neither may start with a capability already
    // installed. The shared *admitted* fixture preinstalls one, which would
    // mask exactly the outcome under test.
    crate::engine::insert_legacy_test_peer_pending_auth(
        &state_a,
        &id_b,
        Arc::clone(&link.left),
        Arc::clone(&link.left_auth),
    );
    let owner = crate::engine::legacy_test_owner(&state_a, &id_b).expect("peer owner is installed");
    assert!(
        !crate::engine::legacy_test_has_authenticated_channel(&state_a, &owner),
        "non-vacuity: the channel must be unauthenticated before the peer's proof"
    );

    // The genuine channel material this side observes.
    let observed_local = link
        .left
        .local_fingerprint()
        .await
        .expect("the live link exposes our fingerprint");
    let observed_remote = link
        .left
        .remote_fingerprint()
        .await
        .expect("the live link exposes the peer's fingerprint");

    // Bind the peer's contribution through the task's own entry point, exactly
    // as `on_hello` does. The task draws its own half and caches its own proof;
    // nothing here supplies either.
    let peer_contribution = PeerContribution::from_wire(LocalContribution::generate().as_str())
        .expect("a generated draw is canonical");
    let bound = link
        .left_auth
        .accept_peer_hello(peer_contribution.clone())
        .expect("the first canonical contribution binds this attempt");
    assert!(
        matches!(bound, super::AcceptedPeerHello::FirstBinding(_)),
        "non-vacuity: this must be the Hello that binds, not a repeat"
    );

    LiveAttempt {
        state_a,
        state_b,
        link,
        owner,
        peer_contribution,
        observed_local,
        observed_remote,
    }
}

impl LiveAttempt {
    /// The peer's half, committing to the caller's chosen remote fingerprint.
    ///
    /// Every other field is the genuine one: right signer, right identities,
    /// right mesh context, right derived profile, right contribution pair. The
    /// mirror context reconstructs what the peer would sign, so the only way
    /// the two twins diverge is the component passed here.
    fn peer_proof_committing_to(&self, remote_component: &str) -> String {
        let mirror = EndpointAuthContext::new(
            &self.state_a.network_id,
            self.state_a.identity.public_id(),
            crate::signing::pubkey_part(self.state_b.identity.public_id()),
            EndpointAuthBinding::webrtc_certificate_fingerprints(
                &self.observed_local,
                remote_component,
            )
            .expect("both components present"),
        )
        .expect("live mesh and Device identifiers are non-empty");
        crate::signing::sign_with(
            self.state_b.identity.signing_key(),
            &transcript::transcript_for_context(
                &mirror,
                mirror.local_role().peer(),
                &self.link.left_auth.local_contribution(),
                self.peer_contribution.as_str(),
            ),
        )
    }

    /// The fixture really is on a live link whose production supplier states
    /// both components.
    ///
    /// Every missing-component control below removes one side of a pair it
    /// obtained from this exact supplier, so this is what makes those controls
    /// statements about the live boundary rather than about two string
    /// literals. The two components must also differ, or blanking the local
    /// side would be indistinguishable from blanking the remote one.
    async fn assert_live_supplier_states_both_components(&self) {
        assert!(
            !self.observed_local.is_empty(),
            "the live link states this endpoint's fingerprint"
        );
        assert!(
            !self.observed_remote.is_empty(),
            "the live link states the peer's fingerprint"
        );
        assert_ne!(
            self.observed_local, self.observed_remote,
            "non-vacuity: each endpoint presents its own certificate, so the two \
             sides are distinguishable"
        );
        assert!(
            self.link.left.endpoint_auth_binding().await.is_some(),
            "non-vacuity: the production supplier yields a binding on this live link, \
             so a refusal below is the missing component and not an unusable fixture"
        );
    }

    /// The genuine pair this live link observed, as the supplier would state it.
    fn observed_binding(&self) -> crate::connector::EndpointAuthBinding {
        EndpointAuthBinding::webrtc_certificate_fingerprints(
            &self.observed_local,
            &self.observed_remote,
        )
        .expect("the live link states both components")
    }

    async fn close(self) {
        for worker in [&self.link.left, &self.link.right] {
            worker
                .retire_and_close()
                .await
                .expect("native control connector closes");
        }
    }
}

/// Terminating-signaling-MITM / fingerprint substitution, through the live
/// `on_auth_response` handler.
///
/// An interceptor that terminates DTLS on each leg must present its own
/// certificate, so the fingerprints the victim observes differ from the ones
/// the real peer signed. This drives that condition on a real link: the
/// AuthResponse is otherwise entirely correct and differs only in the
/// fingerprint pair it commits to.
///
/// Transcript-level inequality is not the gate. This asserts the production
/// handler refuses the exact current peer, that the refusal is the typed
/// `SignatureInvalid` rather than an unrelated failure, and that no
/// authenticated capability is installed.
#[tokio::test]
#[ignore = "opens a native WebRTC link; run in the isolated native endpoint-auth control"]
async fn v4_arc04_substituted_fingerprint_is_refused_by_the_live_handler() {
    let attempt = live_attempt("arc04-mitm-a", "arc04-mitm-b").await;

    // What an interceptor would have presented instead.
    let substituted_remote = format!("{}:ff", attempt.observed_remote);
    assert_ne!(
        substituted_remote, attempt.observed_remote,
        "non-vacuity: the substituted fingerprint must differ from the observed one"
    );
    let forged = attempt.peer_proof_committing_to(&substituted_remote);

    crate::engine::handshake::on_auth_response(
        &attempt.state_a,
        &attempt.owner,
        AuthResponseMessage { signature: forged },
    )
    .await;

    assert!(
        !crate::engine::legacy_test_has_authenticated_channel(&attempt.state_a, &attempt.owner),
        "a proof committing to a substituted fingerprint must not authenticate this channel"
    );
    // Fail-closed for the exact stated reason: the proof did not verify over
    // this attempt's transcript. Asserting only the absence of a capability
    // would also pass if the attempt had died for an unrelated reason.
    assert_eq!(
        attempt.link.left_auth.terminal_error(),
        Some(EndpointAuthError::SignatureInvalid),
        "the refusal must be the typed signature failure, not an incidental one"
    );
    attempt.close().await;
}

/// The positive twin: the same construction, with nothing substituted.
///
/// Identical to the negative in every respect except that the peer's proof
/// commits to the fingerprint this endpoint actually observed. That the same
/// fixture promotes here is what makes the negative's refusal attributable to
/// the substitution rather than to the fixture never being able to promote at
/// all.
#[tokio::test]
#[ignore = "opens a native WebRTC link; run in the isolated native endpoint-auth control"]
async fn v4_arc04_observed_fingerprint_promotes_through_the_live_handler() {
    let attempt = live_attempt("arc04-observed-a", "arc04-observed-b").await;

    let genuine = attempt.peer_proof_committing_to(&attempt.observed_remote);

    crate::engine::handshake::on_auth_response(
        &attempt.state_a,
        &attempt.owner,
        AuthResponseMessage { signature: genuine },
    )
    .await;

    assert!(
        crate::engine::legacy_test_has_authenticated_channel(&attempt.state_a, &attempt.owner),
        "a proof committing to the observed fingerprint pair must promote this channel"
    );
    assert_eq!(
        attempt.link.left_auth.terminal_error(),
        None,
        "a promoted attempt holds no terminal error"
    );
    attempt.close().await;
}

/// Missing **local** fingerprint, against the live link's own material.
///
/// The review requires the fingerprint field to be load-bearing rather than
/// incidental: a half pair must fail closed on its own account, not because
/// something unrelated happened to break. This removes exactly one component
/// from a pair this live link's production supplier actually stated, leaves the
/// other component genuine, and asserts nothing can be built from the result.
///
/// The refusal lands at the only constructor, one step *before* a typed error
/// is reachable: with no binding there is no context, so no task, transcript,
/// proof, or capability can exist for a half pair. The typed
/// `EndpointAuthSetupError::MissingIdentityField` refusal asserted afterwards is
/// that same missing-required-field rule at the next boundary down, where a
/// typed cause does exist — stated here so the two are pinned together rather
/// than assumed to agree.
///
/// That cause is a *setup* one and deliberately not a terminal one: nothing has
/// been built yet, so there is no attempt for it to end. What fails this path
/// closed is the production caller retiring the exact connector, not the value.
#[tokio::test]
#[ignore = "opens a native WebRTC link; run in the isolated native endpoint-auth control"]
async fn v4_arc04d_missing_local_fingerprint_is_fail_closed_on_a_live_link() {
    let attempt = live_attempt("arc04d-missing-local-a", "arc04d-missing-local-b").await;
    attempt.assert_live_supplier_states_both_components().await;

    assert!(
        EndpointAuthBinding::webrtc_certificate_fingerprints("", &attempt.observed_remote)
            .is_none(),
        "a missing local fingerprint must yield no binding at all"
    );
    // Discriminating: the same call differing only in the restored local
    // component succeeds on this same live material, so the refusal above is
    // attributable to the missing local side.
    assert!(
        EndpointAuthBinding::webrtc_certificate_fingerprints(
            &attempt.observed_local,
            &attempt.observed_remote,
        )
        .is_some(),
        "non-vacuity: with the local component present the same constructor yields a binding"
    );

    // The same rule, one boundary down, where a typed cause exists: an absent
    // required field is the typed refusal, never a defaulted or empty value.
    // `err()` rather than `expect_err`: the success type is deliberately not
    // `Debug`, because a context that could be printed could be copied into a
    // report and then re-supplied.
    assert_eq!(
        EndpointAuthContext::new(
            &attempt.state_a.network_id,
            "",
            crate::signing::pubkey_part(attempt.state_b.identity.public_id()),
            attempt.observed_binding(),
        )
        .err(),
        Some(EndpointAuthSetupError::MissingIdentityField),
        "the missing local side fails with the typed missing-field cause"
    );
    attempt.close().await;
}

/// Missing **remote** fingerprint — the exact twin of the control above, with
/// the other side of the pair removed, so neither control can pass on a
/// condition belonging to its sibling.
#[tokio::test]
#[ignore = "opens a native WebRTC link; run in the isolated native endpoint-auth control"]
async fn v4_arc04d_missing_remote_fingerprint_is_fail_closed_on_a_live_link() {
    let attempt = live_attempt("arc04d-missing-remote-a", "arc04d-missing-remote-b").await;
    attempt.assert_live_supplier_states_both_components().await;

    assert!(
        EndpointAuthBinding::webrtc_certificate_fingerprints(&attempt.observed_local, "").is_none(),
        "a missing remote fingerprint must yield no binding at all"
    );
    assert!(
        EndpointAuthBinding::webrtc_certificate_fingerprints(
            &attempt.observed_local,
            &attempt.observed_remote,
        )
        .is_some(),
        "non-vacuity: with the remote component present the same constructor yields a binding"
    );

    assert_eq!(
        EndpointAuthContext::new(
            &attempt.state_a.network_id,
            attempt.state_a.identity.public_id(),
            "",
            attempt.observed_binding(),
        )
        .err(),
        Some(EndpointAuthSetupError::MissingIdentityField),
        "the missing remote side fails with the typed missing-field cause"
    );
    attempt.close().await;
}

/// A peer that does not advertise the closed endpoint-auth profile is refused
/// before any proof work, on the live handler.
///
/// The unit control in `engine::handshake` proves `negotiate_profile` itself is
/// exact. This proves the production `on_hello` path enforces it over a real
/// DTLS link: the Hello is otherwise entirely well formed — right device id,
/// right canonical contribution — and differs only in the absent feature id.
#[tokio::test]
#[ignore = "opens a native WebRTC link; run in the isolated native endpoint-auth control"]
async fn v4_arc04d_unadvertised_profile_is_refused_by_the_live_handler() {
    let attempt = live_attempt("arc04d-unadvertised-a", "arc04d-unadvertised-b").await;
    // Non-vacuity: this build requires exactly the id it advertises, so the
    // refusal below is the peer's omission and not an id nobody sends.
    assert!(
        crate::protocol::features::ADVERTISED_FEATURES
            .contains(&crate::protocol::features::Feature::ENDPOINT_AUTH_V1),
        "this build advertises the profile it requires"
    );
    assert_eq!(
        super::negotiate_profile(&[]),
        Err(EndpointAuthSetupError::IncompatibleProfile),
        "an empty advertisement is the typed incompatible-profile refusal"
    );

    let hello = crate::protocol::handshake::HelloMessage {
        protocol: crate::PROTOCOL_VERSION,
        device_id: attempt.state_b.identity.public_id().to_string(),
        label: "unadvertised".to_string(),
        // The exact canonical value this attempt already bound, so the refusal
        // cannot be attributed to a malformed or conflicting contribution.
        nonce: attempt.peer_contribution.as_str().to_owned(),
        verification_code: "zzz999".to_string(),
        // An unrelated string is not a compatibility fallback for the one
        // required profile.
        features: vec!["unrelated_profile".to_string()],
    };

    let device_id = attempt.state_b.identity.public_id().to_string();
    crate::engine::handshake::on_hello(&attempt.state_a, &attempt.owner, hello).await;

    assert!(
        !crate::engine::legacy_test_has_authenticated_channel(&attempt.state_a, &attempt.owner),
        "an unadvertised profile must not authenticate this channel"
    );
    // The load-bearing assertion. Absence of a capability alone would pass even
    // with the gate deleted, because this Hello carries the already-bound
    // contribution and would simply be answered from the cached proof — a Hello
    // never installs a capability. What only the gate produces is the drop: the
    // entry is torn down, so the refusal is fail-closed rather than merely
    // not-yet-authenticated.
    assert!(
        crate::engine::legacy_test_owner(&attempt.state_a, &device_id).is_none(),
        "the peer entry must be dropped, not left alive and unauthenticated"
    );
    attempt.close().await;
}
