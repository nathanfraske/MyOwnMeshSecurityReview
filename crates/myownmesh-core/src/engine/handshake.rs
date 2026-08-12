//! Hello → auth_response state machine.
//!
//! This file owns wire translation and peer lifecycle. It owns no
//! cryptographic state: the context, both contributions, the transcript
//! framing, the signing key, the one cached local proof, and the terminal
//! state all belong to the exact current `EndpointAuthTask`. Nothing here
//! draws a contribution, assembles a transcript, selects profile semantics,
//! or signs.
//!
//! On data channel open:
//!   - Reads the task's own single contribution and a verification code.
//!   - Sends `hello { device_id, label, nonce, verification_code,
//!     features }`. No application capability metadata: the Hello is
//!     admitted before a session exists, and what this node offers is
//!     sent after promotion over `CapabilitiesUpdate`.
//!   - Watchdog scheduled at `HANDSHAKE_TIMEOUT_MS`; up to three
//!     hello retries on the [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`].
//!
//! On inbound hello:
//!   - Hand the typed peer contribution to the exact current task first,
//!     before recording anything from the frame, and send back the proof
//!     it returns.
//!   - The task classifies the Hello: a first binding, an exact
//!     retransmission answered from the cached proof with no draw and no
//!     second signature, or a conflicting value, which is the typed
//!     terminal `ConflictingPeerContribution` for that exact task — its
//!     own cause, never the currentness one.
//!   - Only a first binding records the peer's label, verification code
//!     and features, under the exact-current owner fence. A
//!     retransmission is answered without adopting any of them.
//!
//! On inbound auth_response:
//!   - Hand the wire signature to the exact current task, which verifies
//!     it against the transcript it already built. A one-directional
//!     proof is not accepted as mutual.
//!   - On success: install the `AuthenticatedChannelCapability` on the
//!     peer *before* any legacy admission state, emit `PeerAuthenticated`,
//!     decide approval (roster auto-approve or wait for user), send
//!     `approve` when cleared.
//!   - Duplicates are idempotent for a channel this exact current task
//!     already promoted; anything else fails closed.
//!
//! The legacy `SIGN_DOMAIN_TAG` payload is no longer produced or accepted
//! on this path — only the frame envelope is retained, so an old peer
//! fails to verify rather than selecting a weaker format. The fingerprint
//! pair is not a session-unique exporter; see `endpoint_auth/BOUNDARY.md`.
//!
//! On inbound approve:
//!   - If we've also sent ours, transition to `Active` and emit
//!     `PeerApproved`.

use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, warn};

use crate::events::{DropReason, MeshEvent, PeerEvent};
use crate::protocol::{
    features::ADVERTISED_FEATURES,
    handshake::{ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage},
    MeshMessage,
};
use crate::signing;
use crate::verification;
use crate::PROTOCOL_VERSION;

use super::connection::PeerStatus;
use super::ladder::ConnectionTier;
use super::peer_registry::PeerOwnerToken;
use super::scheduler::{HANDSHAKE_HELLO_RETRY_SCHEDULE_MS, HANDSHAKE_TIMEOUT_MS};
use super::state::NetworkState;
use super::{phase, send_to_peer_owner};

/// The Hello this node sends, built in exactly one place.
///
/// No capability advertisement travels here. The local advert is sent after
/// promotion, over `CapabilitiesUpdate`, so this frame cannot disclose what this
/// node offers to an endpoint that has not yet authenticated.
///
/// That absence is why this is a named builder rather than a struct literal
/// inline in [`initiate`]. A control asserting the absence against a Hello it
/// constructed itself proves only that the control declined to add one — it
/// would still pass if this builder started reading the local advertisement, or
/// if the field came back as an `Option` that a fresh value leaves `None`.
/// Asserting against *this* function is what makes the claim about production.
///
/// Everything it reads is a pre-session fact: identity, the profile list this
/// build advertises, and the two per-attempt values the caller draws.
pub(super) fn local_hello(
    state: &Arc<NetworkState>,
    contribution: String,
    verification_code: String,
) -> HelloMessage {
    HelloMessage {
        protocol: PROTOCOL_VERSION,
        device_id: state.identity.public_id().to_string(),
        label: state.identity.label().to_string(),
        nonce: contribution,
        verification_code,
        features: ADVERTISED_FEATURES.iter().map(|s| s.to_string()).collect(),
    }
}

/// Kick off the handshake — called once the data channel opens.
/// Sends the first hello and schedules the timeout watchdog.
pub(super) async fn initiate(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    auth_task: Arc<crate::endpoint_auth::EndpointAuthTask>,
) {
    if state
        .peers
        .with_current(owner, |peer| peer.endpoint_auth_is_current(&auth_task))
        != Some(true)
    {
        return;
    }
    let device_id = owner.device_id();
    // The contribution on the wire is the task's own single draw, read out
    // rather than generated here. The task signs and verifies against the value
    // it drew, so a second draw made at this boundary would put a contribution
    // on the wire that this endpoint's own transcript does not contain.
    let contribution = auth_task.local_contribution();
    let code = verification::generate_code();
    let hello = local_hello(state, contribution, code.clone());
    // `with_current` rather than `get_if_current`, for the same reason as the
    // first-Hello metadata write below: this is a synchronous multi-field write
    // that must linearize against registry replacement, not merely observe that
    // the owner was current a moment ago. There is no await inside, so
    // replacement orders strictly before or after the whole block and a peer
    // replaced after the lookup cannot be started into Handshaking.
    state.peers.with_current(owner, |peer| {
        let mut data = peer.state.write();
        data.status = PeerStatus::Handshaking;
        data.verification_code_sent = Some(code.clone());
        data.handshake_started_at = Some(Instant::now());
        data.hello_attempt = 1;
        data.diag.hellos_sent += 1;
    });
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "sending hello to {} (code: {code})",
            super::short_peer(device_id)
        ),
        serde_json::json!({ "peer": device_id, "code": code }),
    );
    let hello_msg = MeshMessage::Hello(hello);
    if let Err(e) = send_to_peer_owner(state, owner, &hello_msg).await {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!("send hello to {} failed: {e}", super::short_peer(device_id)),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
        warn!(peer = %device_id, "send hello failed: {e}");
    }
    schedule_hello_retries(state.clone(), owner.clone(), hello_msg);
    schedule_watchdog(state.clone(), owner.clone());
}

/// Re-send the same hello at each tick of
/// [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`] until the peer authenticates
/// or the watchdog tears down. Replaying the hello is safe because the
/// contribution it carries is the task's one immutable draw: the
/// receiver's task recognises the exact duplicate and answers from its
/// cached proof, without a new draw, a rebuilt transcript, or a second
/// signature. Idempotence is a property of the task, not of a slot
/// this path overwrites.
fn schedule_hello_retries(state: Arc<NetworkState>, owner: PeerOwnerToken, hello: MeshMessage) {
    tokio::spawn(async move {
        let device_id = owner.device_id().to_string();
        for &delay_ms in HANDSHAKE_HELLO_RETRY_SCHEDULE_MS {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let still_handshaking = {
                let Some(peer) = state.peers.get_if_current(&owner) else {
                    return;
                };
                let data = peer.state.read();
                matches!(data.status, PeerStatus::Handshaking) && !data.authenticated
            };
            if !still_handshaking {
                return;
            }
            if let Err(e) = send_to_peer_owner(&state, &owner, &hello).await {
                debug!(peer = %device_id, "hello retry send failed: {e}");
            }
            if let Some(peer) = state.peers.get_if_current(&owner) {
                let mut data = peer.state.write();
                data.hello_attempt = data.hello_attempt.saturating_add(1);
                data.diag.hellos_sent = data.diag.hellos_sent.saturating_add(1);
            }
        }
    });
}

fn schedule_watchdog(state: Arc<NetworkState>, owner: PeerOwnerToken) {
    tokio::spawn(async move {
        let device_id = owner.device_id().to_string();
        tokio::time::sleep(std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS)).await;
        let should_fail = {
            let Some(peer) = state.peers.get_if_current(&owner) else {
                return;
            };
            let data = peer.state.read();
            !data.authenticated
                && matches!(data.status, PeerStatus::Handshaking)
                && data
                    .handshake_started_at
                    .map(|t| t.elapsed().as_millis() as u64 >= HANDSHAKE_TIMEOUT_MS)
                    .unwrap_or(false)
        };
        if should_fail {
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "handshake",
                format!("handshake watchdog fired for {device_id} — tearing down"),
                serde_json::json!({ "peer": device_id }),
            );
            super::drop_peer_if_current(&state, &owner, DropReason::HeartbeatTimeout).await;
        }
    });
}

pub async fn on_hello(state: &Arc<NetworkState>, owner: &PeerOwnerToken, hello: HelloMessage) {
    on_hello_with_retention(state, owner, hello, None).await
}

pub(super) async fn on_hello_with_retention(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    hello: HelloMessage,
    retention: Option<crate::resource::ResourceLease>,
) {
    let device_id = owner.device_id();
    // Sanity-check: the device id the peer claimed in the hello
    // must match the connection id we're using to route this
    // frame. If a peer claims to be someone else, refuse — the
    // signature check would catch this anyway, but failing early
    // surfaces a clearer diagnostic.
    if signing::pubkey_part(&hello.device_id) != signing::pubkey_part(device_id) {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "hello from {} claimed a different id ({}) — dropping",
                super::short_peer(device_id),
                super::short_peer(&hello.device_id)
            ),
            serde_json::json!({
                "connection_peer": device_id,
                "claimed_peer": hello.device_id,
            }),
        );
        warn!(
            peer = %device_id,
            claimed = %hello.device_id,
            "hello claimed a different device id than the connection — dropping"
        );
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    if !crate::protocol::handshake::verification_code_has_protocol_shape(&hello.verification_code) {
        warn!(peer = %device_id, "hello carried a malformed verification code — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // Profile first, before any proof work. A peer that does not advertise the
    // closed endpoint-auth profile has no agreed transcript, so nothing it
    // sends can be verified and nothing we send it can be verified either.
    // Refusing here means no contribution is bound, no transcript is built and
    // no signature is computed for an unauthenticatable peer. There is no
    // fallback: an older peer fails closed rather than being offered anything
    // weaker, which is the whole point of advertising the profile at all.
    if let Err(error) = crate::endpoint_auth::negotiate_profile(&hello.features) {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "hello from {} does not advertise the endpoint-auth profile — dropping",
                super::short_peer(device_id)
            ),
            serde_json::json!({
                "peer": device_id,
                "error": format!("{error:?}"),
                "required": crate::protocol::features::Feature::ENDPOINT_AUTH_V1,
            }),
        );
        warn!(peer = %device_id, "endpoint-auth profile not advertised: {error:?} — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // The peer's contribution must arrive in its exact canonical encoding. A
    // short or non-canonical value cannot carry a full-width draw, and since
    // freshness — not the channel binding — is what separates two channels
    // between the same pair, accepting one would silently weaken the property
    // rather than fail visibly.
    let Ok(peer_contribution) = crate::endpoint_auth::PeerContribution::from_wire(&hello.nonce)
    else {
        warn!(peer = %device_id, "hello carried a malformed endpoint-auth contribution — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };

    // Hand the typed contribution to the exact current task *before* recording
    // anything from this frame. The channel binding, the transcript, the role
    // ordering, the profile, and the signature all belong to the task — this
    // path translates wire values and nothing else. The legacy
    // `SIGN_DOMAIN_TAG` payload is deliberately never sent: domain separation
    // means a peer that still speaks the old format simply fails to verify,
    // rather than being offered a weaker format it could select.
    let Some(task) = state
        .peers
        .get_if_current(owner)
        .and_then(|p| p.endpoint_auth_task())
    else {
        warn!(peer = %device_id, "no endpoint-auth task at hello — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    // Whether this Hello is the first one or a retransmission is the task's
    // answer, decided against the contribution it actually bound — never
    // re-derived here from engine state. A conflicting value has already retired
    // this exact task inside `accept_peer_hello` and is terminal, carrying
    // `ConflictingPeerContribution` rather than a currentness cause, so the
    // diagnostic below distinguishes a peer sending a second, different
    // contribution from this endpoint tearing the channel down.
    let accepted = match task.accept_peer_hello(peer_contribution) {
        Ok(accepted) => accepted,
        Err(error) => {
            // Structured, like its sibling profile refusal above: the typed
            // cause is the whole diagnostic value here. Without it the drop
            // reads identically for a conflict, a stale contribution and an
            // ordinary teardown, and the one that indicates a live peer doing
            // something it cannot be doing is the one that gets lost.
            state.log_diag_with(
                crate::events::DiagLevel::Error,
                "handshake",
                format!(
                    "endpoint-auth task refused the contribution from {} — dropping",
                    super::short_peer(device_id)
                ),
                serde_json::json!({
                    "peer": device_id,
                    "error": format!("{error:?}"),
                }),
            );
            warn!(peer = %device_id, "endpoint-auth task refused the peer contribution: {error:?}");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
    };
    let signature = accepted.proof().as_str().to_owned();

    // Peer-supplied metadata belongs to the Hello that established this
    // attempt. A retransmission carries the same contribution but is otherwise
    // attacker-controlled input, so adopting its label, code, or features would
    // let a late frame rewrite the identity of an attempt that is already bound
    // — or already promoted — while the proof it gets back is the cached one.
    // Only the first binding records; the classification is matched, never
    // inferred from peer state.
    //
    // What is recorded here is deliberately the smallest set: two cosmetic
    // strings that authorize nothing and gate nothing, and the feature list,
    // which only ever refuses. Application capability metadata is not among
    // them and cannot be — the frame no longer carries any.
    match accepted {
        crate::endpoint_auth::AcceptedPeerHello::FirstBinding(_) => {
            // `with_current` rather than `get_if_current`, because this write
            // must linearize against registry replacement rather than merely
            // observe that the owner was current a moment ago. There is no
            // await inside, so replacement orders strictly before or after the
            // whole block, and a peer replaced after the task call cannot
            // receive the old frame's metadata.
            state.peers.with_current(owner, |peer| {
                let mut data = peer.state.write();
                data.verification_code_received = Some(hello.verification_code.clone());
                data.label = hello.label.clone();
                // The advertised feature set is the sender-side gate for every
                // optional frame kind (acked channel delivery, governance wire,
                // …) — record it, or `peer_supports` has nothing to consult.
                data.features = hello.features.clone();
                data.hello_retention = retention;
            });
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "handshake",
                format!(
                    "hello received from {} (label: {:?}, code: {})",
                    super::short_peer(device_id),
                    hello.label,
                    hello.verification_code,
                ),
                serde_json::json!({
                    "peer": device_id,
                    "label": hello.label,
                    "code": hello.verification_code,
                }),
            );
        }
        crate::endpoint_auth::AcceptedPeerHello::ExactDuplicate(_) => {
            debug!(
                peer = %device_id,
                "retransmitted hello: replying from the cached proof without adopting its metadata"
            );
        }
    }
    if let Err(e) = send_to_peer_owner(
        state,
        owner,
        &MeshMessage::AuthResponse(AuthResponseMessage { signature }),
    )
    .await
    {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "send auth_response to {} failed: {e}",
                super::short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
        warn!(peer = %device_id, "send auth_response failed: {e}");
        return;
    }
    debug!(peer = %device_id, "responded to hello");
}

pub async fn on_auth_response(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    resp: AuthResponseMessage,
) {
    let device_id = owner.device_id();
    // Verify both halves of the Arc 04 endpoint-auth transcript. The peer's
    // signature covers `ENDPOINT_AUTH_DOMAIN_TAG` followed by the
    // length-prefixed mesh context, profile, signer role, both Device IDs,
    // both contributions and both certificate fingerprints, ordered by role
    // rather than by which side is local — so both endpoints derive identical
    // bytes. Domain separation from the legacy `SIGN_DOMAIN_TAG` payload means
    // an Arc 03 signature simply fails here; it is not an accepted fallback.
    // Neither contribution is held in per-peer state. Both belong to the task,
    // which keeps its own draw and its bound peer value for its whole life,
    // including after promotion — so a retransmitted or delayed Hello still
    // finds the attempt it belongs to instead of tearing down a peer whose
    // proof is valid. Single promotion is enforced by the move-only handoff.
    // Idempotence for sequential retransmission, checked before any transport
    // or signing work. Each connector has one event-pump task that awaits an
    // event before taking the next, so a duplicate AuthResponse on this channel
    // runs strictly after the first completed. `has_authenticated_channel` is
    // the right predicate on its own: it is true only for the entry's exact
    // current, unretired connector, because retirement and replacement drop the
    // capability. Without this the duplicate would re-enter promotion, find the
    // handoff already consumed, and tear down a peer whose proof was valid.
    if state
        .peers
        .get_if_current(owner)
        .is_some_and(|peer| peer.has_authenticated_channel())
    {
        debug!(peer = %device_id, "ignoring duplicate auth_response for an already authenticated channel");
        return;
    }
    let (peer_label, verification_code) = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let data = peer.state.read();
        (
            data.label.clone(),
            data.verification_code_received.clone().unwrap_or_default(),
        )
    };
    // The endpoint-auth task for the *exact current* connector. A task from a
    // replaced channel cannot promote: because the certificate-fingerprint
    // binding is not session-unique, this ownership check — not the binding —
    // is what distinguishes two channels between the same device pair.
    let Some(auth_task) = state
        .peers
        .get_if_current(owner)
        .and_then(|p| p.endpoint_auth_task())
    else {
        warn!(peer = %device_id, "no current endpoint-auth task at auth_response — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };

    // The task must be the one built for *this* mesh and *this* peer. Ownership
    // of the current connector is not the same fact: a task is created with an
    // immutable context, and this is where the engine states that the entry it
    // is about to promote is the entry that context names. The remote id is
    // derived exactly as task creation derives it, so the comparison is against
    // the same canonical form the context stored rather than a display spelling.
    // Fail closed with no fallback: a task whose context does not match cannot
    // be corrected here, only refused.
    if !auth_task.context_matches(&state.network_id, crate::signing::pubkey_part(device_id)) {
        warn!(peer = %device_id, "endpoint-auth task authenticates a different mesh or peer — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // The task owns both halves. It already produced and cached our own proof
    // when it bound the peer's contribution, and it holds the context, the
    // binding, and the transcript, so this path hands it the wire signature and
    // nothing else. There is no fingerprint fetch, no transcript assembly, and
    // no signing here.
    let capability = match auth_task.accept_peer_proof(&resp.signature) {
        // Unboxed here and nowhere else. The box is a size decision on the
        // outcome enum, not a change of custody: what install receives below is
        // the exact capability the promotion built.
        Ok(crate::endpoint_auth::PeerProofAcceptance::Promoted(capability)) => *capability,
        // A retransmission arriving at a task that has already promoted, stated
        // by the task rather than inferred from a terminal cause it never took.
        //
        // What it states is exactly one thing: this *task* moved its channel out
        // already. It is a lifecycle fact and nothing more. It does **not** say
        // the replayed signature verified — once the handoff is gone there is
        // nothing left to verify it against, and the frame's bytes are never
        // examined — and it does **not** say the capability that promotion
        // issued was ever installed.
        //
        // So installation is still corroborated here, and this arm fails closed
        // without it. The caller that wins promotion can move the capability and
        // then fail to install it; treating every `AlreadyPromoted` as benign
        // would leave that peer alive and unauthenticated, which is precisely
        // what the old `Err(ChannelNotCurrent)` shape avoided by falling through
        // to the drop below. Only the corroborated case is benign.
        //
        // The ordinary sequential retransmission never reaches this arm: it is
        // absorbed by the `has_authenticated_channel` guard above, before any
        // task work at all. What the typed outcome buys is the concurrent case —
        // a caller that loses a race to promote is *told* it lost, instead of
        // reading a terminal currentness cause it must then disambiguate.
        //
        // This arm is also why the conflict cause is separate. A task that a
        // conflicting contribution retired is terminal and answers
        // `Err(ConflictingPeerContribution)`, so it cannot reach this arm at all
        // and falls to the refusal below — a peer that sent a second, different
        // contribution can never present the result here as a retransmission of
        // its first.
        Ok(crate::endpoint_auth::PeerProofAcceptance::AlreadyPromoted) => {
            if state.peers.get_if_current(owner).is_some_and(|peer| {
                peer.has_authenticated_channel() && peer.endpoint_auth_is_current(&auth_task)
            }) {
                debug!(peer = %device_id, "duplicate auth_response after promotion completed");
                return;
            }
            warn!(
                peer = %device_id,
                "endpoint-auth task already promoted with no authenticated channel installed for it — dropping"
            );
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
        // Every remaining outcome is terminal for the attempt: the task recorded
        // this cause and retired itself, so there is nothing left to fall back
        // to and the peer goes with it.
        Err(error) => {
            warn!(peer = %device_id, "endpoint authentication refused: {error:?}");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
    };

    let Some(peer) = state.peers.get_if_current(owner) else {
        return;
    };
    // Install the capability before any legacy admission state is set, so no
    // window exists in which `authenticated == true` without a live
    // authenticated channel behind it.
    if !peer.install_authenticated_channel(&auth_task, capability) {
        // Refused because one is already installed for this exact current task
        // is a duplicate, not a failure; the capability just dropped, which
        // runs its handoff retention. Any other refusal fails closed.
        if peer.has_authenticated_channel() && peer.endpoint_auth_is_current(&auth_task) {
            debug!(peer = %device_id, "authenticated channel already installed for this connector");
            return;
        }
        warn!(peer = %device_id, "authenticated channel is not installable on the current connector — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // Authentication succeeded.
    //
    // Before ANY admission path runs, the signed-eviction gate: a device
    // this network's governance has evicted is denied here — with the
    // signed log attached as proof so it can verify its own removal and
    // stand down. Without this gate an evicted device that missed the
    // news redialed forever and the flow below RESURRECTED it: pending-
    // approval nudges at best, and on an auto-approve network (every
    // fleet mesh) auto-approve → mutual ACTIVE → `approve_roster` put it
    // straight back into the roster and gossiped it fleet-wide.
    if super::governance::deny_if_evicted(state, owner).await {
        return;
    }
    // Both network-global reads are hoisted above the peer write. Taking the
    // roster and the config while holding a peer's state guard nests a
    // `NetworkState` lock under a per-peer lock, which is the opposite of the
    // order everything else uses, and it makes the policy decision and the
    // policy write two separate atoms for no benefit — neither read depends on
    // this peer's state.
    let rostered = state.is_rostered(device_id);
    let policy_admits = super::governance::current_policy_admits(
        &state.governance_state.read(),
        state.identity.public_id(),
        device_id,
    );
    let auto_approve = policy_admits && (state.config.read().auto_approve || rostered);
    // The write itself linearizes against registry replacement rather than
    // merely observing that the owner was current a moment ago. It is
    // synchronous, has no await inside, and carries only owned values out.
    if state
        .peers
        .with_current(owner, |peer| {
            let mut data = peer.state.write();
            data.authenticated = true;
            data.status = PeerStatus::PendingApproval;
        })
        .is_none()
    {
        return;
    }

    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "auth ok with {} ({})",
            super::short_peer(device_id),
            if auto_approve {
                if rostered {
                    "rostered → auto-approve"
                } else {
                    "auto-approve enabled"
                }
            } else {
                "awaiting user approval"
            }
        ),
        serde_json::json!({
            "peer": device_id,
            "rostered": rostered,
            "auto_approve": auto_approve,
        }),
    );

    state.emit(MeshEvent::Peer(PeerEvent::Authenticated {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
        label: peer_label.clone(),
        verification_code,
        rostered,
    }));

    if auto_approve {
        send_local_approve_owner(state, owner).await;
    }
}

pub async fn on_approve(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    let recorded = state.peers.with_current(owner, |peer| {
        peer.state.write().remote_approve_seen = true;
    });
    if recorded.is_none() {
        return;
    }
    maybe_activate(state, owner).await;
}

/// Complete the Active edge from facts already established on the exact peer.
/// Only [`on_approve`] may latch remote approval. Re-evaluating after a local
/// send must never manufacture peer consent.
async fn maybe_activate(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    maybe_activate_after_check(state, owner, || {}).await;
}

/// Recheck and commit activation under the exact installation fence.
///
/// `before_commit` is normally empty. The deterministic replacement test uses
/// it to replace the peer after the initial eligibility read but before the
/// roster persistence linearization point.
async fn maybe_activate_after_check(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    before_commit: impl FnOnce(),
) {
    let device_id = owner.device_id();
    let eligible = state.peers.get_if_current(owner).is_some_and(|peer| {
        let data = peer.state.read();
        !matches!(data.status, PeerStatus::Active)
            && data.authenticated
            && data.local_approve_sent
            && data.remote_approve_seen
    });
    if !eligible {
        return;
    }

    before_commit();

    let Some(Some(roster_result)) = state.peers.with_current(owner, |peer| {
        let mut data = peer.state.write();
        // Guard the transition edge: a peer that re-sends Approve after
        // we're already ACTIVE shouldn't re-fire the on-active side
        // effects (roster persist, gossip, Approved event).
        let was_active = matches!(data.status, PeerStatus::Active);
        // A peer reaches ACTIVE only once it has proven its ed25519 identity.
        // `remote_approve_seen` can be latched by an `Approve` that arrives
        // before authentication (protocol frames pass the admission gate), and
        // a locally accepted Approve send can be recorded before authentication.
        // Without this `authenticated` conjunct an
        // unauthenticated peer could be promoted to ACTIVE and gain the run of
        // every application and control plane. The early latch is harmless: the
        // transition simply completes the moment authentication lands.
        let active = data.authenticated
            && data.local_approve_sent
            && data.remote_approve_seen
            && super::governance::current_policy_admits(
                &state.governance_state.read(),
                state.identity.public_id(),
                device_id,
            );
        if !active || was_active {
            return None;
        }
        data.status = PeerStatus::Active;
        data.tier = ConnectionTier::Steady;
        data.ice_failed_count = 0;
        data.no_turn_diag_emitted = false;
        let label = data.label.clone();
        drop(data);

        // This file mutation has no await point and runs while registry
        // replacement is excluded. Replacement therefore linearizes before
        // this complete commit or after it.
        let roster_result = state.approve_roster_now(device_id, &label);
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "peer",
            format!("{} ACTIVE", super::short_peer(device_id)),
            serde_json::json!({ "peer": device_id }),
        );
        state.emit(MeshEvent::Peer(PeerEvent::Approved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            label: label.clone(),
        }));
        state.resolve_connect_waiters(device_id, None);
        state.clear_reconnect_intent(device_id);
        Some(roster_result)
    }) else {
        return;
    };

    // Nothing is installed here, and that absence is the design. Real-time work
    // is authorized by the promoted session, which the registry fence mints on
    // demand at the moment of use — so reaching Active is already everything
    // that has to be true, and a separate post-Active step could only be a
    // second copy of the same fact, taken at a different instant, able to drift.

    if let Err(e) = roster_result {
        state.log_diag(
            crate::events::DiagLevel::Warn,
            "roster",
            format!(
                "persist {} after mutual approve failed: {e}",
                super::short_peer(device_id)
            ),
        );
    }

    phase::recompute(state);
    super::reliable::flush_owner(state, owner).await;
    if state.peers.get_if_current(owner).is_none() {
        return;
    }
    // The ordinary first establishment: a peer that reaches Active with a
    // session it can promote is told what this node offers, without waiting for
    // the application to advertise again.
    //
    // This installs nothing and is not the second copy of a fact the note above
    // warns against — it is a send, and it asks the same lender every other
    // application send asks. Nor is it the only place the debt can be paid: if
    // promotion resource-refuses here, nothing is minted, nothing is consumed,
    // and the first later successful promotion still owes it.
    super::replay_local_capabilities_to_owner(state, owner).await;
    if state.peers.get_if_current(owner).is_none() {
        return;
    }
    super::ladder::reevaluate_topology(state).await;
    if state.peers.get_if_current(owner).is_none() {
        return;
    }

    if super::governance::broadcast_roster_summary_for_owner(state, owner).await {
        let _ = super::governance::broadcast_state_for_owner(state, owner).await;
    }
}

pub async fn on_deny(state: &Arc<NetworkState>, owner: &PeerOwnerToken, deny: DenyMessage) {
    let device_id = owner.device_id();
    state.log_diag_with(
        crate::events::DiagLevel::Warn,
        "auth",
        format!("peer denied us: {device_id} (reason: {:?})", deny.reason),
        serde_json::json!({ "peer": device_id, "reason": format!("{:?}", deny.reason) }),
    );
    // An eviction denial carries the network's signed logs as proof.
    // Nothing about the DENIER is trusted: the logs go through the same
    // strict-extension verification every adoption takes, so a forged or
    // foreign log changes nothing — but a genuine one finally teaches a
    // device that was evicted while offline that it is out, flipping it
    // to stood-down (and letting the embedding app clear its fleet
    // state) instead of redialing into denials forever.
    if !deny.transitions.is_empty() || !deny.member_log.is_empty() {
        super::governance::adopt_deny_proof(state, device_id, &deny.transitions, &deny.member_log)
            .await;
    }
    super::drop_peer_if_current(state, owner, DropReason::Denied).await;
}

async fn send_local_approve_owner(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    let device_id = owner.device_id();
    let Some(already) = state
        .peers
        .with_current(owner, |peer| peer.state.read().local_approve_sent)
    else {
        return;
    };
    if already {
        // Authentication or remote approval may have completed since the
        // successful local send. Fold the established facts again.
        maybe_activate(state, owner).await;
        return;
    }
    if let Err(e) = send_to_peer_owner(state, owner, &MeshMessage::Approve(ApproveMessage {})).await
    {
        warn!(peer = %device_id, "send approve failed: {e}");
        return;
    }
    let recorded = state.peers.with_current(owner, |peer| {
        peer.state.write().local_approve_sent = true;
    });
    if recorded.is_none() {
        return;
    }
    // This flag means the exact current transport accepted the bytes for
    // transmission. It does not prove remote receipt. Concurrent duplicate
    // Approves are harmless, while a failed send must never erase another
    // successful one.
    // A remote Approve may have arrived before authentication completed.
    // Re-evaluate after local send acceptance without manufacturing the
    // remote-approval fact.
    maybe_activate(state, owner).await;
}

/// Send the local approve frame for a peer. Called from the
/// auto-approve path and from the user-facing
/// [`crate::MeshHandle::approve_peer`] action.
pub async fn send_local_approve(state: &Arc<NetworkState>, device_id: &str) {
    if let Some(owner) = state.peers.owner(device_id) {
        send_local_approve_owner(state, &owner).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_response(signature: &str) -> AuthResponseMessage {
        AuthResponseMessage {
            signature: signature.to_string(),
        }
    }

    /// A registry peer whose endpoint-auth task has promoted and whose
    /// capability was **not** installed.
    ///
    /// Built against `state.network_id` and the peer's own Device ID, so the
    /// handler's context check passes and the control reaches the outcome under
    /// test rather than stopping at an earlier refusal. The capability the
    /// promotion issues is deliberately dropped: that is the whole scenario —
    /// a caller that won promotion, moved the channel out, and then failed to
    /// install what it was handed.
    fn promoted_peer_without_an_installed_channel(
        state: &Arc<NetworkState>,
    ) -> (
        PeerOwnerToken,
        Arc<crate::endpoint_auth::EndpointAuthTask>,
        String,
    ) {
        fn device_id(key: &ed25519_dalek::SigningKey) -> String {
            data_encoding::BASE32_NOPAD
                .encode(key.verifying_key().as_bytes())
                .to_lowercase()
        }

        let local_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let peer_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let remote_id = device_id(&peer_key);
        let context = crate::endpoint_auth::EndpointAuthContext::new(
            &state.network_id,
            &device_id(&local_key),
            &remote_id,
            crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
                "arc04g-local-fp",
                "arc04g-remote-fp",
            )
            .expect("both fixture components present"),
        )
        .expect("non-empty fixture identifiers");
        let task = Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(
            context,
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
            crate::endpoint_auth::LocalIdentitySigner::for_identity(Arc::new(
                crate::identity::Identity::from_signing_key(local_key, "arc04g-fixture"),
            )),
        ));

        // Drive the exchange to `Promoted`, then drop the capability on the
        // floor. Nothing installs it.
        let peer_contribution = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical");
        task.accept_peer_hello(peer_contribution.clone())
            .expect("the first contribution binds");
        let promoted = task
            .accept_peer_proof(&crate::endpoint_auth::peer_proof_for_test(
                &task,
                &peer_contribution,
                &peer_key,
            ))
            .expect("the fixture proof promotes");
        assert!(
            matches!(
                promoted,
                crate::endpoint_auth::PeerProofAcceptance::Promoted(_)
            ),
            "non-vacuity: the task really did promote"
        );
        drop(promoted);

        super::super::install_peer(
            &state.peers,
            Arc::new(
                crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
                    remote_id.clone(),
                    Arc::clone(&task),
                ),
            ),
        );
        let owner = state.peers.owner(&remote_id).expect("installed peer owner");
        (owner, task, remote_id)
    }

    #[tokio::test]
    async fn v4_arc04g_already_promoted_without_an_installed_channel_drops() {
        // The paired half of the entry guard below, and the reason the typed
        // duplicate outcome is corroborated rather than trusted on its own.
        //
        // `PeerProofAcceptance::AlreadyPromoted` states one thing: the task moved
        // its channel out. It does not state that the capability was installed,
        // and it does not state that this frame's signature verified — the state
        // is read before any verification, so the bytes below are never
        // examined. A handler that read it as "benign duplicate, do nothing"
        // would leave this peer alive and unauthenticated forever.
        let state = crate::engine::build_test_state("arc04g-promoted-not-installed");
        let (owner, task, device_id) = promoted_peer_without_an_installed_channel(&state);

        // Non-vacuity: the entry guard cannot absorb this frame, because there
        // is nothing installed for it to absorb it with, and the task is the
        // entry's current one so the handler reaches the promotion outcome.
        let peer = state.peers.get(&device_id).expect("peer is installed");
        assert!(!peer.has_authenticated_channel());
        assert!(peer.endpoint_auth_is_current(&task));

        on_auth_response(&state, &owner, auth_response("bytes-nobody-verified")).await;

        assert!(
            state.peers.get_if_current(&owner).is_none(),
            "a promoted task with no installed channel behind it must fail closed"
        );
    }

    #[tokio::test]
    async fn v4_arc04_duplicate_auth_response_after_promotion_is_idempotent() {
        // A retransmitted AuthResponse must not re-enter promotion. Before the
        // idempotence guard it would find the handoff already consumed, be
        // refused, and drop a peer whose proof was valid.
        //
        // This is the *entry* guard: an installed authenticated channel absorbs
        // the duplicate before any task work happens, which is where every
        // ordinary sequential retransmission is caught. Its paired half —
        // a task that promoted with nothing installed behind it — is
        // `v4_arc04g_already_promoted_without_an_installed_channel_drops`.
        let state = crate::engine::build_test_state("arc04-duplicate-auth-response");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        let peer = state.peers.get("peer").expect("peer is installed");
        peer.install_authenticated_channel_for_test();
        assert!(
            peer.has_authenticated_channel(),
            "non-vacuity: the channel really is authenticated before the duplicate"
        );

        on_auth_response(&state, &owner, auth_response("replayed-signature")).await;

        assert!(
            state.peers.get_if_current(&owner).is_some(),
            "a duplicate must not tear the peer down"
        );
        assert!(
            state
                .peers
                .get("peer")
                .expect("peer is installed")
                .has_authenticated_channel(),
            "and the exact capability survives untouched"
        );
    }

    // The one-sided-transcript control that stood here worked by writing a
    // contribution pair into peer state, which no longer exists: the pair
    // belongs to the Endpoint Auth Task. Its substance moved with it, to
    // `endpoint_auth::task::v4_arc04b_proof_before_any_peer_contribution_is_refused`.
    // The delayed-hello control did not move — it is restored below, against the
    // real handler, because the property it holds is an engine one: what a
    // retransmission is allowed to write.

    /// A Hello carrying an exact contribution plus every field a late frame
    /// could try to rewrite.
    fn hello_carrying(
        device_id: &str,
        contribution: &str,
        label: &str,
        code: &str,
        feature: &str,
    ) -> HelloMessage {
        HelloMessage {
            protocol: PROTOCOL_VERSION,
            device_id: device_id.to_string(),
            label: label.to_string(),
            nonce: contribution.to_string(),
            verification_code: code.to_string(),
            // Every well-formed peer advertises the closed endpoint-auth
            // profile alongside whatever else it supports; without it the
            // handshake now fails closed before any proof work. `feature` is
            // the id each control varies, so both are carried here.
            features: vec![
                crate::protocol::features::Feature::ENDPOINT_AUTH_V1.to_string(),
                feature.to_string(),
            ],
        }
    }

    /// The same fixture with the endpoint-auth profile deliberately absent.
    fn hello_without_endpoint_auth_profile(device_id: &str, contribution: &str) -> HelloMessage {
        HelloMessage {
            protocol: PROTOCOL_VERSION,
            device_id: device_id.to_string(),
            label: "unadvertised".to_string(),
            nonce: contribution.to_string(),
            verification_code: "zzz999".to_string(),
            // An older peer: it speaks other features, just not this profile.
            features: vec![crate::protocol::features::Feature::TYPED_CHANNELS.to_string()],
        }
    }

    #[test]
    fn v4_arc04c_profile_negotiation_refuses_an_unadvertised_peer() {
        use crate::protocol::features::Feature;

        // Non-vacuity: the advertised set really does resolve, so the refusal
        // below is the absence of the id and not a predicate that never says
        // yes. Both directions are asserted.
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&[
                Feature::ENDPOINT_AUTH_V1.to_string(),
                Feature::TYPED_CHANNELS.to_string(),
            ]),
            Ok(crate::endpoint_auth::EndpointAuthProfile::V1Ed25519Dtls),
            "a peer advertising the profile resolves to the one closed profile"
        );
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&[Feature::TYPED_CHANNELS.to_string()]),
            Err(crate::endpoint_auth::EndpointAuthSetupError::IncompatibleProfile),
            "a peer that speaks other features but not this profile is refused"
        );
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&[]),
            Err(crate::endpoint_auth::EndpointAuthSetupError::IncompatibleProfile),
            "an empty advertisement is refused, not defaulted"
        );
        // Exact-string matching: a near-miss must not resolve, or the id would
        // be an invitation to improvise rather than a closed selector.
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&["endpoint_auth_v2".to_string()]),
            Err(crate::endpoint_auth::EndpointAuthSetupError::IncompatibleProfile),
            "no forward-compatible guessing: an unknown id is not this profile"
        );
        assert!(
            crate::protocol::features::ADVERTISED_FEATURES.contains(&Feature::ENDPOINT_AUTH_V1),
            "this build must advertise what it requires, or two MyOwnMesh peers \
             could never authenticate each other"
        );
    }

    #[tokio::test]
    async fn v4_arc04c_hello_without_the_profile_is_refused_before_any_proof_work() {
        // The live-handler half. An unadvertised peer must be dropped before a
        // contribution is bound, so no transcript exists and no proof is
        // computed for a peer that could never verify one.
        let state = crate::engine::build_test_state("arc04c-profile-refusal");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        let contribution = crate::endpoint_auth::LocalContribution::generate();

        on_hello(
            &state,
            &owner,
            hello_without_endpoint_auth_profile(owner.device_id(), contribution.as_str()),
        )
        .await;

        assert!(
            state.peers.get_if_current(&owner).is_none(),
            "an unadvertised peer is dropped rather than authenticated"
        );
    }

    #[tokio::test]
    async fn v4_arc04h_malformed_contribution_closes_the_exact_current_peer() {
        // The production half of the setup/terminal split, on the inbound path.
        //
        // A refusal from `PeerContribution::from_wire` is an
        // `EndpointAuthSetupError`: the parser holds no task, so it terminalizes
        // nothing and its value makes no lifecycle claim. That is exactly why
        // this control exists — with the cause no longer able to imply "the
        // attempt is over", the thing that has to fail this closed is the
        // handler's own act on its own state, and it must be asserted rather
        // than inferred from the error type as it was when both senses shared
        // one enum.
        //
        // The twins differ in one field. Both Hellos are otherwise identical
        // and both advertise the closed profile, so the drop below is
        // attributable to the contribution and not to an earlier gate.
        fn fixture(
            suffix: &str,
        ) -> (
            Arc<NetworkState>,
            Arc<crate::endpoint_auth::EndpointAuthTask>,
            PeerOwnerToken,
        ) {
            let state = crate::engine::build_test_state(suffix);
            let task = Arc::new(crate::endpoint_auth::task_for_test(
                crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
            ));
            crate::engine::install_peer(
                &state.peers,
                Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                    "peer".to_string(),
                    Arc::clone(&task),
                )),
            );
            let owner = state.peers.owner("peer").expect("installed peer owner");
            (state, task, owner)
        }

        // Non-vacuity: the canonical twin. The same handler, the same fixture,
        // the same frame — with a contribution the parser accepts — keeps the
        // peer and binds the attempt.
        {
            let (state, task, owner) = fixture("arc04h-canonical-contribution");
            on_hello(
                &state,
                &owner,
                hello_carrying(
                    "peer",
                    crate::endpoint_auth::LocalContribution::generate().as_str(),
                    "label",
                    "aaa111",
                    "feature",
                ),
            )
            .await;

            assert!(
                state.peers.get_if_current(&owner).is_some(),
                "a canonical contribution keeps the exact current peer"
            );
            assert_eq!(
                task.signature_count(),
                1,
                "and binds the attempt, producing the one local proof"
            );
        }

        let (state, task, owner) = fixture("arc04h-malformed-contribution");
        // The exact value under test, refused by the exact parser the handler
        // calls, with the exact setup cause. Stated here so the drop below is
        // pinned to that refusal rather than assumed to follow from it.
        assert_eq!(
            crate::endpoint_auth::PeerContribution::from_wire("not-base32!"),
            Err(crate::endpoint_auth::EndpointAuthSetupError::ContributionMalformed),
            "non-vacuity: this value really is refused, and as an input rather \
             than as a lifecycle event"
        );

        on_hello(
            &state,
            &owner,
            hello_carrying("peer", "not-base32!", "label", "aaa111", "feature"),
        )
        .await;

        // Fail-closed, and closed on the *exact* current owner: the entry is
        // removed rather than left alive and unauthenticated. This is the
        // synchronous half of the teardown; retiring the connector behind it
        // runs on the peer's own owner path, so this control asserts the
        // registry closure it can observe rather than racing that.
        assert!(
            state.peers.get_if_current(&owner).is_none(),
            "a malformed contribution closes the exact current peer rather than \
             leaving it alive and unauthenticated"
        );
        // And the attempt was never reached: a value the parser refuses cannot
        // bind anything, so no transcript was built and no signature produced
        // for it. The one draw the task made at construction is still its only
        // draw.
        assert_eq!(task.signature_count(), 0, "a refused input signs nothing");
        assert_eq!(task.draw_count(), 1, "and causes no second draw");
    }

    #[tokio::test]
    async fn v4_arc04b_duplicate_hello_replies_without_adopting_its_metadata() {
        // Migrated delayed-Hello control, restated for task-owned contributions.
        // A retransmission carries the bound contribution, so it is answered
        // from the cached proof — but everything else in that frame is still
        // attacker-controlled input. Adopting it would let a late Hello rewrite
        // the identity of an attempt that is already bound while the proof it
        // receives is the one the first Hello earned.
        use crate::protocol::features::Feature;

        let state = crate::engine::build_test_state("arc04-duplicate-hello-metadata");
        let task = Arc::new(crate::endpoint_auth::task_for_test(
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
        ));
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                "peer".to_string(),
                Arc::clone(&task),
            )),
        );
        let owner = state.peers.owner("peer").expect("installed peer owner");

        let contribution = crate::endpoint_auth::LocalContribution::generate();
        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                contribution.as_str(),
                "settled-label",
                "aaa111",
                "settled-feature",
            ),
        )
        .await;

        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("the first hello keeps the peer");
            let data = peer.state.read();
            assert_eq!(
                data.label, "settled-label",
                "non-vacuity: the first hello really did establish this metadata"
            );
            assert_eq!(data.verification_code_received.as_deref(), Some("aaa111"));
            assert_eq!(
                data.features,
                vec![
                    Feature::ENDPOINT_AUTH_V1.to_string(),
                    "settled-feature".to_string()
                ]
            );
        }
        let draws = task.draw_count();
        let signatures = task.signature_count();

        // The same contribution — so the task classifies this a retransmission —
        // with every other field changed.
        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                contribution.as_str(),
                "rewritten-label",
                "zzz999",
                "injected-feature",
            ),
        )
        .await;

        let peer = state
            .peers
            .get_if_current(&owner)
            .expect("a retransmitted hello must not tear the peer down");
        let data = peer.state.read();
        assert_eq!(
            data.label, "settled-label",
            "the first hello's label stands"
        );
        assert_eq!(
            data.verification_code_received.as_deref(),
            Some("aaa111"),
            "and its verification code"
        );
        assert_eq!(
            data.features,
            vec![
                Feature::ENDPOINT_AUTH_V1.to_string(),
                "settled-feature".to_string()
            ],
            "and its advertised feature set, which gates every optional frame kind"
        );
        drop(data);
        // Ed25519 is deterministic, so equal proof bytes would prove nothing
        // about re-signing. The counters do.
        assert_eq!(task.draw_count(), draws, "no second draw");
        assert_eq!(
            task.signature_count(),
            signatures,
            "and no second signature"
        );
    }

    #[tokio::test]
    async fn v4_arc04b_conflicting_hello_is_terminal_and_writes_no_metadata() {
        // The other classification: a different contribution is not a repeat,
        // so it is terminal for that exact task and must leave the established
        // metadata alone on its way out.
        //
        // The cause is asserted, not merely the retirement. Retirement alone
        // would also hold if this Hello had been refused for some unrelated
        // reason, or if the conflict site went back to reporting a currentness
        // failure — and the diagnostic this path emits carries that cause, so a
        // conflict would become indistinguishable from an ordinary teardown in
        // the one record an operator actually reads.
        let state = crate::engine::build_test_state("arc04-conflicting-hello-metadata");
        let task = Arc::new(crate::endpoint_auth::task_for_test(
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
        ));
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                "peer".to_string(),
                Arc::clone(&task),
            )),
        );
        let owner = state.peers.owner("peer").expect("installed peer owner");

        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                crate::endpoint_auth::LocalContribution::generate().as_str(),
                "settled-label",
                "aaa111",
                "settled-feature",
            ),
        )
        .await;
        assert!(
            state.peers.get_if_current(&owner).is_some(),
            "non-vacuity: the first hello bound the attempt"
        );

        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                crate::endpoint_auth::LocalContribution::generate().as_str(),
                "rewritten-label",
                "zzz999",
                "injected-feature",
            ),
        )
        .await;

        assert!(task.is_retired(), "a conflicting contribution is terminal");
        assert_eq!(
            task.terminal_error(),
            Some(crate::endpoint_auth::EndpointAuthError::ConflictingPeerContribution),
            "and it is terminal for the conflict, not for a currentness failure it never had"
        );
        if let Some(peer) = state.peers.get("peer") {
            let data = peer.state.read();
            assert_eq!(data.label, "settled-label");
            assert_eq!(data.verification_code_received.as_deref(), Some("aaa111"));
        }
    }

    #[tokio::test]
    async fn v4_arc04c_auth_response_for_another_context_is_refused_before_promotion() {
        // The task-context fence at the real handler. Everything else about this
        // attempt is correct: the task binds the peer's contribution and the
        // AuthResponse carries the genuine proof over that task's own transcript,
        // signed by the exact remote key its context expects — so without the
        // context check this promotes and installs. It must be refused because
        // the task authenticates a different mesh and a different remote Device
        // than the entry it is installed on.
        let state = crate::engine::build_test_state("arc04c-auth-response-context-mismatch");
        let task = Arc::new(crate::endpoint_auth::task_for_test(
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
        ));
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                "peer".to_string(),
                Arc::clone(&task),
            )),
        );
        let owner = state.peers.owner("peer").expect("installed peer owner");
        assert!(
            !task.context_matches(&state.network_id, crate::signing::pubkey_part("peer")),
            "non-vacuity: the fixture task really does authenticate another mesh and peer"
        );

        // The peer's half, over the task's own bound attempt.
        let peer_contribution = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical");
        task.accept_peer_hello(peer_contribution.clone())
            .expect("the first canonical contribution binds this attempt");
        let proof = crate::endpoint_auth::peer_proof_for_test(
            &task,
            &peer_contribution,
            &ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]),
        );

        on_auth_response(&state, &owner, auth_response(&proof)).await;

        assert!(
            state
                .peers
                .get("peer")
                .is_none_or(|peer| !peer.has_authenticated_channel()),
            "a task built for another context must not promote this entry"
        );
    }

    #[tokio::test]
    async fn v4_arc04_auth_response_before_our_hello_is_refused() {
        // No endpoint-auth task exists for this peer, so there is no attempt to
        // complete and nothing can be promoted.
        let state = crate::engine::build_test_state("arc04-auth-response-before-hello");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");

        on_auth_response(&state, &owner, auth_response("unsolicited")).await;

        assert!(
            state
                .peers
                .get("peer")
                .is_none_or(|peer| !peer.has_authenticated_channel()),
            "an unsolicited auth_response must never promote"
        );
    }

    #[tokio::test]
    async fn v4_arc03_remote_approve_before_local_send_acceptance_converges() {
        let state = crate::engine::build_test_state("arc03-approve-remote-first");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let mut data = peer.state.write();
            data.authenticated = true;
            data.status = PeerStatus::PendingApproval;
        }

        on_approve(&state, &owner).await;
        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let data = peer.state.read();
            assert!(data.remote_approve_seen);
            assert!(!data.local_approve_sent);
            assert_eq!(data.status, PeerStatus::PendingApproval);
        }

        state
            .peers
            .get_if_current(&owner)
            .expect("exact peer remains installed")
            .state
            .write()
            .local_approve_sent = true;
        send_local_approve_owner(&state, &owner).await;

        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let data = peer.state.read();
            assert!(data.remote_approve_seen);
            assert!(data.local_approve_sent);
            assert_eq!(data.status, PeerStatus::Active);
        }
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_arc03_local_approve_without_remote_consent_stays_pending() {
        let state = crate::engine::build_test_state("arc03-approve-local-only");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let mut data = peer.state.write();
            data.authenticated = true;
            data.local_approve_sent = true;
            data.status = PeerStatus::PendingApproval;
        }

        send_local_approve_owner(&state, &owner).await;

        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let data = peer.state.read();
            assert!(!data.remote_approve_seen);
            assert_eq!(data.status, PeerStatus::PendingApproval);
        }
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_arc03_replacement_before_roster_persistence_cancels_activation_commit() {
        let state = crate::engine::build_test_state("arc03-approve-stale-owner");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let stale_owner = state.peers.owner("peer").expect("first peer owner");
        let mut events = state.events_tx.subscribe();
        let (waiter_tx, mut waiter_rx) = tokio::sync::oneshot::channel();
        state.register_connect_waiter(
            "peer",
            crate::engine::state::ConnectWaiterRegistration {
                id: 1,
                reply: waiter_tx,
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        );
        state.record_reconnect_intent("peer", false);
        {
            let peer = state
                .peers
                .get_if_current(&stale_owner)
                .expect("first peer remains installed");
            let mut data = peer.state.write();
            data.authenticated = true;
            data.local_approve_sent = true;
            data.remote_approve_seen = true;
            data.status = PeerStatus::PendingApproval;
        }

        let replacement_state = Arc::clone(&state);
        maybe_activate_after_check(&state, &stale_owner, move || {
            crate::engine::insert_session_less_peer(&replacement_state, "peer", None);
        })
        .await;

        {
            let replacement = state.peers.get("peer").expect("replacement peer");
            let data = replacement.state.read();
            assert!(!data.authenticated);
            assert!(!data.local_approve_sent);
            assert!(!data.remote_approve_seen);
            assert_ne!(data.status, PeerStatus::Active);
        }
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            waiter_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert!(state.has_reconnect_intent("peer"));
        assert!(
            !state.is_rostered("peer"),
            "a peer replaced before the persistence fence must not enter the roster"
        );
        state.shutdown().await;
    }

    /// A Hello cannot carry application capability metadata, and a peer that
    /// sends one anyway changes nothing.
    ///
    /// This is the pre-promotion half of the capability boundary, and it is a
    /// wire claim rather than a type claim: deleting the field from
    /// `HelloMessage` stops *this* build from producing one, but says nothing
    /// about what a peer may put on the wire. A sender that still emits the old
    /// frame — or an attacker that emits it deliberately — must be unable to
    /// place application metadata into this node before a session owns it.
    ///
    /// Three things are asserted, and each fails differently:
    ///
    /// 1. the frame still parses, so the removal is a hard cutover of *meaning*
    ///    and not an accidental denial of service against every older peer;
    /// 2. the parsed value has nowhere to put it — there is no field on
    ///    `HelloMessage` that a `capabilities` key can land in, which is what
    ///    makes step 3 structural rather than a matter of the handler
    ///    remembering to ignore it;
    /// 3. re-encoding what was parsed does not carry the key forward, so the
    ///    metadata cannot be relayed onward either.
    ///
    /// The complementary post-promotion half — that `CapabilitiesUpdate` is
    /// refused before a live session — is enforced by the admission gate in
    /// `engine::mod` and by the live-session lender `on_capabilities_update`
    /// runs under; a peer without a promoted session reaches neither.
    #[test]
    fn a_hello_advertising_capabilities_is_parsed_without_them() {
        use crate::protocol::features::Feature;

        let with_advert = serde_json::json!({
            "protocol": PROTOCOL_VERSION,
            "device_id": "peer",
            "label": "Phone",
            "nonce": "noncexyz",
            "verification_code": "aaa111",
            "features": [Feature::ENDPOINT_AUTH_V1.to_string()],
            // The retired fields, exactly as an older peer would send them.
            "capabilities": { "tags": ["transcribe"], "app_version": "9.9.9" },
            "max_connections": 8,
            "app_version": "9.9.9",
        });

        let hello: HelloMessage =
            serde_json::from_value(with_advert).expect("an older peer's hello still parses");
        assert_eq!(hello.device_id, "peer");
        assert_eq!(hello.features, vec![Feature::ENDPOINT_AUTH_V1.to_string()]);

        let reencoded = serde_json::to_value(&hello).expect("hello re-encodes");
        let object = reencoded.as_object().expect("hello is a JSON object");
        for retired in ["capabilities", "max_connections", "app_version"] {
            assert!(
                !object.contains_key(retired),
                "a retired hello field must not survive a parse: {reencoded}"
            );
        }
    }
}
