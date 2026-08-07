//! Hello → auth_response state machine.
//!
//! On data channel open:
//!   - Local generates nonce + verification code.
//!   - Sends `hello { device_id, label, nonce, verification_code,
//!     capabilities, app_version, features }`.
//!   - Watchdog scheduled at `HANDSHAKE_TIMEOUT_MS`; up to three
//!     hello retries on the [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`].
//!
//! On inbound hello:
//!   - Record peer's contribution + verification code.
//!   - Build the Arc 04 endpoint-auth transcript — length-prefixed
//!     fields under `ENDPOINT_AUTH_DOMAIN_TAG`: mesh context, fixed
//!     crypto profile, signer role, both device IDs, both contributions,
//!     and both endpoints' DTLS fingerprints, every paired field in
//!     role-canonical order — and ed25519-sign it.
//!   - Reply with `auth_response { signature }`.
//!   - A hello arriving after this channel is already authenticated is a
//!     retransmission: the stored contribution is reused and peer state
//!     is left untouched, but the reply is still sent.
//!
//! On inbound auth_response:
//!   - Reconstruct the same transcript, recompute *our* half, and verify
//!     both halves through the exact current `EndpointAuthTask`. A
//!     one-directional proof is not accepted as mutual.
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
use super::scheduler::{HANDSHAKE_HELLO_RETRY_SCHEDULE_MS, HANDSHAKE_TIMEOUT_MS};
use super::state::{NetworkState, PeerOwnerToken};
use super::{phase, send_to_peer_owner};

/// Generate a fresh contribution: 32 CSPRNG bytes, base32-lowercase.
///
/// This is the endpoint-auth contribution as well as the legacy handshake
/// nonce; the type keeps the two from drifting apart, and keeps the value
/// unconstructible except from a draw.
fn fresh_nonce() -> crate::endpoint_auth::LocalContribution {
    crate::endpoint_auth::LocalContribution::generate()
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
    let nonce = fresh_nonce();
    let code = verification::generate_code();
    let caps = state
        .rpc
        .read()
        .as_ref()
        .map(|r| r.capability.lock().clone())
        .unwrap_or_default();
    let hello = HelloMessage {
        protocol: PROTOCOL_VERSION,
        device_id: state.identity.public_id().to_string(),
        label: state.identity.label().to_string(),
        nonce: nonce.as_str().to_owned(),
        verification_code: code.clone(),
        capabilities: Some(caps),
        max_connections: None,
        features: ADVERTISED_FEATURES.iter().map(|s| s.to_string()).collect(),
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    if let Some(peer) = state.peers.get_if_current(owner) {
        let mut data = peer.state.write();
        data.status = PeerStatus::Handshaking;
        data.nonce_sent = Some(nonce);
        data.verification_code_sent = Some(code.clone());
        data.handshake_started_at = Some(Instant::now());
        data.hello_attempt = 1;
        data.diag.hellos_sent += 1;
    }
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
/// or the watchdog tears down. Replaying the hello is safe: the
/// receiver overwrites its `nonce_received` slot unconditionally and
/// the signature in `auth_response` is deterministic, so a duplicate
/// just yields a duplicate (idempotent) reply.
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

    // A Hello that arrives after this channel is already authenticated is a
    // retransmission, not a new attempt. Adopting its contribution would
    // rewrite the transcript underneath a completed proof, so the stored one
    // is reused and peer state is left alone. We still fall through and re-send
    // an AuthResponse, because the retransmission usually means ours was lost.
    let already_authenticated = state
        .peers
        .get_if_current(owner)
        .is_some_and(|p| p.has_authenticated_channel());
    let peer_contribution = if already_authenticated {
        let stored = state
            .peers
            .get_if_current(owner)
            .and_then(|p| p.state.read().nonce_received.clone());
        let Some(stored) = stored else {
            warn!(peer = %device_id, "authenticated peer has no recorded contribution — dropping");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        };
        stored
    } else {
        peer_contribution
    };

    // Record the peer's nonce / verification code and capabilities.
    if let Some(peer) = state
        .peers
        .get_if_current(owner)
        .filter(|_| !already_authenticated)
    {
        let mut data = peer.state.write();
        data.nonce_received = Some(peer_contribution.clone());
        data.verification_code_received = Some(hello.verification_code.clone());
        data.label = hello.label.clone();
        // The advertised feature set is the sender-side gate for every
        // optional frame kind (acked channel delivery, governance wire,
        // …) — record it, or `peer_supports` has nothing to consult.
        data.features = hello.features.clone();
        if let Some(caps) = &hello.capabilities {
            data.capabilities = Some(caps.clone());
        }
    }

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

    // Bind the signed handshake to this DTLS channel: fold in the fingerprint
    // of the certificate we present here. The initiator verifies it against
    // the fingerprint it observes on its end of the channel, so a
    // signaling-path MITM that terminates DTLS on each leg (presenting its own
    // cert) makes the two disagree and the signature fails. Fail closed if the
    // transport can't surface it — dropping is safer than sending an unbound
    // signature an interceptor could relay unmodified.
    let Some(session) = state
        .peers
        .get_if_current(owner)
        .and_then(|p| p.session.lock().clone())
    else {
        // On an already-authenticated channel this hello is a retransmission,
        // and failing to build the *reply* is not grounds to tear down a peer
        // whose proof already succeeded. Only a first attempt fails closed.
        if already_authenticated {
            debug!(peer = %device_id, "no session for a hello retransmission — leaving the authenticated peer alone");
            return;
        }
        warn!(peer = %device_id, "no transport session at hello — cannot channel-bind, dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    let Some(local_fingerprint) = session.local_fingerprint().await else {
        if already_authenticated {
            debug!(peer = %device_id, "no local fingerprint for a hello retransmission — leaving the authenticated peer alone");
            return;
        }
        warn!(peer = %device_id, "no local DTLS fingerprint — refusing to send an unbound auth response");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    // Both endpoints' certificates are bound, in role-canonical order, so the
    // transcript commits to the pair rather than only to the signer's own
    // certificate. A signer-only binding leaves the verifier's endpoint
    // uncommitted.
    let Some(remote_fingerprint) = session.remote_fingerprint().await else {
        if already_authenticated {
            debug!(peer = %device_id, "no remote fingerprint for a hello retransmission — leaving the authenticated peer alone");
            return;
        }
        warn!(peer = %device_id, "no remote DTLS fingerprint — refusing to send a half-bound auth response");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    // Our own contribution must already exist: the transcript is mutual, and
    // signing it without our half would prove only one direction.
    // Borrowed only long enough to copy the encoded form: the typed value
    // stays in place so this attempt's completion still consumes it. Hello
    // retries within one attempt therefore reuse the same stored draw.
    let Some(local_contribution) = state.peers.get_if_current(owner).and_then(|p| {
        p.state
            .read()
            .nonce_sent
            .as_ref()
            .map(|c| c.as_str().to_owned())
    }) else {
        warn!(peer = %device_id, "no local contribution at hello — refusing to sign a one-sided transcript");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    if state.peers.get_if_current(owner).is_none() {
        return;
    }

    // Build the Arc 04 endpoint-auth transcript and reply. The legacy
    // `SIGN_DOMAIN_TAG` payload is deliberately not sent: domain separation
    // means a peer that still speaks the old format simply fails to verify,
    // rather than being offered a weaker format it could select.
    let local_device_id = state.identity.public_id().to_string();
    let remote_device_id = signing::pubkey_part(device_id).to_string();
    let payload = crate::endpoint_auth::EndpointAuthAttempt::transcript_bytes(
        &state.network_id,
        crate::endpoint_auth::EndpointAuthProfile::V1Ed25519Dtls,
        crate::endpoint_auth::EndpointAuthAttempt::role_of(&local_device_id, &remote_device_id),
        &local_device_id,
        &remote_device_id,
        &local_contribution,
        peer_contribution.as_str(),
        &local_fingerprint,
        &remote_fingerprint,
    );
    let signature = signing::sign_with(state.identity.signing_key(), &payload);
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
    // `nonce_sent` stays owned by per-peer state for the whole connector
    // attempt; only its encoded form is copied out. Consuming it here would
    // open a retry race — a retransmitted or delayed Hello would then find no
    // local contribution and tear down a peer whose proof is valid. Single
    // promotion is enforced by the move-only handoff instead.
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
    let (my_nonce, peer_nonce, peer_label, verification_code) = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let data = peer.state.read();
        (
            data.nonce_sent.as_ref().map(|c| c.as_str().to_owned()),
            data.nonce_received.clone(),
            data.label.clone(),
            data.verification_code_received.clone().unwrap_or_default(),
        )
    };
    let Some(my_nonce) = my_nonce else {
        warn!(peer = %device_id, "auth_response without an unconsumed local contribution — no hello sent, or this attempt already completed");
        return;
    };
    // Both contributions are required. Verifying with only ours would leave
    // the peer's freshness out of the transcript, and freshness is what
    // separates two channels that share a certificate.
    let Some(peer_nonce) = peer_nonce else {
        warn!(peer = %device_id, "auth_response before the peer's hello — no peer contribution to bind");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    // Reconstruct the peer's channel binding: the DTLS fingerprint we observe
    // on our end of the channel. The peer signed the fingerprint of the cert
    // it presented; WebRTC guarantees that equals what we observe here unless
    // DTLS was re-terminated in the middle — in which case the fingerprints
    // differ and the signature won't verify below. Fail closed if the
    // transport can't surface it.
    let Some(session) = state
        .peers
        .get_if_current(owner)
        .and_then(|p| p.session.lock().clone())
    else {
        warn!(peer = %device_id, "no transport session at auth_response — cannot verify channel binding, dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    let Some(remote_fingerprint) = session.remote_fingerprint().await else {
        warn!(peer = %device_id, "no remote DTLS fingerprint — cannot verify channel binding, dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    let Some(local_fingerprint) = session.local_fingerprint().await else {
        warn!(peer = %device_id, "no local DTLS fingerprint — cannot verify the bound pair, dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
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

    let local_device_id = state.identity.public_id().to_string();
    let remote_device_id = signing::pubkey_part(device_id).to_string();
    let profile = crate::endpoint_auth::EndpointAuthProfile::V1Ed25519Dtls;
    // Recompute our own half. Proving only the peer's half would let a
    // one-directional proof masquerade as mutual authentication.
    let local_signature = signing::sign_with(
        state.identity.signing_key(),
        &crate::endpoint_auth::EndpointAuthAttempt::transcript_bytes(
            &state.network_id,
            profile,
            crate::endpoint_auth::EndpointAuthAttempt::role_of(&local_device_id, &remote_device_id),
            &local_device_id,
            &remote_device_id,
            &my_nonce,
            peer_nonce.as_str(),
            &local_fingerprint,
            &remote_fingerprint,
        ),
    );
    let Some(peer) = state.peers.get_if_current(owner) else {
        return;
    };
    // The typed local contribution is *borrowed* from per-peer state, never
    // moved out, so a Hello retransmission can still re-sign this attempt.
    // The read guard is held only across synchronous work.
    let outcome = {
        let data = peer.state.read();
        data.nonce_sent.as_ref().map(|my_contribution| {
            auth_task.authenticate(
                &state.network_id,
                profile,
                &local_device_id,
                &remote_device_id,
                my_contribution,
                &peer_nonce,
                &local_fingerprint,
                &remote_fingerprint,
                &local_signature,
                &resp.signature,
            )
        })
    };
    let capability = match outcome {
        Some(Ok(capability)) => capability,
        // A retransmission that arrived after promotion completed. Each
        // connector has a single event-pump task that awaits one event before
        // taking the next, so frames on one channel are handled sequentially —
        // this is a *sequential* retransmission, not a concurrent one, and by
        // the time it runs the install has already happened.
        //
        // This check deliberately does not claim to close a concurrent window.
        // If two callers could ever run `authenticate` against one task in
        // parallel, the loser could observe `ChannelNotCurrent` while the
        // winner had taken the handoff but not yet installed, and would fail
        // closed rather than being recognised as a duplicate. Making that safe
        // needs promotion and install to be one atomic step, not a wider
        // read-back here.
        Some(Err(crate::endpoint_auth::EndpointAuthError::ChannelNotCurrent))
            if peer.has_authenticated_channel() && peer.endpoint_auth_is_current(&auth_task) =>
        {
            debug!(peer = %device_id, "duplicate auth_response after promotion completed");
            return;
        }
        Some(Err(error)) => {
            warn!(peer = %device_id, "endpoint authentication refused: {error:?}");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
        None => {
            warn!(peer = %device_id, "local contribution vanished mid-attempt — dropping");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
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
    let (auto_approve, rostered, caps) = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let mut data = peer.state.write();
        data.authenticated = true;
        data.status = PeerStatus::PendingApproval;
        let rostered = state.is_rostered(device_id);
        let cfg = state.config.read();
        let auto = cfg.auto_approve || rostered;
        (
            auto,
            rostered,
            data.capabilities.clone().unwrap_or_default(),
        )
    };

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
        capabilities: caps,
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
        let active = data.authenticated && data.local_approve_sent && data.remote_approve_seen;
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
        if !peer.install_legacy_realtime_flow() {
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "connector",
                format!(
                    "{} ACTIVE without an admitted connector-native real-time flow",
                    super::short_peer(device_id)
                ),
                serde_json::json!({ "peer": device_id }),
            );
        }
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
    super::reliable::flush_peer_owner(state, owner).await;
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

    #[tokio::test]
    async fn v4_arc04_duplicate_auth_response_after_promotion_is_idempotent() {
        // A retransmitted AuthResponse must not re-enter promotion. Before the
        // idempotence guard it would find the handoff already consumed, return
        // ChannelNotCurrent, and drop a peer whose proof was valid.
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

    #[tokio::test]
    async fn v4_arc04_delayed_hello_after_promotion_does_not_rewrite_the_attempt() {
        // A hello that arrives after this channel is authenticated is a
        // retransmission. Adopting its contribution would rewrite the
        // transcript underneath a completed proof, and failing to build the
        // reply must not tear down a peer whose proof already succeeded.
        let state = crate::engine::build_test_state("arc04-delayed-hello");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        let settled = crate::endpoint_auth::LocalContribution::generate();
        let settled_peer = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical");
        {
            let peer = state.peers.get("peer").expect("peer is installed");
            let mut data = peer.state.write();
            data.nonce_sent = Some(settled);
            data.nonce_received = Some(settled_peer.clone());
            data.label = "settled-label".to_string();
            data.verification_code_received = Some("aaa111".to_string());
        }
        let peer = state.peers.get("peer").expect("peer is installed");
        peer.install_authenticated_channel_for_test();
        assert!(
            peer.has_authenticated_channel(),
            "non-vacuity: the attempt really is complete before the delayed hello"
        );

        // A late hello carrying a *different* contribution and label.
        let intruding = crate::endpoint_auth::LocalContribution::generate();
        on_hello(
            &state,
            &owner,
            HelloMessage {
                protocol: PROTOCOL_VERSION,
                device_id: owner.device_id().to_string(),
                label: "rewritten-label".to_string(),
                nonce: intruding.as_str().to_string(),
                verification_code: "zzz999".to_string(),
                capabilities: None,
                max_connections: None,
                features: Vec::new(),
                app_version: None,
            },
        )
        .await;

        let peer = state
            .peers
            .get_if_current(&owner)
            .expect("a retransmitted hello must not tear the peer down");
        assert!(
            peer.has_authenticated_channel(),
            "the exact current capability is preserved"
        );
        let data = peer.state.read();
        assert_eq!(
            data.nonce_received.as_ref().map(|c| c.as_str().to_owned()),
            Some(settled_peer.as_str().to_owned()),
            "the completed attempt's contribution must not be rewritten"
        );
        assert_eq!(data.label, "settled-label", "nor its recorded label");
        assert_eq!(
            data.verification_code_received.as_deref(),
            Some("aaa111"),
            "nor its verification code"
        );
    }

    #[tokio::test]
    async fn v4_arc04_auth_response_before_our_hello_is_refused() {
        // No local contribution has been drawn, so there is no attempt to
        // complete and nothing can be promoted.
        let state = crate::engine::build_test_state("arc04-auth-response-before-hello");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        assert!(state
            .peers
            .get("peer")
            .expect("peer is installed")
            .state
            .read()
            .nonce_sent
            .is_none());

        on_auth_response(&state, &owner, auth_response("unsolicited")).await;

        assert!(
            !state
                .peers
                .get("peer")
                .expect("peer is installed")
                .has_authenticated_channel(),
            "an unsolicited auth_response must never promote"
        );
    }

    #[tokio::test]
    async fn v4_arc04_auth_response_before_the_peers_hello_is_refused() {
        // We drew our contribution, but the peer's has not arrived, so the
        // transcript is missing a required field. Promotion must not occur.
        let state = crate::engine::build_test_state("arc04-auth-response-before-peer-hello");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        {
            let peer = state.peers.get("peer").expect("peer is installed");
            let mut data = peer.state.write();
            data.nonce_sent = Some(crate::endpoint_auth::LocalContribution::generate());
            assert!(data.nonce_received.is_none());
        }

        on_auth_response(&state, &owner, auth_response("premature")).await;

        assert!(
            state
                .peers
                .get("peer")
                .is_none_or(|peer| !peer.has_authenticated_channel()),
            "a one-sided transcript must never promote"
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
        state.register_connect_waiter("peer", waiter_tx);
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
}
