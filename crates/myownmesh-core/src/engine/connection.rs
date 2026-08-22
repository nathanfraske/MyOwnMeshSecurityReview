//! Per-peer connection state held by the engine.
//!
//! Each entry in the engine's `peers` map is a [`PeerConnection`]:
//! the shared [`PeerStateData`] (status, tier, watermarks,
//! capabilities) plus the optional WebRTC connector worker.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::protocol::CapabilityAdvert;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};
use crate::transport::{PeerDiag, SelectedCandidatePair, WebRtcConnectorWorker};

use super::ladder::ConnectionTier;
use crate::runtime::peer_session::{DedupToken, PromotedChannelBinding};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Signaling has surfaced the peer; transport is being
    /// brought up.
    Sighted,
    /// Data channel is open; hello/auth_response in flight.
    Handshaking,
    /// Auth verified; awaiting user (or auto-roster) approval.
    PendingApproval,
    /// Both sides have exchanged `approve`; app traffic flows.
    Active,
    /// Active connection demoted by the topology selector. The
    /// data channel stays open as a heartbeat path.
    Shelved,
    /// Connection dropped; reconnect attempts in progress.
    Reconnecting,
    /// Connection torn down. The engine retains the entry only
    /// briefly so an immediate reconnect can short-circuit
    /// approval.
    Offline,
    /// Fatal error — peer is excluded until user intervention.
    Error,
}

#[derive(Debug)]
pub struct PeerStateData {
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub authenticated: bool,
    /// Profile identifiers the peer advertised in its `hello` (see
    /// `protocol::features`). Empty until the hello lands. Endpoint
    /// authentication requires the one exact current profile identifier.
    pub features: Vec<String>,
    /// Attempt-owned funding for the peer-supplied Hello representation kept
    /// here until this connector is retired. This is deliberately not copied
    /// into snapshots: it is ownership, not diagnostic state.
    pub(crate) hello_retention: Option<crate::resource::ResourceLease>,
    /// True after the exact current data channel accepts our `Approve` bytes
    /// for transmission. This does not prove remote receipt.
    pub local_approve_sent: bool,
    /// True only after this exact peer sends us an inbound `Approve`.
    pub remote_approve_seen: bool,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub label: String,
    /// The short codes the two endpoints display for out-of-band comparison.
    ///
    /// Presentation only. Neither is an authentication input: the Endpoint Auth
    /// Task owns the contributions the transcript is built from, so nothing a
    /// later frame writes here can move a proof.
    pub verification_code_sent: Option<String>,
    pub verification_code_received: Option<String>,
    pub last_recv_at: Option<Instant>,
    pub last_ping_sent_at: Option<Instant>,
    /// Wall-clock of the most recent SDP offer we sent for this
    /// peer (either the original from `ensure_peer_session` or a
    /// re-poke from `handle_signaling_inbound`). Used to rate-
    /// limit the announce-driven re-offer path so a burst of
    /// inbound announces (e.g. REQ-replay delivering 14 stored
    /// announces in one ms) doesn't translate into 14 outbound
    /// offers. `None` until we've sent the first offer for this
    /// session; cleared on `drop_peer`.
    pub last_offer_sent_at: Option<Instant>,
    /// Wall-clock of the most recent announce-driven liveness probe we
    /// fired for this peer. When a peer we believe is connected re-announces
    /// but its inbound has gone silent, we ping it and rebuild if no traffic
    /// confirms the link (see `confirm_active_session_on_announce`). This
    /// single-flights that probe so an announce burst (REQ replay) can't
    /// stack a dozen probe tasks on one peer. `None` until the first probe;
    /// cleared with the rest of the state on `drop_peer` (a rebuild starts a
    /// fresh `PeerStateData`).
    pub last_liveness_probe_at: Option<Instant>,
    pub last_ping_t: Option<i64>,
    pub rtt_ms: Option<u32>,
    /// Rolling clock-skew samples against this peer, newest last (ms;
    /// positive = the peer's wall clock reads ahead of ours). Each inbound
    /// heartbeat ping contributes one — its `t` is the sender's wall clock,
    /// corrected by half our measured RTT — so the estimate is purely
    /// passive: no extra traffic to any node. Capped at
    /// `heartbeat::SKEW_WINDOW`.
    pub clock_skew_samples: Vec<i64>,
    /// Median of [`Self::clock_skew_samples`] — the per-peer estimate
    /// surfaced in `PeerInfo` and folded into the network-wide check in
    /// `heartbeat::tick`. `None` until the first inbound ping.
    pub clock_skew_ms: Option<i64>,
    pub ice_disconnected_since: Option<Instant>,
    /// When this peer's transport session (the `RTCPeerConnection`) was
    /// created. The single clock for a *connecting* peer: if its data
    /// channel hasn't opened within `DATA_CHANNEL_OPEN_TIMEOUT_MS` of
    /// this, the attempt is treated as failed and rebuilt. Replaces the
    /// old ICE-`Checking` timeout — we time the reliable milestone (a data
    /// channel that actually opened) instead of webrtc-rs's unreliable ICE
    /// connection state. `None` only for the session-less peers some unit
    /// tests insert; set in `ensure_peer_session` when the session opens.
    pub session_started_at: Option<Instant>,
    /// The connector's track set changed on this session and the SDP no
    /// longer matches — the renegotiation pass owes this peer one in-place
    /// offer. Coalesced: any number of changes between passes costs a
    /// single renegotiation.
    pub media_reneg_pending: bool,
    /// A renegotiation task is currently running for this peer
    /// (spawned off the driver — see `service_media_renegotiations`).
    /// Single-flight guard: the tick skips a peer whose offer is still
    /// in flight instead of stacking a second one onto webrtc-rs.
    pub media_reneg_inflight: bool,
    /// True once this session's data channel has fired `on_open` — the one
    /// reliable "transport is up" signal (DTLS + SCTP genuinely
    /// established). The connect-timeout watchdog only reclaims a peer
    /// whose channel never opened; once it's open, liveness is governed by
    /// inbound-frame recency (heartbeat), not by ICE state.
    pub data_channel_open: bool,
    pub handshake_started_at: Option<Instant>,
    pub hello_attempt: u32,
    /// Consecutive `ICE failed` events since the last successful
    /// transition to Active. Drives the no-TURN diagnostic: after
    /// a few failures with zero relay candidates we tell the user
    /// their setup will never work without TURN.
    pub ice_failed_count: u32,
    /// One-shot guard so we don't re-emit the no-TURN diagnostic
    /// every time the ladder cycles. Reset when the peer becomes
    /// Active again.
    pub no_turn_diag_emitted: bool,
    /// The ICE candidate pair actually in use, once the agent has
    /// nominated one. The graph uses this to classify the link as
    /// LAN (host↔host), STUN (srflx involved), or TURN (relay
    /// involved) without relying on heuristics over the gathered-
    /// candidate counts. `None` until ICE reaches Connected.
    pub selected_pair: Option<SelectedCandidatePair>,
    /// Count of inbound frames the admission gate dropped because the peer
    /// hadn't reached the phase they require (an application/RPC/reliable/
    /// governance/media frame arriving before the ed25519 handshake + approval
    /// finished). Drives a power-of-two-throttled warn so a pre-admission
    /// flood can't be turned into a log-amplification primitive.
    pub admission_rejected: u64,
    pub diag: PeerDiag,
}

/// One peer's session record and state data, borrowed together.
///
/// The whole value of this type is that its three fields were read under **one**
/// observation — see [`PeerConnection::with_peer_view`], which is the only way
/// to obtain it. Nothing here is owned, so a caller can measure it without
/// allocating, and nothing can outlive the guards it was read from.
///
/// `session` is `None` for a peer with no current promoted session. That is a
/// fact about the peer, not a failure to read it: its state is still present and
/// still borrowed from the same instant.
///
/// `Copy`, because it is three shared references: a caller that measures the
/// view and then builds from it is reading the same borrows twice, not
/// observing the peer twice.
#[derive(Clone, Copy)]
pub(super) struct PeerView<'a> {
    pub(super) device_id: &'a str,
    pub(super) data: &'a PeerStateData,
    pub(super) session: Option<&'a crate::runtime::peer_session::PeerSessionState>,
}

/// Clonable point-in-time view for diagnostics and compatibility callers.
///
/// This deliberately omits mutable ownership such as the pending candidate
/// queue. Mutating a snapshot cannot alter the live peer or duplicate an
/// observation lease.
#[derive(Debug, Clone)]
pub struct PeerStateSnapshot {
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub rtt_ms: Option<u32>,
    pub clock_skew_ms: Option<i64>,
    pub label: String,
    pub capabilities: Option<CapabilityAdvert>,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub authenticated: bool,
    pub verification_code_received: Option<String>,
    pub verification_code_sent: Option<String>,
    pub local_approve_sent: bool,
    pub remote_approve_seen: bool,
    pub needs_turn: bool,
    pub diag: PeerDiag,
    pub selected_pair: Option<SelectedCandidatePair>,
}

impl PeerStateData {
    /// The admission boundary: `true` once this peer has proven its ed25519
    /// identity (`authenticated`) **and** both sides have approved (`Active`,
    /// or `Shelved` — an admitted `Active` peer parked by the topology
    /// selector). This is the single predicate every inbound application/RPC/
    /// reliable/governance/routing/media path — and the application-level
    /// outbound senders — gate on. A merely-connected peer (`Sighted`/
    /// `Handshaking`/`PendingApproval`) is **not** admitted: a live DTLS data
    /// channel is not authorization. The `authenticated` conjunct is defence in
    /// depth — even if some path reached `Active` without authenticating, no
    /// traffic flows.
    pub fn is_admitted(&self) -> bool {
        self.authenticated && matches!(self.status, PeerStatus::Active | PeerStatus::Shelved)
    }

    /// The diagnostic view of this peer's *state*.
    ///
    /// `capabilities` is supplied rather than read, because it is no longer peer
    /// state: it belongs to the promoted session, and only a caller holding the
    /// entry can reach that. [`PeerConnection::snapshot`] is that caller. Passing
    /// it in keeps the one public snapshot shape while making it impossible to
    /// fill the field from anything that outlives the session.
    pub fn snapshot(&self, capabilities: Option<CapabilityAdvert>) -> PeerStateSnapshot {
        PeerStateSnapshot {
            status: self.status,
            tier: self.tier,
            rtt_ms: self.rtt_ms,
            clock_skew_ms: self.clock_skew_ms,
            label: self.label.clone(),
            capabilities,
            local_shelved: self.local_shelved,
            remote_shelved: self.remote_shelved,
            authenticated: self.authenticated,
            verification_code_received: self.verification_code_received.clone(),
            verification_code_sent: self.verification_code_sent.clone(),
            local_approve_sent: self.local_approve_sent,
            remote_approve_seen: self.remote_approve_seen,
            needs_turn: self.no_turn_diag_emitted,
            diag: self.diag.clone(),
            selected_pair: self.selected_pair,
        }
    }
}

impl Default for PeerStateData {
    fn default() -> Self {
        Self {
            status: PeerStatus::Sighted,
            tier: ConnectionTier::Steady,
            authenticated: false,
            features: Vec::new(),
            hello_retention: None,
            local_approve_sent: false,
            remote_approve_seen: false,
            local_shelved: false,
            remote_shelved: false,
            label: String::new(),
            verification_code_sent: None,
            verification_code_received: None,
            last_recv_at: None,
            last_ping_sent_at: None,
            last_offer_sent_at: None,
            last_liveness_probe_at: None,
            last_ping_t: None,
            rtt_ms: None,
            clock_skew_samples: Vec::new(),
            clock_skew_ms: None,
            ice_disconnected_since: None,
            session_started_at: None,
            media_reneg_pending: false,
            media_reneg_inflight: false,
            data_channel_open: false,
            handshake_started_at: None,
            hello_attempt: 0,
            ice_failed_count: 0,
            no_turn_diag_emitted: false,
            selected_pair: None,
            admission_rejected: 0,
            diag: PeerDiag::default(),
        }
    }
}

/// What one call to [`PeerConnection::promote_session_if_needed`] did.
///
/// Three answers rather than a boolean, because the caller acts differently on
/// each and one of them is an event. A session that was *minted* by this call is
/// the only moment at which anything owed to a new session becomes owed, and it
/// happens exactly once per session however many operations later reuse it. A
/// boolean collapses `Current` and `NewlyPromoted` into "usable", which is
/// enough to proceed but not enough to announce — and an announcement derived
/// from "usable" would fire on every operation for the life of the session.
///
/// `Refused` covers both the terminal refusals and the capacity one. Neither
/// minted a session, so neither announces; the capacity refusal in particular
/// leaves the authenticated channel installed, so a later operation promotes and
/// *that* call is the one that announces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Promotion {
    /// A session was already installed and every use-time conjunct still holds.
    Current,
    /// This call minted the session. Nothing owed to it has been done yet.
    NewlyPromoted,
    /// No usable session, and none was minted.
    Refused,
}

impl Promotion {
    /// Whether the caller may proceed against a live session.
    pub(super) fn is_usable(self) -> bool {
        matches!(self, Self::Current | Self::NewlyPromoted)
    }
}

pub(super) struct SpeculativePromotion {
    pub(super) displaced_attempt: Option<AttemptDisplacement>,
    pub(super) selected: bool,
}

pub(super) struct AttemptDisplacement {
    pub(super) dedup: Option<DedupToken>,
    pub(super) additional_dedup: Vec<DedupToken>,
}

pub(super) struct SpeculativeRetirement {
    pub(super) worker: Arc<WebRtcConnectorWorker>,
    pub(super) dedup: Option<DedupToken>,
    pub(super) additional_dedup: Vec<DedupToken>,
}

/// A provider-funded connector being considered as a replacement for the
/// promoted connector.  This slot is deliberately separate from `session`:
/// signaling may drive it, but it cannot borrow or mutate application
/// authority until Endpoint Auth has completed on this exact worker.
pub(super) struct SpeculativeAttempt {
    pub(super) correlation: String,
    pub(super) session: Arc<WebRtcConnectorWorker>,
    pub(super) endpoint_auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    pub(super) authenticated_channel: Option<crate::endpoint_auth::AuthenticatedChannelCapability>,
    pub(super) dedup: Option<DedupToken>,
    pub(super) additional_dedup: Vec<DedupToken>,
    pub(super) _attempt_lease: ResourceLease,
}

impl PeerConnection {
    pub(super) fn speculative_attempt_claim(correlation: &str) -> ResourceClaim {
        let correlation_bytes = u64::try_from(correlation.len())
            .expect("correlation length fits the provider accounting width");
        let record_bytes = u64::try_from(std::mem::size_of::<SpeculativeAttempt>())
            .expect("candidate record size fits the provider accounting width");
        let accounted = correlation_bytes
            .checked_add(record_bytes)
            .expect("candidate record accounting cannot overflow");
        ResourceClaim::try_from_entries([
            // One live candidate owns this correlation allocation and record.
            // The lease is released with that exact candidate; there is no
            // peer-lifetime replay tombstone or fixed candidate count.
            (ResourceClass::AccountedMemoryBytes, accounted),
            (ResourceClass::StorageObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .expect("fixed candidate-record resource dimensions cannot overflow")
    }
}

pub struct PeerConnection {
    pub device_id: String,
    pub state: RwLock<PeerStateData>,
    pub(super) session: Mutex<Option<Arc<WebRtcConnectorWorker>>>,
    speculative: Mutex<Vec<SpeculativeAttempt>>,
    closing_workers: Mutex<Vec<Arc<WebRtcConnectorWorker>>>,
    retired_dedup: Mutex<Vec<DedupToken>>,
    signaling_runtime: RwLock<Option<Weak<crate::engine::signaling_ingress::SignalingRuntime>>>,
    media_renegotiation_workers: Mutex<Vec<Arc<WebRtcConnectorWorker>>>,
    endpoint_auth: Mutex<Option<Arc<crate::endpoint_auth::EndpointAuthTask>>>,
    /// The Arc 04 authority artifact for the exact current channel.
    ///
    /// `PeerStateData::authenticated` remains as legacy diagnostic and policy
    /// state, but a bool cannot be invalidated by channel replacement and
    /// carries no provenance. This slot does: it is installed only by the
    /// endpoint-auth task that owns the current connector, and it is dropped
    /// whenever that connector is retired or replaced.
    authenticated_channel: Mutex<Option<crate::endpoint_auth::AuthenticatedChannelCapability>>,
    /// The correlation naming this connection attempt, for de-duplication.
    ///
    /// One installation of a peer is one attempt, so this is minted here, once,
    /// and a replacement installation gets a different one. It rides every
    /// offer, answer and candidate this side emits for the attempt, and the
    /// answering side adopts the offerer's value through [`Self::adopt_attempt`]
    /// so both ends name the attempt the same thing.
    ///
    /// **What it is for, and the one thing it is not.** The signaling ingress
    /// keys de-duplication under it, which is the only way to tell "the second
    /// relay's copy of this offer" from "the same host candidate again on a
    /// fresh attempt" — the two are byte-identical otherwise, which is how a
    /// retired attempt's key used to swallow a live one. It is sender-chosen and
    /// unauthenticated on arrival, so it may scope that and nothing else: it is
    /// not a route identity, not a path generation, not a session generation,
    /// and no decision anywhere reads it as authority or preference.
    attempt: RwLock<String>,
    attempt_dedup: Mutex<Option<DedupToken>>,
    additional_attempt_dedup: Mutex<Vec<DedupToken>>,
    /// The promoted session for the exact current channel.
    ///
    /// Promotion **moves** the authenticated capability out of the slot above
    /// and into the session, so the two are never both occupied for one channel:
    /// once promoted, the session is the sole owner of that channel's authority,
    /// and its drop is what returns the connected claim to connector retention.
    ///
    /// Dropped by `retire_connector` for the same reason the capability is —
    /// a session promoted under the retired connector must not survive into its
    /// replacement.
    ///
    /// The slot, the bundle it holds and the use and revocation rules that
    /// govern it all belong to
    /// [`peer_session`](crate::runtime::peer_session): this entry owns the
    /// connector and refers to its session owner rather than implementing that
    /// owner's state machine.
    promoted_session: crate::runtime::peer_session::PromotedSessionSlot,
    registry_retired: AtomicBool,
    /// Diagnostic-only rebuild ordinal. It is never accepted as callback,
    /// attempt, resource, or application authority.
    pub epoch: u64,
    unpromoted_offer_in_flight: AtomicBool,
}

/// Exact-owner witness for one legacy untrusted-signaling mutation.
///
/// The registry mints this only while the named installation is current and
/// unpromoted. Its lifetime blocks both normal and speculative promotion for
/// that installation until the awaited mutation has completed or been
/// cancelled.
pub(super) struct UnpromotedNegotiation {
    peer: Arc<PeerConnection>,
}

impl UnpromotedNegotiation {
    pub(super) fn new(peer: Arc<PeerConnection>) -> Self {
        Self { peer }
    }
}

impl Drop for UnpromotedNegotiation {
    fn drop(&mut self) {
        self.peer
            .unpromoted_offer_in_flight
            .store(false, Ordering::Release);
    }
}

/// Process-wide diagnostic sequence for [`PeerConnection::epoch`].
static DIAGNOSTIC_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl PeerConnection {
    fn retain_closing_worker(&self, worker: Arc<WebRtcConnectorWorker>) {
        worker.retire();
        let mut closing = self.closing_workers.lock();
        if !closing.iter().any(|current| Arc::ptr_eq(current, &worker)) {
            closing.push(worker);
        }
    }

    pub(super) fn revoke_promoted_session(self: &Arc<Self>) {
        let workers = self.promoted_session.take_workers_with_dedup();
        let runtime = self
            .signaling_runtime
            .read()
            .as_ref()
            .and_then(Weak::upgrade);
        drop(self.session.lock().take());
        drop(self.endpoint_auth.lock().take());
        drop(self.authenticated_channel.lock().take());
        self.media_renegotiation_workers.lock().clear();
        for (worker, dedup, additional_dedup) in workers {
            if let Some(runtime) = runtime.as_ref() {
                if let Some(dedup) = dedup {
                    runtime.forget_token(dedup);
                }
                for dedup in additional_dedup {
                    runtime.forget_token(dedup);
                }
            } else {
                if let Some(dedup) = dedup {
                    self.retired_dedup.lock().push(dedup);
                }
                self.retired_dedup.lock().extend(additional_dedup);
            }
            self.retain_closing_worker(Arc::clone(&worker));
            worker.start_close();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let peer = Arc::clone(self);
                handle.spawn(async move {
                    if let Err(error) = worker.retire_and_close().await {
                        tracing::warn!(%error, "revoked connector native close failed");
                    }
                    let mut closing = peer.closing_workers.lock();
                    if let Some(index) = closing
                        .iter()
                        .position(|current| Arc::ptr_eq(current, &worker))
                    {
                        drop(closing.swap_remove(index));
                    }
                });
            }
        }
    }

    pub(super) fn bind_signaling_runtime(
        &self,
        runtime: Weak<crate::engine::signaling_ingress::SignalingRuntime>,
    ) {
        *self.signaling_runtime.write() = Some(runtime);
    }

    /// Replace this installed peer's connector after its promoted session and
    /// authenticated channel have both been consumed. Controls only.
    ///
    /// Production installs a new [`PeerConnection`] when a connector is
    /// replaced. The exact-session fence control deliberately keeps this
    /// installation (and therefore its owner token) fixed so replacement of the
    /// session cannot be confused with replacement of the peer. This seam makes
    /// only that normally-atomic fixture step separable; the replacement still
    /// has to present its own live connector and authenticated handoff before it
    /// can promote.
    #[cfg(test)]
    pub(crate) fn replace_connector_for_session_control(&self, worker: Arc<WebRtcConnectorWorker>) {
        assert!(
            !self.promoted_session.is_installed(),
            "the session control replaces a connector only after revocation"
        );
        assert!(
            self.authenticated_channel.lock().is_none(),
            "a successfully promoted channel is consumed before replacement"
        );
        let replaced = self.session.lock().replace(worker);
        drop(replaced);
    }

    /// This attempt's correlation, for stamping an outbound signal.
    pub(super) fn attempt(&self) -> String {
        self.attempt.read().clone()
    }

    /// Adopt the offerer's correlation for this attempt.
    ///
    /// The offering side mints; the answering side adopts, so one attempt has
    /// one name on both ends rather than two names that agree about nothing.
    /// Called when an offer is applied, before any answer or candidate for that
    /// attempt is emitted.
    ///
    /// Returns the correlation this displaced, when it displaced a different
    /// one. That return value is not a courtesy: a rebuild offer — the peer tore
    /// its connection down and built a fresh one on the same installation —
    /// establishes a second attempt here, and the keys the ingress remembered
    /// under the first can never legitimately match again. The caller releases
    /// them. Without the hand-back there is no other way to learn the old value,
    /// and it would sit in the ring until provider pressure evicted it.
    ///
    /// Ignores an empty value, which is what an unstamped frame decodes to:
    /// blanking the field would leave this side emitting uncorrelated signals
    /// for an attempt that has a perfectly good name.
    #[cfg(test)]
    pub(super) fn adopt_attempt(&self, attempt: &str) -> Option<String> {
        let previous = self.attempt();
        self.adopt_attempt_with_dedup(attempt, None)
            .map(|_| previous)
    }

    pub(super) fn adopt_attempt_with_dedup(
        &self,
        attempt: &str,
        dedup: Option<DedupToken>,
    ) -> Option<AttemptDisplacement> {
        if attempt.is_empty() {
            return None;
        }
        let mut current = self.attempt.write();
        if *current == attempt {
            if let Some(dedup) = dedup {
                self.additional_attempt_dedup.lock().push(dedup);
            }
            return None;
        }
        *current = attempt.to_string();
        let previous = std::mem::replace(&mut *self.attempt_dedup.lock(), dedup);
        let additional_dedup = std::mem::take(&mut *self.additional_attempt_dedup.lock());
        Some(AttemptDisplacement {
            dedup: previous,
            additional_dedup,
        })
    }

    pub(super) fn retain_current_dedup(&self, token: DedupToken) {
        self.additional_attempt_dedup.lock().push(token);
    }

    /// Install a separately owned replacement attempt.  The correlation is
    /// only a lookup key; ownership is proved by the worker stored here.
    #[cfg(test)]
    pub(super) fn install_speculative(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
    ) -> bool {
        let mut dedup = None;
        self.install_speculative_with_dedup(correlation, session, attempt_lease, &mut dedup)
    }

    pub(super) fn install_speculative_with_dedup(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
        dedup: &mut Option<DedupToken>,
    ) -> bool {
        if self.registry_retired() || self.session.lock().is_none() {
            return false;
        }
        self.install_speculative_after_precheck(correlation, session, attempt_lease, dedup)
    }

    fn install_speculative_after_precheck(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
        dedup: &mut Option<DedupToken>,
    ) -> bool {
        let mut candidates = self.speculative.lock();
        // Retirement sets this flag before waiting for the same slot lock. If
        // insertion won the lock first, retirement drains the new slot after
        // release; if retirement won first, this recheck refuses the insert.
        if self.registry_retired() {
            return false;
        }
        if candidates
            .iter()
            .any(|attempt| Arc::ptr_eq(&attempt.session, &session))
        {
            return false;
        }
        candidates.push(SpeculativeAttempt {
            correlation,
            session,
            endpoint_auth: None,
            authenticated_channel: None,
            dedup: dedup.take(),
            additional_dedup: Vec::new(),
            _attempt_lease: attempt_lease,
        });
        true
    }

    /// Controls only: stage retirement after the optimistic precheck and
    /// before the speculative slot insertion. The production insertion seam
    /// is reused after that staged edge, so the control distinguishes the
    /// slot-locked retirement recheck from the old check-then-insert shape.
    #[cfg(test)]
    pub(super) fn install_speculative_after_retire_race_for_test(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
    ) -> bool {
        if self.registry_retired() || self.session.lock().is_none() {
            return false;
        }
        self.retire_connector();
        let mut dedup = None;
        self.install_speculative_after_precheck(correlation, session, attempt_lease, &mut dedup)
    }

    #[cfg(test)]
    pub(super) fn speculative_resources_empty_for_test(&self) -> bool {
        self.speculative.lock().is_empty()
    }

    #[cfg(test)]
    pub(super) fn speculative_worker_for(
        &self,
        correlation: &str,
    ) -> Option<Arc<WebRtcConnectorWorker>> {
        self.speculative
            .lock()
            .iter()
            .find(|attempt| attempt.correlation == correlation)
            .map(|attempt| Arc::clone(&attempt.session))
    }

    pub(super) fn speculative_workers_for(
        &self,
        correlation: &str,
    ) -> Vec<Arc<WebRtcConnectorWorker>> {
        self.speculative
            .lock()
            .iter()
            .filter(|attempt| attempt.correlation == correlation)
            .map(|attempt| Arc::clone(&attempt.session))
            .collect()
    }

    #[cfg(test)]
    pub(super) fn has_speculative(&self) -> bool {
        !self.speculative.lock().is_empty()
    }

    pub(super) fn speculative_is_exact(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> bool {
        self.speculative.lock().iter().any(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        })
    }

    pub(super) fn speculative_endpoint_auth(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        self.speculative
            .lock()
            .iter()
            .find(|attempt| {
                attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
            })
            .and_then(|attempt| attempt.endpoint_auth.clone())
    }

    /// Remove one failed or superseded candidate.  The promoted worker is not
    /// touched, even when the candidate's carrier correlation is forged.
    pub(super) fn take_speculative_exact(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<SpeculativeRetirement> {
        let mut candidates = self.speculative.lock();
        let index = candidates.iter().position(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        })?;
        let attempt = candidates.swap_remove(index);
        if let Some(task) = attempt.endpoint_auth {
            task.retire();
        }
        let worker = attempt.session;
        self.retain_closing_worker(Arc::clone(&worker));
        Some(SpeculativeRetirement {
            worker,
            dedup: attempt.dedup,
            additional_dedup: attempt.additional_dedup,
        })
    }

    pub(super) fn retain_dedup_for_worker(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        token: DedupToken,
    ) -> bool {
        {
            let mut candidates = self.speculative.lock();
            if let Some(attempt) = candidates.iter_mut().find(|attempt| {
                attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
            }) {
                attempt.additional_dedup.push(token);
                return true;
            }
        }
        self.promoted_session.retain_dedup_for_worker(worker, token)
    }

    pub(super) fn install_speculative_endpoint_auth(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        if self.registry_retired() {
            return false;
        }
        let mut candidates = self.speculative.lock();
        let Some(attempt) = candidates.iter_mut().find(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        }) else {
            return false;
        };
        if !attempt.session.owns_endpoint_auth(&task) || attempt.endpoint_auth.is_some() {
            return false;
        }
        attempt.endpoint_auth = Some(task);
        true
    }

    pub(super) fn install_speculative_authenticated_channel(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
        capability: crate::endpoint_auth::AuthenticatedChannelCapability,
    ) -> bool {
        if self.registry_retired() {
            return false;
        }
        let mut candidates = self.speculative.lock();
        let Some(attempt) = candidates.iter_mut().find(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        }) else {
            return false;
        };
        if attempt
            .endpoint_auth
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, task))
            || attempt.authenticated_channel.is_some()
            || task.is_retired()
            || !capability.belongs_to(task.incarnation())
            || !task.issued(&capability)
        {
            return false;
        }
        attempt.authenticated_channel = Some(capability);
        true
    }

    /// Atomically move an authenticated speculative connector into the
    /// promoted slot.  The caller holds the registry mutation fence, so the
    /// predecessor can be retired after this returns without a device-id
    /// re-resolution race.
    pub(super) fn promote_speculative_if_needed(
        &self,
        correlation: &str,
        candidate: &Arc<WebRtcConnectorWorker>,
        broker: &crate::runtime::session_broker::SessionBroker,
        mesh_context: &str,
        policy_admits: bool,
        select: bool,
    ) -> Option<SpeculativePromotion> {
        if self.registry_retired() || !policy_admits || self.unpromoted_offer_in_flight() {
            return None;
        }
        let (
            candidate,
            connector,
            capability,
            endpoint_auth,
            correlation,
            mut dedup,
            mut additional_dedup,
        ) = {
            let mut candidates = self.speculative.lock();
            let attempt = candidates.iter_mut().find(|attempt| {
                attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, candidate)
            })?;
            let endpoint_auth = attempt.endpoint_auth.as_ref()?.clone();
            if endpoint_auth.is_retired() || !attempt.session.owns_endpoint_auth(&endpoint_auth) {
                return None;
            }
            let connector = attempt.session.live_connector_incarnation().cloned()?;
            let capability = attempt.authenticated_channel.take()?;
            let endpoint_auth = attempt
                .endpoint_auth
                .take()
                .expect("the checked endpoint-auth task remains installed");
            (
                Arc::clone(&attempt.session),
                connector,
                capability,
                endpoint_auth,
                attempt.correlation.clone(),
                attempt.dedup.take(),
                std::mem::take(&mut attempt.additional_dedup),
            )
        };
        let policy = crate::runtime::session_broker::CurrentPolicyAdmission::from_admitted_peer(
            mesh_context,
            &self.device_id,
            true,
        );
        let mut channel = Some(capability);
        let promoted = match broker.promote(&mut channel, &connector, policy) {
            Ok(promoted) => promoted,
            Err(_) => {
                if let Some(capability) = channel {
                    let mut candidates = self.speculative.lock();
                    if let Some(attempt) = candidates
                        .iter_mut()
                        .find(|attempt| Arc::ptr_eq(&attempt.session, &candidate))
                    {
                        attempt.authenticated_channel = Some(capability);
                        attempt.endpoint_auth = Some(endpoint_auth);
                        attempt.dedup = dedup;
                        attempt.additional_dedup = additional_dedup;
                    } else {
                        endpoint_auth.retire();
                    }
                } else {
                    let mut candidates = self.speculative.lock();
                    if let Some(attempt) = candidates
                        .iter_mut()
                        .find(|attempt| Arc::ptr_eq(&attempt.session, &candidate))
                    {
                        attempt.endpoint_auth = Some(endpoint_auth);
                        attempt.dedup = dedup;
                        attempt.additional_dedup = additional_dedup;
                    } else {
                        endpoint_auth.retire();
                    }
                }
                return None;
            }
        };
        let binding = PromotedChannelBinding {
            worker: Arc::clone(&candidate),
            endpoint_auth: Some(Arc::clone(&endpoint_auth)),
            correlation: correlation.clone(),
            dedup: dedup.take(),
            additional_dedup: std::mem::take(&mut additional_dedup),
        };
        if let Err((returned_dedup, returned_additional_dedup)) = self.promoted_session.add_channel(
            promoted,
            candidate.new_session_flows(),
            binding,
            select,
        ) {
            endpoint_auth.retire();
            candidate.retire();
            // Leave the exact attempt in the speculative slot. The command
            // consumer will run the normal exact terminal cleanup, which
            // retains the token long enough for the caller to release only
            // this candidate's dedup record.
            dedup = returned_dedup;
            additional_dedup = returned_additional_dedup;
            if let Some(attempt) = self
                .speculative
                .lock()
                .iter_mut()
                .find(|attempt| Arc::ptr_eq(&attempt.session, &candidate))
            {
                attempt.dedup = dedup;
                attempt.additional_dedup = additional_dedup;
            }
            return None;
        }
        if select {
            self.session.lock().replace(Arc::clone(&candidate));
            self.endpoint_auth.lock().replace(endpoint_auth);
        }
        let displaced_attempt = if select {
            let mut attempt = self.attempt.write();
            if *attempt == correlation {
                None
            } else {
                *attempt = correlation.clone();
                let dedup = self.attempt_dedup.lock().take();
                let additional_dedup = std::mem::take(&mut *self.additional_attempt_dedup.lock());
                Some(AttemptDisplacement {
                    dedup,
                    additional_dedup,
                })
            }
        } else {
            None
        };
        if select && displaced_attempt.is_some() {
            self.attempt_dedup.lock().take();
            self.additional_attempt_dedup.lock().clear();
        }
        let mut candidates = self.speculative.lock();
        if let Some(index) = candidates.iter().position(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, &candidate)
        }) {
            drop(candidates.swap_remove(index));
        }
        Some(SpeculativePromotion {
            displaced_attempt,
            selected: select,
        })
    }

    pub(super) fn new(device_id: String, session: Option<Arc<WebRtcConnectorWorker>>) -> Self {
        Self {
            device_id,
            state: RwLock::new(PeerStateData::default()),
            session: Mutex::new(session),
            speculative: Mutex::new(Vec::new()),
            closing_workers: Mutex::new(Vec::new()),
            retired_dedup: Mutex::new(Vec::new()),
            signaling_runtime: RwLock::new(None),
            media_renegotiation_workers: Mutex::new(Vec::new()),
            endpoint_auth: Mutex::new(None),
            authenticated_channel: Mutex::new(None),
            attempt: RwLock::new(mint_attempt()),
            attempt_dedup: Mutex::new(None),
            additional_attempt_dedup: Mutex::new(Vec::new()),
            promoted_session: crate::runtime::peer_session::PromotedSessionSlot::new(),
            registry_retired: AtomicBool::new(false),
            epoch: DIAGNOSTIC_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            unpromoted_offer_in_flight: AtomicBool::new(false),
        }
    }

    pub(super) fn begin_unpromoted_negotiation(&self) -> bool {
        if self.registry_retired() || self.holds_promoted_session() {
            return false;
        }
        if self
            .unpromoted_offer_in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        if self.session.lock().is_none() {
            self.unpromoted_offer_in_flight
                .store(false, Ordering::Release);
            return false;
        }
        true
    }

    pub(super) fn unpromoted_offer_in_flight(&self) -> bool {
        self.unpromoted_offer_in_flight.load(Ordering::Acquire)
    }

    /// Return a clonable diagnostic view without copying mutable ownership.
    ///
    /// The advertisement is read through the live session first and bound to a
    /// local, **before** the state guard is taken. That order is required, not
    /// stylistic: the lender runs promotion, which holds `promoted_session`
    /// while re-reading `state`, so taking `state` first and the session second
    /// would close a lock cycle. A peer with no current session reports `None`,
    /// which is the truthful answer — nothing has been advertised over a session
    /// that does not exist.
    pub fn snapshot(&self) -> PeerStateSnapshot {
        self.with_peer_view(|view| {
            let capabilities = view.session.and_then(|app| app.capabilities());
            view.data.snapshot(capabilities)
        })
    }

    /// Lend this peer's session record and state data as **one** observation.
    ///
    /// This is the fence the snapshot paths were missing. The shape it replaces
    /// read the advertisement through the session lender, released that guard,
    /// and *then* took `state` — two observations stitched together, so a
    /// snapshot could pair one session's advert with state written after that
    /// session had already been replaced.
    ///
    /// Here the state guard is taken **inside** the session lender, so both are
    /// held together for the closure's whole life. That is the documented order
    /// and not a new one: the lender's own liveness predicate already takes
    /// `state.read()` while holding `promoted_session` (see
    /// [`Self::session_is_current`]), and no writer in this crate takes
    /// `state.write()` while holding the slot. Reversing it — state first, then
    /// the session — is the direction that closes a cycle, and it is what
    /// [`Self::with_live_session`]'s warning forbids.
    ///
    /// A peer with no current session yields `None` for the session half rather
    /// than being skipped. That is the truthful answer and it is why this cannot
    /// be written as a plain `Option` chain: an unpromoted peer still has state
    /// worth reporting, and it must be reported from the same read.
    ///
    /// **The closure must not re-enter the registry, the session lender, or the
    /// provider.** Two locks are held for its duration, and provider
    /// acquisition under them is exactly the reentrancy the resource discipline
    /// forbids. Callers measure and copy here; they acquire elsewhere.
    pub(super) fn with_peer_view<R>(&self, view: impl FnOnce(PeerView<'_>) -> R) -> R {
        // Moved through an `Option` because it is `FnOnce` and there are two
        // exits — a live session and none — and a closure cannot be called on
        // both paths.
        let mut view = Some(view);
        let seen = self.with_live_session_state(|_session, app| {
            let data = self.state.read();
            (view.take().expect("the peer view runs exactly once"))(PeerView {
                device_id: &self.device_id,
                data: &data,
                session: Some(app),
            })
        });
        match seen {
            Some(result) => result,
            None => {
                let data = self.state.read();
                (view.take().expect("the peer view runs exactly once"))(PeerView {
                    device_id: &self.device_id,
                    data: &data,
                    session: None,
                })
            }
        }
    }

    /// Retire the exact connector worker owned by this registry entry.
    /// External `Arc` holders cannot keep callbacks or queued candidates live.
    pub(crate) fn retire_connector(&self) {
        self.registry_retired.store(true, Ordering::Release);
        // Replacement invalidation is a security control, not housekeeping:
        // because the certificate-fingerprint binding is not session-unique,
        // exact connector ownership is what distinguishes this channel from
        // another between the same pair. A capability authenticated under the
        // retired connector must not survive into its replacement.
        drop(self.authenticated_channel.lock().take());
        // The promoted session carries that same channel's authority, so it is
        // dropped on the same edge. Dropping it also releases its
        // post-authentication resource reservation, so a retired connector does
        // not hold session capacity its replacement then has to compete for.
        let mut workers = self.promoted_session.take_workers_with_dedup();
        // Retire the endpoint-auth task at the source, so a superseded
        // connector refuses promotion rather than merely failing to install
        // afterwards. Without this the task stays live with its handoff
        // intact, `belongs_to` still answers true, and a late AuthResponse can
        // still mint a capability — one that install would reject, but only
        // after the fact. Retiring here makes `authenticate` fail closed with
        // `ChannelNotCurrent`.
        if let Some(task) = self.endpoint_auth.lock().as_ref() {
            task.retire();
        }
        for attempt in self.speculative.lock().drain(..) {
            if let Some(task) = attempt.endpoint_auth {
                task.retire();
            }
            attempt.session.retire();
            if let Some(dedup) = attempt.dedup {
                self.retired_dedup.lock().push(dedup);
            }
            self.retired_dedup.lock().extend(attempt.additional_dedup);
            workers.push((attempt.session, None, Vec::new()));
        }
        let worker = self.session.lock().take();
        if let Some(worker) = worker {
            worker.retire();
            workers.push((
                worker,
                self.attempt_dedup.lock().take(),
                std::mem::take(&mut *self.additional_attempt_dedup.lock()),
            ));
        }
        for (worker, dedup, additional_dedup) in workers {
            if let Some(dedup) = dedup {
                self.retired_dedup.lock().push(dedup);
            }
            self.retired_dedup.lock().extend(additional_dedup);
            self.retain_closing_worker(worker);
        }
    }

    pub(super) fn take_retired_dedup(&self) -> Vec<DedupToken> {
        std::mem::take(&mut *self.retired_dedup.lock())
    }

    /// Fence the exact connector, await its single native cleanup owner, then
    /// release Endpoint Auth Task's connected-channel claim.
    pub(super) async fn retire_and_close(&self) -> crate::Result<()> {
        self.retire_connector();
        let result = self.await_retired_workers().await;
        drop(self.authenticated_channel.lock().take());
        self.promoted_session.clear();
        drop(self.endpoint_auth.lock().take());
        result
    }

    /// Await every worker this peer already retired without retiring the live
    /// logical session. Candidate refusal uses this in controls to prove the
    /// native owners really settled; full peer teardown calls it after first
    /// moving every remaining worker into the same list.
    pub(super) async fn await_retired_workers(&self) -> crate::Result<()> {
        let mut result = Ok(());
        loop {
            let workers = self.closing_workers.lock().clone();
            if workers.is_empty() {
                return result;
            }
            let outcomes =
                futures::future::join_all(workers.into_iter().map(|worker| async move {
                    let outcome = worker.retire_and_close().await;
                    (worker, outcome)
                }))
                .await;
            for (worker, outcome) in outcomes {
                if let Err(error) = outcome {
                    if result.is_ok() {
                        result = Err(error);
                    }
                }
                let mut closing = self.closing_workers.lock();
                if let Some(index) = closing
                    .iter()
                    .position(|current| Arc::ptr_eq(current, &worker))
                {
                    drop(closing.swap_remove(index));
                }
            }
        }
    }

    /// Remove and await one exact candidate retired by a registry operation.
    ///
    /// Candidate failure is a terminal edge, not peer teardown: retaining the
    /// worker in `closing_workers` until the peer dies would pin its native
    /// close owner and its provider claim for the peer's whole lifetime. The
    /// registry only returns exact workers, and this method runs after that
    /// fence has been released, so the native await never occurs under a
    /// registry or candidate lock. A missing worker is stale and is left alone.
    pub(super) async fn await_exact_retired_worker(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<crate::Result<()>> {
        if !self
            .closing_workers
            .lock()
            .iter()
            .any(|current| Arc::ptr_eq(current, worker))
        {
            return None;
        }
        // Keep exact custody visible until the native await completes. A
        // concurrent shutdown may take the same Arc from the closing set and
        // await its idempotent native close; it must never lose sight of a
        // close merely because a candidate path started waiting first.
        let result = worker.retire_and_close().await;
        let mut closing = self.closing_workers.lock();
        if let Some(index) = closing
            .iter()
            .position(|current| Arc::ptr_eq(current, worker))
        {
            drop(closing.swap_remove(index));
        }
        Some(result)
    }

    #[cfg(test)]
    pub(super) fn retired_worker_count_for_test(&self) -> usize {
        self.closing_workers.lock().len()
    }

    pub(super) fn registry_retired(&self) -> bool {
        self.registry_retired.load(Ordering::Acquire)
    }

    pub(super) fn install_endpoint_auth(
        &self,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        let exact_connector = self
            .session
            .lock()
            .as_ref()
            .is_some_and(|worker| worker.owns_endpoint_auth(&task));
        if !exact_connector {
            return false;
        }
        let mut current = self.endpoint_auth.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(task);
        true
    }

    pub(super) fn endpoint_auth_is_current(
        &self,
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        self.endpoint_auth
            .lock()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, task))
    }

    /// The current endpoint-auth task, if this entry still owns one.
    pub(super) fn endpoint_auth_task(&self) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        (!self.registry_retired()).then(|| self.endpoint_auth.lock().clone())?
    }

    pub(super) fn endpoint_auth_task_for(
        &self,
        worker: Option<&Arc<WebRtcConnectorWorker>>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        if self.registry_retired() {
            return None;
        }
        let Some(worker) = worker else {
            return self.endpoint_auth_task();
        };
        self.promoted_session.endpoint_auth_for(worker).or_else(|| {
            self.session
                .lock()
                .as_ref()
                .filter(|current| Arc::ptr_eq(current, worker))
                .and_then(|_| self.endpoint_auth.lock().clone())
        })
    }

    pub(super) fn attempt_for_worker(&self, worker: &Arc<WebRtcConnectorWorker>) -> Option<String> {
        self.promoted_session.correlation_for(worker).or_else(|| {
            self.session
                .lock()
                .as_ref()
                .filter(|current| Arc::ptr_eq(current, worker))
                .map(|_| self.attempt())
        })
    }

    pub(super) fn owns_authenticated_worker(&self, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        !self.registry_retired()
            && (self.promoted_session.contains_worker(worker)
                || self
                    .session
                    .lock()
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, worker)))
    }

    pub(super) fn mark_media_renegotiation(&self, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        if !self.owns_authenticated_worker(worker) {
            return false;
        }
        let mut pending = self.media_renegotiation_workers.lock();
        if !pending.iter().any(|current| Arc::ptr_eq(current, worker)) {
            pending.push(Arc::clone(worker));
        }
        true
    }

    pub(super) fn media_renegotiation_worker(&self) -> Option<Arc<WebRtcConnectorWorker>> {
        self.media_renegotiation_workers.lock().first().cloned()
    }

    pub(super) fn clear_media_renegotiation_worker(&self, worker: &Arc<WebRtcConnectorWorker>) {
        let mut pending = self.media_renegotiation_workers.lock();
        if let Some(index) = pending
            .iter()
            .position(|current| Arc::ptr_eq(current, worker))
        {
            drop(pending.swap_remove(index));
        }
    }

    pub(super) fn has_pending_media_renegotiation(&self) -> bool {
        !self.media_renegotiation_workers.lock().is_empty()
    }

    pub(super) fn retire_authenticated_worker(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<crate::runtime::peer_session::RemovedPromotedChannel> {
        let removed = self.promoted_session.remove_channel(worker)?;
        self.clear_media_renegotiation_worker(worker);
        self.retain_closing_worker(Arc::clone(&removed.worker));
        if let Some(selected) = removed.selected_worker.as_ref() {
            self.session.lock().replace(Arc::clone(selected));
            if let Some(task) = self.promoted_session.endpoint_auth_for(selected) {
                self.endpoint_auth.lock().replace(task);
            }
            if let Some(correlation) = removed.selected_correlation.as_ref() {
                *self.attempt.write() = correlation.clone();
            }
            self.attempt_dedup.lock().take();
            self.additional_attempt_dedup.lock().clear();
        } else {
            drop(self.session.lock().take());
            drop(self.endpoint_auth.lock().take());
            self.attempt_dedup.lock().take();
            self.additional_attempt_dedup.lock().clear();
        }
        Some(removed)
    }

    pub(super) fn take_attempt_displacement(&self) -> AttemptDisplacement {
        AttemptDisplacement {
            dedup: self.attempt_dedup.lock().take(),
            additional_dedup: std::mem::take(&mut *self.additional_attempt_dedup.lock()),
        }
    }

    pub(super) fn take_current_dedups(&self) -> Vec<DedupToken> {
        let mut tokens = std::mem::take(&mut *self.additional_attempt_dedup.lock());
        if let Some(token) = self.attempt_dedup.lock().take() {
            tokens.push(token);
        }
        tokens
    }

    /// Build an entry that already holds `task` as its current endpoint-auth
    /// task, without a connector worker.
    ///
    /// The worker check in [`Self::install_endpoint_auth`] is deliberately
    /// bypassed: it is not what this seam exists to exercise. Controls use it
    /// to drive the real [`Self::install_authenticated_channel`] — including
    /// its capability/incarnation binding — against tasks built from genuine
    /// connector fixtures, which live in the transport module's test tree.
    #[cfg(test)]
    pub(crate) fn with_endpoint_auth_for_test(
        device_id: String,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> Self {
        let peer = Self::new(device_id, None);
        *peer.endpoint_auth.lock() = Some(task);
        peer
    }

    /// Install the authenticated-channel capability produced by `task`.
    ///
    /// Refused unless `task` is still this entry's current endpoint-auth task,
    /// is not retired, and the entry has not been retired — so a capability
    /// cannot be installed against a channel that has already been replaced.
    /// Refused a second time, so one channel yields at most one installed
    /// capability. Also refused unless the capability was promoted from that
    /// same connector incarnation.
    pub(crate) fn install_authenticated_channel(
        &self,
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
        capability: crate::endpoint_auth::AuthenticatedChannelCapability,
    ) -> bool {
        let mut current = self.authenticated_channel.lock();
        if current.is_some() {
            return false;
        }
        // Rechecked *under* the slot lock, not before taking it. Checking
        // first would leave a window in which `retire_connector` sets retired,
        // takes an empty slot, and returns — after which this call would write
        // a capability into an already-invalidated entry, surviving the very
        // replacement invalidation it is supposed to obey. With the recheck
        // here, retirement either lands before it (and is seen) or blocks on
        // this same lock and takes the capability we just installed.
        // `is_retired` is checked explicitly: a task can be retired between
        // `authenticate` returning and this install, and it stays in the slot
        // when that happens, so slot identity alone would not notice.
        if self.registry_retired() || task.is_retired() || !self.endpoint_auth_is_current(task) {
            return false;
        }
        // The capability must have been promoted from *this* task's connector
        // incarnation. Checking only that `task` is current would accept a
        // capability promoted from a superseded channel whenever the caller
        // supplied the current task alongside it — a cross-channel relay the
        // certificate-fingerprint binding cannot rule out by itself.
        if !capability.belongs_to(task.incarnation()) {
            return false;
        }
        // And it must carry *this* task's authenticated context. The answer
        // comes from the capability's own private record — mesh, local and
        // remote Device, profile, and connector — not from anything the caller
        // supplied, so a capability authenticated for another mesh or another
        // peer is refused here even when the current task is handed in with it.
        if !task.issued(&capability) {
            return false;
        }
        *current = Some(capability);
        true
    }

    /// Install a real authenticated capability, bypassing only provenance.
    ///
    /// For call-site tests that need to exercise the inbound / send / reliable
    /// wiring rather than the promotion path. The capability installed here is
    /// a genuine [`crate::endpoint_auth::AuthenticatedChannelCapability`], so
    /// the gate is satisfied the same way production satisfies it — what is
    /// skipped is only the connector-provenance check, which is proven
    /// separately by the transport controls. This is deliberately not a way to
    /// make [`Self::has_authenticated_channel`] answer `true` without a
    /// capability present.
    #[cfg(test)]
    pub(crate) fn install_authenticated_channel_for_test(&self) {
        *self.authenticated_channel.lock() = Some(crate::endpoint_auth::authenticated_for_test(
            crate::runtime::runtime_for_test(),
        ));
    }

    /// Install a real authenticated capability **for this entry's own live
    /// connector**, in this Mesh's own context.
    ///
    /// The difference from [`Self::install_authenticated_channel_for_test`] is
    /// the whole point: that one installs a capability bound to a fixture
    /// connector, a fixture runtime, and a fixture context, which satisfies
    /// `has_authenticated_channel` but can never promote — `promote` compares
    /// the connector by pointer identity and the runtime by incarnation, and
    /// `is_current_for` re-proves the mesh context and remote Device at every
    /// use. A control that needs a *promoted session* therefore needs this
    /// form, which takes the handoff the peer's own connector produced and
    /// names this Mesh and this peer.
    ///
    /// Provenance is still the only thing skipped: no exchange ran, so the
    /// task-issued path is bypassed exactly as above. Every conjunct promotion
    /// actually evaluates is real, so promotion can still refuse — and does,
    /// for a retired connector, an unadmitted peer, a foreign context, or
    /// exhausted session capacity.
    ///
    /// `handoff` is moved: it carries the connected claim's retention
    /// obligation, so a capability built from it and then dropped returns that
    /// claim through the connector's own close owner rather than releasing it
    /// early.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn install_authenticated_channel_over_for_test(
        &self,
        handoff: crate::connector::ConnectedChannelHandoff,
        mesh_context: &str,
        local_device_id: &str,
    ) {
        let capability = crate::endpoint_auth::authenticated_over_for_test(
            handoff,
            mesh_context,
            local_device_id,
            &self.device_id,
        );
        *self.authenticated_channel.lock() = Some(capability);
    }

    /// Whether a promoted `SessionCapability` is installed on this entry.
    ///
    /// Observation only: it cannot lend one, clone one, or revive one, and it
    /// answers nothing about whether that session would still be admitted.
    /// Controls need it to separate "the fence refused and dropped the session"
    /// from "the fence refused and left it installed" — which is the whole
    /// difference between a revocation that takes effect and one that merely
    /// declines the next call while the authority stays alive behind it.
    ///
    /// **This is also what "a live session" means, and the booleans it replaces
    /// were not it.** `authenticated && data_channel_open` describes the transport
    /// underneath a session; promotion is the session. Two owners now read this
    /// rather than those booleans: graceful departure, which may only depart a
    /// session that exists, and the carrier-withdrawal arm, which may not retire
    /// one. A channel that has closed while recovery or replacement is in
    /// progress leaves the promoted session installed, and that is the whole
    /// point - the connector and the Peer Session own that state, not signaling.
    ///
    /// Production, and there is no counterfeit. Only a real connector promotes,
    /// which is why every control that needs the true case lives behind
    /// `transport-lab`; a control that wanted to fake one would be asserting
    /// against a session the product cannot produce.
    pub(crate) fn holds_promoted_session(&self) -> bool {
        self.promoted_session.is_installed()
    }

    pub(super) fn promoted_channel_count(&self) -> usize {
        self.promoted_session.channel_count()
    }

    /// Promote this entry's authenticated channel into a live session, once.
    ///
    /// Called only from inside the registry mutation lock, which is what makes
    /// the policy conjunct true of *this installation* rather than of a device
    /// id a replacement may have taken over. It takes no registry lock itself.
    ///
    /// Idempotent by construction: a session already promoted for the live
    /// connector is reused, so one channel yields at most one session and one
    /// resource reservation. A cached session that no longer names the live
    /// connector is dropped rather than returned — that is the replacement
    /// invalidation, applied at use.
    ///
    /// The capability is never taken out of its slot here. The slot is lent to
    /// the broker, which borrows the channel for every fallible step and moves
    /// it out only after the post-authentication reservation succeeds. A
    /// capacity refusal therefore leaves the exact channel installed, and the
    /// next operation retries it; a terminal refusal — superseded connector,
    /// refused policy, runtime disagreement — empties the slot inside the
    /// broker, because a capability whose own record does not match this entry's
    /// context is one this entry must not keep.
    ///
    /// **Lock order: `session`, then `promoted_session`, then
    /// `authenticated_channel`.** This is the only method that nests any of
    /// them, and it is the reason the order exists at all: it holds
    /// `promoted_session` across the capability take, because installing a
    /// session and consuming the channel it was promoted from must be one step.
    /// The worker is therefore cloned out of `session` and that guard released
    /// *before* `promoted_session` is taken. Acquiring them the other way round
    /// here — with `promoted_session` held while `session` is locked — is what
    /// would close a cycle against [`Self::with_live_session_flow_and_worker`],
    /// which reads `session` first on its way to the same pair.
    ///
    /// Reading the worker a moment early costs nothing: a connector that
    /// retires in the gap fails the `is_current_for` recheck below, or the
    /// `is_active` proof before promotion, or — for a session installed against
    /// a connector that retired immediately after — the `belongs_to` check at
    /// the next use. Every one of those refuses rather than admits.
    pub(super) fn promote_session_if_needed(
        &self,
        broker: &crate::runtime::session_broker::SessionBroker,
        mesh_context: &str,
        policy_admits: bool,
    ) -> Promotion {
        // An inbound legacy Offer holds this exact-owner witness across its
        // awaited SDP application, attempt adoption, and answer creation.
        // Refuse promotion for that same installation until the complete Offer
        // mutation has finished; otherwise the later answer-side effect could
        // run against a session promoted after the Offer's initial check.
        if self.unpromoted_offer_in_flight() {
            return Promotion::Refused;
        }
        let worker = self.session.lock().clone();
        let live_connector = worker
            .as_ref()
            .and_then(|worker| worker.live_connector_incarnation().cloned());
        // The use-time recheck, not merely a currentness test: current policy,
        // connector, mesh context, remote Device, principal and reservation
        // runtime are all re-proved against the session's own record before it
        // authorizes anything.
        //
        // Policy belongs in that conjunction and not only on the promotion path
        // below. Admission is *retained* state: an eviction, a denial or a
        // topology change revokes it long after promotion, and a session
        // promoted while it held would otherwise never be asked again — every
        // operation this fence admits would keep running for a peer the mesh has
        // since refused.
        match self.promoted_session.reuse_or_revoke(|session| {
            policy_admits
                && live_connector.as_ref().is_some_and(|connector| {
                    session.is_current_for(
                        connector,
                        mesh_context,
                        &self.device_id,
                        broker.runtime(),
                    )
                })
        }) {
            crate::runtime::peer_session::Reuse::Current => return Promotion::Current,
            // Refused outright rather than re-promoted. Promoting again here
            // would take a fresh post-authentication reservation for authority
            // that was just withdrawn, on the same call that observed the
            // withdrawal.
            crate::runtime::peer_session::Reuse::Revoked => return Promotion::Refused,
            crate::runtime::peer_session::Reuse::Vacant => {}
        }

        if self.registry_retired() || !policy_admits {
            return Promotion::Refused;
        }
        let (Some(connector), Some(worker)) = (live_connector, worker) else {
            return Promotion::Refused;
        };
        // Re-proved under `promoted_session`, because the incarnation was read
        // before that guard was taken. This is the narrow window the lock order
        // opens, and closing it here means a connector that retired in the gap
        // costs a refused promotion rather than a session installed against a
        // connector that is already gone. Asked of the worker, which is where
        // the adapter's retirement state lives — the incarnation itself is an
        // identity token and answers no liveness question.
        if worker.live_connector_incarnation().is_none() {
            return Promotion::Refused;
        }
        let policy = crate::runtime::session_broker::CurrentPolicyAdmission::from_admitted_peer(
            mesh_context,
            &self.device_id,
            true,
        );
        // The slot is lent to the broker, not its contents. The channel is
        // borrowed for every fallible step and moved out only once the
        // post-authentication reservation has been taken, so a capacity refusal
        // leaves this entry's exact authenticated channel installed and the next
        // application operation retries that same proven channel. The terminal
        // refusals — superseded connector, refused policy, runtime disagreement —
        // still empty the slot, inside the broker, where the decision is made.
        let promotion = {
            let mut channel = self.authenticated_channel.lock();
            broker.promote(&mut channel, &connector, policy)
        };
        match promotion {
            Ok(session) => {
                // The flow set is built by the exact worker this session was
                // promoted from, so its registry and the session's connector are
                // the same one by construction rather than by a later check.
                // Real Endpoint Auth always leaves its exact task here. The
                // optional form is reserved for the transport-lab helper that
                // installs a real capability directly and therefore has no
                // task to counterfeit merely to exercise this admission seam.
                let endpoint_auth = self.endpoint_auth.lock().clone();
                self.promoted_session.install(
                    session,
                    worker.new_session_flows(),
                    PromotedChannelBinding {
                        worker: Arc::clone(&worker),
                        endpoint_auth,
                        correlation: self.attempt(),
                        dedup: self.attempt_dedup.lock().take(),
                        additional_dedup: std::mem::take(
                            &mut *self.additional_attempt_dedup.lock(),
                        ),
                    },
                );
                Promotion::NewlyPromoted
            }
            // Includes the capacity refusal, which is not terminal: the exact
            // authenticated channel is still installed, so the next application
            // operation retries it and *that* promotion is the newly promoted
            // one. Nothing is announced for an attempt that minted no session.
            Err(_) => Promotion::Refused,
        }
    }

    /// Run one effect against this entry's live promoted session.
    ///
    /// The session is lent, never handed out: it is not `Clone`, and the borrow
    /// ends with the closure, so a caller cannot retain application authority
    /// past the fence that authorized it.
    /// Lend this entry's live session together with a **freshly acquired** live
    /// connector incarnation.
    ///
    /// The freshness is the whole point and it is structural, not a convention:
    /// the incarnation handed to `effect` is obtained from the current worker on
    /// this call, and `live_connector_incarnation` yields `None` once that
    /// connector is retired. A caller therefore cannot reach the closure with a
    /// stale identity, and cannot substitute one — it does not supply the
    /// argument, this does.
    ///
    /// That distinction matters because a retained `Arc<ConnectorIncarnation>`
    /// stays pointer-equal to itself forever. Validating a flow against the
    /// `Arc` it stored at open time proves only that the flow is the flow; it
    /// says nothing about whether the connector is still alive, so a retired
    /// peer would keep passing its own gate. Every flow operation must compare
    /// against an incarnation acquired now, which is what this hands out.
    ///
    /// The session is re-checked against that fresh identity before the effect
    /// runs, so a session promoted from a superseded connector yields `None`
    /// rather than an operation.
    /// Lend this entry's live session, and nothing else.
    ///
    /// The same fence as [`Self::with_live_session_flow`] — current worker, a
    /// freshly acquired live incarnation, a promoted session that belongs to it —
    /// projected down to the authority alone. An operation that needs to prove a
    /// session authorized it, but has no business touching the realtime flow set,
    /// asks for this: lending the flow set to a caller that only needed the proof
    /// would hand out a mutable namespace as a side effect of authorization.
    ///
    /// **Do not call this while holding a [`PeerStateData`] guard.** The lender
    /// runs promotion, and promotion holds `promoted_session` while it re-reads
    /// `state` for the retained-policy conjunct; entering here from inside a
    /// `state` guard closes a cycle in the opposite direction. Bind the result
    /// first, then take the guard.
    pub(super) fn with_live_session<R>(
        &self,
        effect: impl FnOnce(&crate::runtime::session_broker::SessionCapability) -> R,
    ) -> Option<R> {
        self.with_live_session_flow_and_worker(|session, _flows, _live, _worker| effect(session))
    }

    /// Lend this entry's live session together with the application state that
    /// session owns.
    ///
    /// The same fence again, projected to the pair that belongs to the
    /// application side: the authority, and the record whose lifetime *is* that
    /// authority's. Nothing here can outlive the session, because the borrow ends
    /// with the closure and the record is a field of the thing being borrowed
    /// from.
    ///
    /// Carries [`Self::with_live_session`]'s lock-order warning unchanged.
    pub(super) fn with_live_session_state<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        let worker = self.session.lock().clone()?;
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live(
            |session| self.session_is_current(session, &live),
            |bundle| {
                let (session, app) = bundle.app_mut();
                effect(session, app)
            },
        )
    }

    pub(super) fn with_live_session_flow<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> R,
    ) -> Option<R> {
        self.with_live_session_flow_and_worker(|session, flows, live, _worker| {
            effect(session, flows, live)
        })
    }

    /// The same fence, additionally lending the connector worker.
    ///
    /// The one body both forms share, so the currency rule is stated once: two
    /// copies of a fence are two things that can drift, and the one that drifts
    /// is the one nobody is reading.
    ///
    /// The worker is lent for the operations that must reach the *native*
    /// connector — creating a transceiver or a track — which cannot happen
    /// under this lock because they await. A caller clones the handle out,
    /// releases the lock, does the async work, and re-enters to commit. The
    /// handle is not authority: it grants nothing this fence has not already
    /// proved, and re-entering proves it again rather than trusting the clone.
    pub(super) fn with_live_session_flow_and_worker<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        let worker = self.session.lock().clone()?;
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live(
            |session| self.session_is_current(session, &live),
            |bundle| {
                let (session, flows, channel_worker) = bundle.flows_mut();
                if !Arc::ptr_eq(channel_worker, &worker) {
                    return None;
                }
                Some(effect(session, flows, &live, &worker))
            },
        )?
    }

    pub(super) fn with_live_session_flow_and_exact_worker<R>(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live_worker(
            worker,
            |session| session.belongs_to(&live),
            |session, flows, channel_worker| effect(session, flows, &live, channel_worker),
        )
    }

    pub(super) fn with_live_session_flow_and_exact_worker_with_correlation<R>(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<WebRtcConnectorWorker>,
            &str,
        ) -> R,
    ) -> Option<R> {
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live_worker_and_correlation(
            worker,
            |session| session.belongs_to(&live),
            |session, flows, channel_worker, correlation| {
                effect(session, flows, &live, channel_worker, correlation)
            },
        )
    }

    /// Both use-time conjuncts, evaluated under the session slot's own guard.
    ///
    /// The connector half is identity — a session promoted from a superseded
    /// connector is not this connector's. `is_admitted` is retained
    /// handshake/topology state, not a live governance read. Governance changes
    /// become authoritative at the registry's synchronous commit seam, which
    /// clears the promoted slot and invalidates effect-begin witnesses before
    /// later effects can start.
    ///
    /// Lock order is preserved: the slot evaluates this with its own guard held
    /// and `state` is taken inside a single statement, which is the order
    /// [`Self::promote_session_if_needed`] already establishes.
    fn session_is_current(
        &self,
        session: &crate::runtime::session_broker::SessionCapability,
        live: &Arc<crate::connector::ConnectorIncarnation>,
    ) -> bool {
        session.belongs_to(live)
    }

    /// Whether this entry holds a live authenticated channel for its exact
    /// current connector.
    ///
    /// This is the provenance-carrying counterpart to
    /// `PeerStateData::authenticated`: a retired entry answers `false` even if
    /// the legacy bool is still set.
    /// The two slots are read **one at a time, never nested**, and that is a
    /// correctness requirement rather than a style choice.
    ///
    /// This entry's lock order is `session` → `promoted_session` →
    /// `authenticated_channel`, and [`Self::promote_session_if_needed`] is the
    /// only method that nests any of them. It holds `promoted_session` while it
    /// takes `authenticated_channel`, so reading those two here in the opposite
    /// order — which is what a single `||` tail expression would do, the first
    /// operand's guard still alive when the second lock is reached — closes a
    /// cycle against promotion running concurrently on another peer's task. The
    /// `let` binding is what ends the first guard's temporary scope before the
    /// second lock is taken.
    ///
    /// Every other acquisition on this entry, here and elsewhere, takes exactly
    /// one of these locks per statement and releases it before the next, so no
    /// other pair can be held at once in either direction.
    pub(crate) fn has_authenticated_channel(&self) -> bool {
        if self.registry_retired() {
            return false;
        }
        // Either slot counts. Promotion *moves* the capability into the session,
        // so once a session exists the capability slot is empty and reading it
        // alone would report a promoted peer as unauthenticated — which would
        // un-admit the very peer that just satisfied every conjunct.
        let holds_capability = self.authenticated_channel.lock().is_some();
        if holds_capability {
            return true;
        }
        self.promoted_session.is_installed()
    }
}

/// Mint one attempt correlation.
///
/// Random rather than a counter: a counter would be a process-visible ordering,
/// and this must not order anything. Base32 of eight random bytes, which is the
/// same shape the carrier translations used to mint individually and short
/// enough to ride every candidate without being a payload.
fn mint_attempt() -> String {
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}
