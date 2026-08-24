//! Concrete Nostr signaling driver. Connects to N relays in
//! parallel, publishes ephemeral signaling events tagged with
//! the room handle, subscribes to inbound events on the same
//! tag, and routes them back to the caller via mpsc channels.
//!
//! Resilience features baked in (see `crate::upstream`):
//!
//! - The subscription REQ is re-sent on every fresh socket, and the
//!   per-socket reconnect backoff (2 → 60 s, jittered) is the single
//!   anti-flood pace for a flapping relay.
//! - Transition-only logging — no per-event spam.
//! - Directed negotiation (offer / answer / candidate) is tagged with
//!   its recipient (`["p", device_id]`) and the subscription asks for
//!   "presence + directed-to-me", so the relay never fans a pairwise
//!   negotiation to the whole room (see `desired_filters`).
//!
//! The driver is independent of the engine; the
//! [`crate::SignalingChannel`] trait is the seam.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::{Sink, SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, trace, warn};

use super::delivery::{
    DeliveryProvider, DeliveryStore, DeliveryTerminal, RelaySessionId, UnmeteredDeliveryProvider,
};
use super::event::{
    make_event, now_secs, NostrEvent, NostrIdentity, SIGNALING_EPHEMERAL_KIND, SIGNALING_EVENT_KIND,
};
use super::handle::derive_room_handle;
use super::shuffle::select_top_n;
use crate::upstream::{ANNOUNCE_BACKOFF_MS, ANNOUNCE_STEADY_MS, PRESENCE_REPLAY_WINDOW_SECS};
use crate::{
    AttemptOutcome, AttemptOutcomeSink, AttemptRefusal, AttemptRefusalSink, CarrierAttribution,
    ErasedOwner, ErasedSource, InboundSink, OutboundSource, SignalingMessage,
};

struct UnmeteredAttemptRefusalSink;

impl AttemptRefusalSink for UnmeteredAttemptRefusalSink {
    fn refused(&self, _refusal: AttemptRefusal) {}
}

struct UnmeteredAttemptOutcomeSink;

impl AttemptOutcomeSink for UnmeteredAttemptOutcomeSink {
    fn outcome(&self, _outcome: AttemptOutcome) {}
}

/// Configuration for one driver instance.
#[derive(Debug, Clone)]
pub struct NostrDriverConfig {
    /// App-id used in the room-handle derivation. Forks pick
    /// their own here to isolate from upstream.
    pub app_id: String,
    /// Network id (the user-facing identifier; not the room
    /// handle — we derive that from `(app_id, network_id)`).
    pub network_id: String,
    /// Our peer's wire-level device id (the ed25519 pubkey
    /// surfaced by the mesh layer).
    pub device_id: String,
    /// User-supplied relay URLs. Empty = use built-in defaults.
    pub servers: Vec<String>,
    /// Hostnames excluded from the shuffle.
    pub denylist: Vec<String>,
    /// Top-N relays to maintain.
    pub redundancy: usize,
    /// Fall back to the built-in public relays when every primary relay is
    /// unreachable. On by default; the fallback is reactive (only while
    /// the primary set is down) so steady state stays on your own relays.
    pub public_fallback: bool,
}

/// Inbound signaling events the driver pushes to the engine.
#[derive(Debug, Clone)]
pub enum NostrInbound {
    /// A peer announced their presence in the room.
    PeerAnnounced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer's signaling connection dropped, as far as the room can tell.
    ///
    /// **`SenderClaimed`, and that is the whole of what it is worth.** Whether
    /// the report came from an intelligent relay noticing a socket close or from
    /// a peer publishing its own `leave`, the device id reaching the engine is
    /// the one in the payload, and neither the relay nor the event author is
    /// authenticated to that device. So this is reachability evidence: it may
    /// update availability, cancel speculative work, and prompt a look at the
    /// connector, and it retires no session in any state.
    ///
    /// **Teardown is the connector's and the heartbeat's.** An earlier version
    /// of this doc said the engine could tear the peer down promptly on it,
    /// which was true and is no longer: exact connector closure, the
    /// authenticated `SessionControl::Depart` over the session itself, or the
    /// heartbeat timeout retire a session, and nothing on this path does.
    PeerLeft {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer addressed us directly with a signaling message.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
#[derive(Debug, Clone)]
pub enum NostrOutbound {
    Announce,
    /// Graceful departure broadcast — the dual of [`Announce`]. Publishes a
    /// `leave` envelope as a reachability hint: a receiver may stop pacing a
    /// dial or cancel speculative work on it, and may not tear a promoted
    /// session down on it, because the device id it carries is one this sender
    /// wrote. Prompt teardown is the authenticated `SessionControl::Depart`
    /// over the session itself; this only ever arrives ahead of it. Rides the
    /// ephemeral kind (like the rest of the live negotiation traffic) so a
    /// relay never replays it onto a future session.
    Leave,
    DirectedToPeer {
        to: String,
        msg: SignalingMessage,
    },
}

/// Start the driver. Spawns a coordinator task per relay; returns
/// the handle (drop to stop).
pub fn start<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<NostrInbound>,
) -> NostrDriverHandle
where
    S: OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    start_with_delivery_provider(
        config,
        outbound,
        inbound_tx,
        Arc::new(UnmeteredDeliveryProvider),
    )
}

/// Start with the provider that funds each exact attempt and relay-session
/// delivery.  Attempt custody is acquired before the event enters the live
/// map; relay custody is acquired before a frame is encoded.
pub fn start_with_delivery_provider<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
) -> NostrDriverHandle
where
    S: OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    start_with_delivery_provider_and_refusal_sink(
        config,
        outbound,
        inbound_tx,
        provider,
        Arc::new(UnmeteredAttemptRefusalSink),
    )
}

/// Start with provider custody and a consumer-owned sink for typed refusal
/// records. The sink receives each exact attempt/event record immediately;
/// the driver never retains a refusal queue.
pub fn start_with_delivery_provider_and_refusal_sink<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
    refusal_sink: Arc<dyn AttemptRefusalSink>,
) -> NostrDriverHandle
where
    S: OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    start_with_delivery_provider_and_sinks(
        config,
        outbound,
        inbound_tx,
        provider,
        refusal_sink,
        Arc::new(UnmeteredAttemptOutcomeSink),
    )
}

/// Start with provider custody and consumer-owned refusal/outcome sinks.
pub fn start_with_delivery_provider_and_sinks<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
    refusal_sink: Arc<dyn AttemptRefusalSink>,
    outcome_sink: Arc<dyn AttemptOutcomeSink>,
) -> NostrDriverHandle
where
    S: OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    let identity = NostrIdentity::generate();
    let room_handle = derive_room_handle(&config.app_id, &config.network_id);
    info!(
        network = %config.network_id,
        room_handle = %&room_handle[..16],
        pubkey = %&identity.pubkey_hex()[..16],
        "starting Nostr driver"
    );

    // Resolve the top-N relay set.
    let pool_storage: Vec<&str>;
    let pool: Vec<&str> = if config.servers.is_empty() {
        super::defaults::DEFAULT_RELAY_URLS.to_vec()
    } else {
        pool_storage = config.servers.iter().map(String::as_str).collect();
        pool_storage
    };
    let denylist = &config.denylist;
    let filtered: Vec<&str> = pool
        .into_iter()
        .filter(|u| !super::denylist::is_denied(u, denylist))
        .collect();
    let selected = select_top_n(&config.app_id, &filtered, config.redundancy);

    // Public-relay fallback pool. Computed now (before `selected` is
    // moved): the built-in public relays, minus the denylist and anything
    // already in the primary set. These are NOT connected in steady state
    // — a supervisor brings them up only after every primary has been down
    // for a grace window, and drops them again the moment one recovers, so
    // presence isn't leaked to public infrastructure during normal
    // operation. Off entirely when `public_fallback` is false.
    let fallback_urls: Vec<String> = if config.public_fallback {
        super::defaults::FALLBACK_RELAY_URLS
            .iter()
            .map(|s| s.to_string())
            .filter(|u| !super::denylist::is_denied(u, denylist) && !selected.contains(u))
            .collect()
    } else {
        Vec::new()
    };

    let delivery = DeliveryStore::new_with_outcome_sink(provider, outcome_sink);
    let (presence_tx, _) = watch::channel::<Option<Arc<NostrEvent>>>(None);
    // Force-reconnect signal. A bumped generation tells every relay
    // task to drop its current socket and redial *now*, skipping the
    // backoff wait — see `run_relay` / `run_relay_session`. The engine
    // bumps it on resume-from-sleep so a zombie relay socket (a TCP
    // connection the OS never tore down while the host was suspended)
    // is replaced immediately instead of waiting minutes for the
    // kernel to notice the peer is gone. `Arc` so the same sender is
    // shared by the driver tasks (which `.subscribe()` receivers) and
    // the engine (which holds a clone to bump it).
    let force_reconnect = Arc::new(watch::channel(0u64).0);
    // Bumped on every fresh relay connection so the engine can wait for
    // signaling to actually come back after a network change before it
    // renegotiates (see `relay_connected` on `DriverShared`).
    let relay_connected = Arc::new(watch::channel(0u64).0);
    let shared = Arc::new(DriverShared {
        identity,
        room_handle,
        device_id: config.device_id.clone(),
        relays: Mutex::new(Vec::new()),
        // Erased once, here, at the only place that knows the producer's owner
        // type. Everything downstream stays concrete, and the owner remains
        // paired with the value it funded.
        outbound: tokio::sync::Mutex::new(Some(Box::new(ErasedSource::new(outbound))
            as Box<dyn OutboundSource<NostrOutbound, Owner = ErasedOwner>>)),
        delivery: delivery.clone(),
        refusal_sink,
        presence_tx,
        force_reconnect: force_reconnect.clone(),
        relay_connected: relay_connected.clone(),
    });
    {
        let mut relays = shared.relays.lock();
        for url in &selected {
            relays.push(RelayHandle {
                url: url.clone(),
                connected: false,
            });
        }
    }

    let mut cancellers = Vec::new();

    // Count of primary relays with a live session; the fallback
    // supervisor watches this to decide when to step in.
    let primary_live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Spawn one connection task per primary relay.
    for url in selected {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        cancellers.push(cancel_token);
        let live = primary_live.clone();
        tokio::spawn(async move {
            run_relay(url, shared, inbound_tx, cancel_token_for_task, Some(live)).await;
        });
    }

    // Spawn the public-relay fallback supervisor (no-op unless the pool is
    // non-empty, i.e. `public_fallback` is on and there are relays to use).
    if !fallback_urls.is_empty() {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        cancellers.push(cancel_token);
        let primary_live = primary_live.clone();
        tokio::spawn(async move {
            run_fallback_supervisor(
                fallback_urls,
                shared,
                inbound_tx,
                cancel_token_for_task,
                primary_live,
            )
            .await;
        });
    }

    // Spawn the outbound pump.
    let shared_for_outbound = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tokio::spawn(async move {
        run_outbound_pump_v2(shared_for_outbound, cancel_token_for_task).await;
    });

    // Spawn the global announce task. Single ticker per driver
    // instance (NOT per relay) — updates the driver-owned presence watch.
    // `upstream.rs` item 7 for the schedule rationale and the
    // earlier "N-relay = N-publish" bug it fixes.
    let shared_for_announce = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tokio::spawn(async move {
        run_announcer(shared_for_announce, cancel_token_for_task).await;
    });

    NostrDriverHandle {
        cancellers,
        force_reconnect,
        relay_connected,
        delivery,
    }
}

/// Handle returned by [`start`]. Drop or call [`Self::stop`] to
/// signal every spawned task to exit.
pub struct NostrDriverHandle {
    cancellers: Vec<Arc<std::sync::atomic::AtomicBool>>,
    force_reconnect: Arc<watch::Sender<u64>>,
    relay_connected: Arc<watch::Sender<u64>>,
    delivery: Arc<DeliveryStore>,
}

impl NostrDriverHandle {
    /// Finish all live emissions carrying one existing attempt correlation.
    pub fn finish_attempt(&self, attempt: &str, terminal: DeliveryTerminal) -> usize {
        self.delivery.finish_attempt(attempt, terminal)
    }

    pub fn stop(self) {
        self.delivery.shutdown();
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Clone of the force-reconnect signal. The engine stashes this
    /// (see `engine::state::NetworkState::set_relay_reconnect`) and
    /// bumps it to make every relay redial immediately — e.g. on
    /// resume from sleep, when the existing sockets are stale.
    pub fn reconnect_signal(&self) -> Arc<watch::Sender<u64>> {
        self.force_reconnect.clone()
    }

    /// Clone of the relay-connected signal. The engine subscribes and, after
    /// asking for a redial on a network change, waits for the next bump (a
    /// fresh relay session) before renegotiating ICE — so the offer isn't
    /// published into a not-yet-reconnected relay. See
    /// `engine::state::NetworkState::set_relay_connected_signal`.
    pub fn connected_signal(&self) -> Arc<watch::Sender<u64>> {
        self.relay_connected.clone()
    }
}

impl Drop for NostrDriverHandle {
    fn drop(&mut self) {
        self.delivery.shutdown();
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct DriverShared {
    identity: NostrIdentity,
    room_handle: String,
    device_id: String,
    relays: Mutex<Vec<RelayHandle>>,
    outbound:
        tokio::sync::Mutex<Option<Box<dyn OutboundSource<NostrOutbound, Owner = ErasedOwner>>>>,
    delivery: Arc<DeliveryStore>,
    refusal_sink: Arc<dyn AttemptRefusalSink>,
    presence_tx: watch::Sender<Option<Arc<NostrEvent>>>,
    /// Generation counter for forced reconnects. Bumping it wakes
    /// every relay task's `watch::Receiver` so it drops its socket
    /// and redials without waiting out the backoff. See the comment
    /// at the channel's creation in [`start`].
    force_reconnect: Arc<watch::Sender<u64>>,
    /// Monotonic counter bumped each time a relay establishes a fresh
    /// session. The engine waits on a change to this (after asking for a
    /// redial) before it fans out an ICE-restart offer, so the offer isn't
    /// published into a relay that hasn't reconnected yet — those ephemeral
    /// offers/candidates would reach nobody (the "0 remote candidates
    /// arrived" stall). See `engine::network_watch::on_network_change`.
    relay_connected: Arc<watch::Sender<u64>>,
    // Outbound *directed* events (offers / answers / candidates) removed;
    // while every relay socket was mid-reconnect; DeliveryStore owns live attempts.
    // A reconnecting session registers fresh per-relay custody entries.
    // DeliveryStore retains them for the next live relay session.
    // DeliveryStore owns live directed attempts and registers fresh custody
    // entries for each reconnecting relay session. The source owner remains in
    // the exact attempt record until its terminal outcome.
}

/// The NIP-01 filter set for our room subscription:
///
///   1. presence (stored kind, replayed over the `since` window),
///   2. directed-to-me negotiation (ephemeral kind, `#p` = us).
///
/// One REQ, both filters (OR semantics).
///
/// # There is no third, room-wide filter, and there is no longer a state
/// machine that adds one
///
/// An earlier revision kept a per-room capability map: every announced peer
/// recorded whether it stamped recipient tags, and while any of them did not,
/// the subscription added a catch-all that asked the relay for *every* pairwise
/// offer, answer and candidate in the room. Two things were wrong with it.
///
/// It was an unbounded unauthenticated keyspace. The map was keyed by the
/// `peer_id` out of an announce nobody authenticated, so one sender could
/// publish arbitrarily many claimed device ids, grow the map without bound, and
/// — because a claimed id that does not advertise the tag holds the catch-all
/// on — keep every peer's pairwise negotiation flowing past every subscriber.
/// The memory and the metadata amplification were the same lever.
///
/// It was also a mixed-version compatibility path, and the adopted hard-alpha
/// cutover has none: peers are same-build, there is no downgrade, and nothing
/// on the wire needs to ask what shape the other end speaks. The map is deleted
/// rather than capped, because a capacity would have kept the amplification and
/// only bounded the memory.
fn desired_filters(shared: &DriverShared) -> Vec<Value> {
    let since = now_secs().saturating_sub(PRESENCE_REPLAY_WINDOW_SECS);
    vec![
        serde_json::json!({
            "kinds": [SIGNALING_EVENT_KIND],
            "#r": [shared.room_handle.clone()],
            "since": since,
        }),
        // Directed-to-me, plus room-addressed broadcasts: a tagging
        // build stamps broadcast ephemerals (`leave`) with the room
        // handle as their recipient, so the narrowed shape still hears
        // departures. `#p` is an OR-list per NIP-01.
        serde_json::json!({
            "kinds": [SIGNALING_EPHEMERAL_KIND],
            "#r": [shared.room_handle.clone()],
            "#p": [shared.device_id.clone(), shared.room_handle.clone()],
        }),
    ]
}

/// Serialize the room REQ for `desired_filters`.
fn build_req(shared: &DriverShared, sub_id: &str) -> String {
    let mut arr = vec![
        Value::String("REQ".to_string()),
        Value::String(sub_id.to_string()),
    ];
    arr.extend(desired_filters(shared));
    Value::Array(arr).to_string()
}

/// Deterministic ±15% jitter on a timer, seeded from the device id and a
/// per-use salt, so co-restarted nodes (a site-wide power blip, a relay
/// outage ending) don't fire their timers in lockstep forever. Pure —
/// same inputs, same wait — which keeps tests exact.
fn jittered_ms(base_ms: u64, seed: &str, salt: u64) -> u64 {
    use sha2::{Digest, Sha256};
    if base_ms == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(salt.to_le_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    // Map to [-15%, +15%] of base.
    let span = base_ms * 30 / 100;
    if span == 0 {
        return base_ms;
    }
    let offset = raw % (span + 1);
    base_ms - (base_ms * 15 / 100) + offset
}

#[allow(dead_code)]
struct RelayHandle {
    url: String,
    connected: bool,
}

async fn run_relay(
    url: String,
    shared: Arc<DriverShared>,
    inbound_tx: InboundSink<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    live: Option<Arc<std::sync::atomic::AtomicUsize>>,
) {
    let mut backoff_attempt = 0u32;
    // Receiver for forced reconnects. `borrow_and_update` marks the
    // current generation as seen so a stale value from before this
    // task started can't fire a spurious immediate reconnect.
    let mut force_rx = shared.force_reconnect.subscribe();
    force_rx.borrow_and_update();
    // Tracks consecutive connect failures so we can dampen the log
    // spam from chronically-broken public relays (DNS no-such-host,
    // 403s, TLS handshake timeouts). Without this, a single bad
    // relay floods stderr with one WARN every 1/2/4/8/16/32/60s
    // forever — drowning out everything else. We surface the first
    // failure of a streak at WARN, drop subsequent failures to
    // DEBUG, then announce recovery at INFO once the relay starts
    // accepting again. Mirrors the rationale behind MyOwnLLM's
    // Trystero-patch noise suppression.
    let mut consecutive_failures = 0u32;
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match tokio_tungstenite::connect_async(&url).await {
            Ok((stream, _)) => {
                if consecutive_failures > 0 {
                    info!(
                        relay = %short(&url),
                        attempts = consecutive_failures,
                        "relay recovered after failed attempts"
                    );
                } else {
                    info!(relay = %short(&url), "relay connected");
                }
                consecutive_failures = 0;
                backoff_attempt = 0;
                // Tell the engine a relay is freshly up so a network-change
                // renegotiation can publish into a live relay instead of a
                // redialing one (the "0 remote candidates arrived" stall).
                shared
                    .relay_connected
                    .send_modify(|g| *g = g.wrapping_add(1));
                // Count this live session so the fallback supervisor can
                // tell whether any primary relay is currently connected.
                // `None` for fallback tasks (they don't gate themselves).
                if let Some(c) = &live {
                    c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let (session, session_refusal, refused) =
                    shared.delivery.open_session_with_refusals();
                if let Some(error) = session_refusal {
                    warn!(
                        relay = %short(&url),
                        ?error,
                        "relay-session custody refused by provider"
                    );
                }
                for refusal in refused {
                    warn!(
                        relay = %short(&url),
                        attempt = %refusal.attempt,
                        event_id = %refusal.event_id,
                        ?refusal.refusal,
                        "relay-session delivery refused by provider"
                    );
                    shared.refusal_sink.refused(refusal);
                }
                let outcome = run_relay_session(
                    &url,
                    stream,
                    &shared,
                    &inbound_tx,
                    &cancel,
                    &mut force_rx,
                    &session,
                )
                .await;
                shared
                    .delivery
                    .close_session(session, DeliveryTerminal::Cancelled);
                if let Some(c) = &live {
                    c.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
                trace!(relay = %short(&url), outcome = ?outcome, "relay session ended");
                if matches!(outcome, RelaySessionOutcome::ForcedReconnect) {
                    // Engine asked us to redial now (e.g. resume from
                    // sleep). Skip the backoff entirely and reconnect on
                    // the next loop turn so a fresh socket — and the
                    // open-announce it sends — lands immediately.
                    debug!(relay = %short(&url), "forced reconnect — redialing now");
                    backoff_attempt = 0;
                    continue;
                }
            }
            Err(e) => {
                if consecutive_failures == 0 {
                    warn!(relay = %short(&url), "relay connect failed: {e}");
                } else {
                    debug!(
                        relay = %short(&url),
                        attempt = consecutive_failures + 1,
                        "relay still failing: {e}"
                    );
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
        }
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // Reconnect backoff: 2 / 4 / 8 / 16 / 32 s capped at 60 s — the
        // increment precedes the shift, so a 1 s wait is unreachable —
        // then jittered ±15% per node so a shared outage (relay restart,
        // site-wide blip) doesn't recover as a synchronized redial herd.
        // A forced-reconnect bump cuts the wait short so resume-from-sleep
        // recovery doesn't sit through a backoff that accrued while the
        // host was suspended.
        backoff_attempt = (backoff_attempt + 1).min(6);
        let base_ms = (1u64 << backoff_attempt).min(60) * 1_000;
        let wait_ms = jittered_ms(base_ms, &shared.device_id, backoff_attempt as u64);
        debug!(relay = %short(&url), wait_ms, "relay backoff before reconnect");
        tokio::select! {
            _ = sleep(Duration::from_millis(wait_ms)) => {}
            _ = force_rx.changed() => {
                debug!(relay = %short(&url), "forced reconnect during backoff — redialing now");
                backoff_attempt = 0;
            }
        }
    }
}

/// How often the fallback supervisor samples primary-relay health.
const FALLBACK_POLL_MS: u64 = 3_000;

/// How long *every* primary relay must be continuously unreachable before
/// the public fallback is brought up. Long enough that a routine
/// reconnect or a brief blip doesn't leak presence to public relays;
/// short enough that a real outage recovers in seconds.
const FALLBACK_ACTIVATION_GRACE_MS: u64 = 20_000;

/// What the fallback supervisor should do on a given tick. A pure
/// function of the inputs so the policy is unit-testable without spawning
/// relays.
#[derive(Debug, PartialEq)]
enum FallbackAction {
    /// Primary down past the grace and fallback isn't up — start it.
    Activate,
    /// A primary returned while fallback was up — stop it.
    StandDown,
    /// Nothing to change this tick.
    Hold,
}

fn fallback_action(primary_live: usize, fallback_active: bool, down_for_ms: u64) -> FallbackAction {
    if primary_live > 0 {
        if fallback_active {
            FallbackAction::StandDown
        } else {
            FallbackAction::Hold
        }
    } else if !fallback_active && down_for_ms >= FALLBACK_ACTIVATION_GRACE_MS {
        FallbackAction::Activate
    } else {
        FallbackAction::Hold
    }
}

/// Supervises the public-relay fallback. Steady state: idle, sampling
/// `primary_live`. When every primary relay has been down for
/// [`FALLBACK_ACTIVATION_GRACE_MS`] it spawns a `run_relay` task per
/// fallback URL; when a primary returns it cancels them. So the public
/// relays only ever carry traffic when the configured/primary set can't —
/// presence stays off public infrastructure in normal operation.
async fn run_fallback_supervisor(
    urls: Vec<String>,
    shared: Arc<DriverShared>,
    inbound_tx: InboundSink<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    primary_live: Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Instant;

    // Cancel tokens for the fallback relay tasks currently running.
    let mut active: Vec<Arc<std::sync::atomic::AtomicBool>> = Vec::new();
    let mut down_since: Option<Instant> = None;

    loop {
        if cancel.load(SeqCst) {
            for c in &active {
                c.store(true, SeqCst);
            }
            return;
        }

        let live = primary_live.load(SeqCst);
        if live == 0 {
            down_since.get_or_insert_with(Instant::now);
        } else {
            down_since = None;
        }
        let down_for_ms = down_since
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        match fallback_action(live, !active.is_empty(), down_for_ms) {
            FallbackAction::Activate => {
                warn!(
                    count = urls.len(),
                    "primary signaling unreachable — bringing up public fallback relays"
                );
                for url in &urls {
                    let task_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    active.push(task_cancel.clone());
                    let shared = shared.clone();
                    let inbound_tx = inbound_tx.clone();
                    let url = url.clone();
                    tokio::spawn(async move {
                        run_relay(url, shared, inbound_tx, task_cancel, None).await;
                    });
                }
            }
            FallbackAction::StandDown => {
                info!("primary signaling recovered — standing down public fallback relays");
                for c in &active {
                    c.store(true, SeqCst);
                }
                active.clear();
            }
            FallbackAction::Hold => {}
        }

        sleep(Duration::from_millis(FALLBACK_POLL_MS)).await;
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Some variants are read only via their Debug impl in trace logs.
enum RelaySessionOutcome {
    Cancelled,
    SocketClosed,
    Error(String),
    /// The engine bumped the force-reconnect signal — drop this socket
    /// and redial immediately, skipping the backoff. Matched in
    /// [`run_relay`].
    ForcedReconnect,
}

/// How often the relay read loop wakes on an otherwise-idle socket to
/// re-check the cancel flag. The loop wakes immediately on any inbound
/// frame or outbound publish; this bounds how long a *stopped* driver
/// (handle dropped / `stop()`) holds an idle socket open before it tears
/// it down — which is what lets an intelligent relay emit our `leave`
/// promptly rather than waiting on its own connection timeout.
const RELAY_CANCEL_POLL_MS: u64 = 250;

async fn send_pending_deliveries<S>(
    url: &str,
    write: &mut S,
    delivery: &Arc<DeliveryStore>,
    session: &RelaySessionId,
) -> Result<(), String>
where
    S: Sink<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    for event_id in delivery.pending(session) {
        let Some(frame) = delivery.with_event(&event_id, |event| {
            serde_json::json!(["EVENT", event]).to_string()
        }) else {
            continue;
        };
        if let Err(error) = write.send(WsMessage::Text(frame)).await {
            delivery.settle(
                session,
                &event_id,
                DeliveryTerminal::TypedRefused(format!("local write: {error}")),
            );
            return Err(format!("send publish: {error}"));
        }
    }
    let _ = url;
    Ok(())
}

/// Prepare a relay session's delivery side before entering the main select
/// loop. The notification is enabled before the initial scan and remains
/// armed while the open announcement is written, closing the scan-to-wait
/// gap in which a directed admission could otherwise lose its wakeup.
async fn prepare_relay_delivery<'a, S>(
    url: &str,
    write: &mut S,
    shared: &DriverShared,
    delivery: &'a Arc<DeliveryStore>,
    session: &RelaySessionId,
) -> Result<Pin<Box<tokio::sync::futures::Notified<'a>>>, String>
where
    S: Sink<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    let mut delivery_notified = Box::pin(delivery.notification().notified());
    delivery_notified.as_mut().enable();

    send_pending_deliveries(url, write, delivery, session).await?;

    let event = build_announce_event(shared);
    let frame = serde_json::json!(["EVENT", event]).to_string();
    write
        .send(WsMessage::Text(frame))
        .await
        .map_err(|error| format!("send open-announce: {error}"))?;

    Ok(delivery_notified)
}

async fn run_relay_session(
    url: &str,
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    shared: &Arc<DriverShared>,
    inbound_tx: &InboundSink<NostrInbound>,
    cancel: &Arc<std::sync::atomic::AtomicBool>,
    force_rx: &mut watch::Receiver<u64>,
    session: &RelaySessionId,
) -> RelaySessionOutcome {
    let (mut write, mut read) = stream.split();

    // Open the room subscription — one REQ, several filters (see
    // `desired_filters`):
    //   - presence on the stored kind, with a `since` window that
    //     replays the last few minutes so a late joiner discovers
    //     everyone already here;
    //   - directed-to-me negotiation on the ephemeral kind (`#p` us).
    // Ephemeral events are never stored, so `since` governs presence
    // replay only — negotiation always arrives live (see
    // `event::SIGNALING_EPHEMERAL_KIND`). The shape is fixed for the life
    // of the session: nothing a peer publishes can widen it.
    let sub_id = "mom-sig-1";
    let req_text = build_req(shared, sub_id);

    if let Err(e) = write.send(WsMessage::Text(req_text)).await {
        return RelaySessionOutcome::Error(format!("send REQ: {e}"));
    }

    // Subscribe to the driver-owned presence watch for this socket.
    // Announce ticking lives in `run_announcer` — one shared task
    // per driver instance, not one per relay — so the per-cycle
    // publish rate doesn't scale with relay count.
    let mut presence_rx = shared.presence_tx.subscribe();
    let mut delivery_notified =
        match prepare_relay_delivery(url, &mut write, shared, &shared.delivery, session).await {
            Ok(notification) => notification,
            Err(error) => return RelaySessionOutcome::Error(error),
        };

    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            // Best-effort clean close so the relay sees our departure
            // immediately (a Close frame, falling back to the TCP FIN
            // from dropping the stream). Bounded so a wedged socket
            // can't hang teardown.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), write.close()).await;
            return RelaySessionOutcome::Cancelled;
        }
        tokio::select! {
            msg = read.next() => {
                let Some(msg) = msg else { return RelaySessionOutcome::SocketClosed };
                let frame = match msg {
                    Ok(WsMessage::Text(t)) => t,
                    Ok(WsMessage::Binary(b)) => match std::str::from_utf8(&b) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                    },
                    Ok(WsMessage::Close(_)) => return RelaySessionOutcome::SocketClosed,
                    Ok(_) => continue,
                    Err(e) => return RelaySessionOutcome::Error(format!("ws read: {e}")),
                };
                if let Err(e) = handle_inbound_frame(url, &frame, shared, inbound_tx, session.clone()) {
                    trace!(relay = %short(url), "inbound frame parse: {e}");
                }
            }
            _ = &mut delivery_notified => {
                // Re-arm before sending so an admission during this write is
                // observed by the next select turn as well.
                delivery_notified = Box::pin(shared.delivery.notification().notified());
                delivery_notified.as_mut().enable();
                if let Err(error) =
                    send_pending_deliveries(url, &mut write, &shared.delivery, session).await
                {
                    return RelaySessionOutcome::Error(error);
                }
            }
            changed = presence_rx.changed() => {
                if changed.is_err() {
                    return RelaySessionOutcome::Cancelled;
                }
                let event = presence_rx.borrow().clone();
                if let Some(event) = event {
                    let frame = serde_json::json!(["EVENT", event.as_ref()]).to_string();
                    if let Err(e) = write.send(WsMessage::Text(frame)).await {
                        return RelaySessionOutcome::Error(format!("send presence: {e}"));
                    }
                }
            }
            // Forced reconnect — the engine bumped the generation
            // (resume-from-sleep, etc.). Tear this session down so
            // `run_relay` redials immediately onto a fresh socket. We
            // skip the clean Close frame here: the whole point is that
            // the existing socket is likely a zombie, so spending up to
            // a second trying to close it gracefully would defeat the
            // "reconnect now" intent.
            _ = force_rx.changed() => {
                return RelaySessionOutcome::ForcedReconnect;
            }
            // Idle-wake so a stopped/dropped handle is noticed within one
            // poll interval even on a quiet socket. Without this, a
            // `read.next()` parked on an idle connection could hold the
            // socket open long after `stop()`, delaying the relay's
            // departure signal. Normal traffic wakes the loop sooner via
            // the branches above; this only bites when nothing is moving.
            _ = tokio::time::sleep(std::time::Duration::from_millis(RELAY_CANCEL_POLL_MS)) => {}
        }
    }
}

/// Global announce ticker. One instance per driver; publishes
/// presence events via the driver-owned watch on the schedule defined by
/// [`ANNOUNCE_BACKOFF_MS`] / [`ANNOUNCE_STEADY_MS`].
///
/// The first announce fires immediately on driver start (a fresh
/// joiner wants to be visible to existing peers without delay).
/// Subsequent waits follow the curve in `upstream.rs` item 7:
/// dense at startup, settling to a 60s steady-state heartbeat.
async fn run_announcer(shared: Arc<DriverShared>, cancel: Arc<std::sync::atomic::AtomicBool>) {
    let mut count: usize = 0;
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let event = build_announce_event(&shared);
        // Each connected relay observes this latest best-effort presence
        // value independently; negotiation never enters this path.
        let _ = shared.presence_tx.send(Some(Arc::new(event)));

        let base_ms = ANNOUNCE_BACKOFF_MS
            .get(count)
            .copied()
            .unwrap_or(ANNOUNCE_STEADY_MS);
        // Jitter the steady cadence (±15%) so nodes that came up together
        // — a site restoring power, a fleet rebooting after an update —
        // don't publish their presence in the same instant every cycle
        // forever. The dense early schedule stays exact: it exists to make
        // a fresh joiner visible fast, and determinism there keeps tests
        // and traces legible.
        let wait_ms = if base_ms == ANNOUNCE_STEADY_MS {
            jittered_ms(base_ms, &shared.device_id, count as u64)
        } else {
            base_ms
        };
        count = count.saturating_add(1);

        // Cancellation-aware sleep: chunked at 1s so a stop()
        // call doesn't have to wait a full 60s tick to take
        // effect. Bounded by `chunk` since wait_ms can exceed it.
        let mut remaining = wait_ms;
        const CHUNK_MS: u64 = 1_000;
        while remaining > 0 {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let step = remaining.min(CHUNK_MS);
            sleep(Duration::from_millis(step)).await;
            remaining = remaining.saturating_sub(step);
        }
    }
}

fn handle_inbound_frame(
    url: &str,
    frame: &str,
    shared: &Arc<DriverShared>,
    inbound_tx: &InboundSink<NostrInbound>,
    session: RelaySessionId,
) -> Result<(), String> {
    let value: Value = serde_json::from_str(frame).map_err(|e| e.to_string())?;
    let arr = value.as_array().ok_or_else(|| "not an array".to_string())?;
    let tag = arr.first().and_then(|v| v.as_str()).unwrap_or("");
    match tag {
        "EVENT" => {
            let event_value = arr.get(2).ok_or_else(|| "missing event body".to_string())?;
            let event: NostrEvent =
                serde_json::from_value(event_value.clone()).map_err(|e| e.to_string())?;
            // Skip events we sent ourselves.
            if event.pubkey == shared.identity.pubkey_hex() {
                return Ok(());
            }
            // No de-duplication here, deliberately. The relay fan-out
            // duplicate is real — one event published once arrives from
            // every relay that has it, and applying an offer twice via
            // `set_remote_description` wedges WebRTC permanently — but this
            // is the wrong layer to remember it at, and remembering it here
            // was a second bug on top of the first.
            //
            // The ring that used to sit on this line recorded the event id
            // *before* the envelope was parsed and *before* the value was
            // offered onward, and it discarded the offer's result. So a copy
            // the consumer refused under pressure still left its id behind,
            // and the identical copy arriving from the next relay — the one
            // that would have rescued the attempt — was dropped here as
            // already seen. Neither copy ever reached the engine.
            //
            // De-duplication now has one owner, downstream, which commits a
            // key only after the value has actually been accepted and scopes
            // it to the exact attempt it describes. A refused value leaves no
            // history anywhere. See `engine::signaling_ingress`.
            //
            // Pull our envelope out of the content.
            let envelope: SignalingEnvelope =
                serde_json::from_str(&event.content).map_err(|e| e.to_string())?;

            // Skip messages directed to a different recipient.
            if let Some(to) = &envelope.to {
                if to != &shared.device_id {
                    return Ok(());
                }
            }

            // Enforce the presence/negotiation kind split on receive.
            // This is the receive-side half of the replay fix: a
            // stored-kind event can be replayed from history, so we
            // only ever honour an Announce there; an offer/answer/
            // candidate must arrive live on the ephemeral kind. A
            // directed message on the stored kind is stale history
            // (a pre-split build, or a relay that wrongly persisted
            // an ephemeral event) and is dropped rather than applied
            // as a remote description against dead ICE credentials.
            match envelope.msg {
                SignalingMessage::Announce { peer_id } => {
                    if event.kind != SIGNALING_EVENT_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "ignoring announce on non-presence kind"
                        );
                        return Ok(());
                    }
                    if peer_id == shared.device_id {
                        return Ok(());
                    }
                    // Sender-claimed, and deliberately still the body id: on
                    // a relay the envelope's own `from` is a second field the
                    // same sender wrote, so preferring it would buy nothing.
                    // What the tag buys is that this can never cancel an
                    // observation a carrier made itself.
                    let _ = inbound_tx.send(NostrInbound::PeerAnnounced {
                        device_id: peer_id,
                        attribution: CarrierAttribution::SenderClaimed,
                    });
                }
                SignalingMessage::Leave { peer_id } => {
                    // Departure rides the ephemeral kind like the rest of
                    // the live negotiation traffic — a stored-kind "leave"
                    // would be stale history, so drop it.
                    if event.kind != SIGNALING_EPHEMERAL_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "ignoring leave on non-ephemeral kind"
                        );
                        return Ok(());
                    }
                    if peer_id == shared.device_id {
                        return Ok(());
                    }
                    let _ = inbound_tx.send(NostrInbound::PeerLeft {
                        device_id: peer_id,
                        attribution: CarrierAttribution::SenderClaimed,
                    });
                }
                other => {
                    if event.kind != SIGNALING_EPHEMERAL_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "dropping replayed/stored-kind negotiation message"
                        );
                        return Ok(());
                    }
                    let _ = inbound_tx.send(NostrInbound::Message {
                        from: envelope.from,
                        msg: other,
                    });
                }
            }
        }
        "OK" => {
            let event_id = arr
                .get(1)
                .and_then(Value::as_str)
                .ok_or_else(|| "OK missing event id".to_string())?;
            let accepted = arr
                .get(2)
                .and_then(Value::as_bool)
                .ok_or_else(|| "OK missing acceptance".to_string())?;
            let reason = arr
                .get(3)
                .and_then(Value::as_str)
                .unwrap_or("relay refused event");
            let terminal = if accepted {
                DeliveryTerminal::Accepted
            } else {
                DeliveryTerminal::TypedRefused(reason.to_string())
            };
            if !shared.delivery.settle(&session, event_id, terminal) {
                trace!(relay = %short(url), %event_id, "stale relay OK ignored");
            }
        }
        "EOSE" => {
            trace!(relay = %short(url), "EOSE");
        }
        "NOTICE" => {
            let body = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            debug!(relay = %short(url), "relay notice: {body}");
        }
        _ => {
            trace!(relay = %short(url), "unhandled tag: {tag}");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignalingEnvelope {
    from: String,
    /// Recipient device id, or None for a broadcast (announce).
    #[serde(default)]
    to: Option<String>,
    #[serde(flatten)]
    msg: SignalingMessage,
}

/// The one announce builder — the periodic ticker, the per-session
/// open-announce, and the engine-driven reactive announce all publish
/// exactly this event, so there is a single place the announce's shape
/// can ever change.
fn build_announce_event(shared: &DriverShared) -> NostrEvent {
    let envelope = SignalingEnvelope {
        from: shared.device_id.clone(),
        to: None,
        msg: SignalingMessage::Announce {
            peer_id: shared.device_id.clone(),
        },
    };
    make_event(
        &shared.identity,
        SIGNALING_EVENT_KIND,
        vec![vec!["r".into(), shared.room_handle.clone()]],
        serde_json::to_string(&envelope).expect("serialize ok"),
        now_secs(),
    )
}

async fn run_outbound_pump_v2(
    shared: Arc<DriverShared>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut rx_guard = shared.outbound.lock().await;
    let Some(mut rx) = rx_guard.take() else {
        return;
    };
    drop(rx_guard);
    while let Some(outbound) = rx.recv().await {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let attempt = outbound_attempt(outbound.value()).map(str::to_owned);
        let shared_for_event = Arc::clone(&shared);
        let owned =
            outbound.map(move |outbound| translate_outbound_event(&shared_for_event, outbound));
        if let Some(attempt) = attempt {
            let report = shared.delivery.admit(attempt.clone(), owned);
            if let Some(refusal) = report.attempt_refusal.clone() {
                let refusal_record = AttemptRefusal {
                    attempt: attempt.clone(),
                    event_id: report.event_id.clone(),
                    refusal: refusal.into_negotiation(),
                };
                warn!(
                    %attempt,
                    event_id = %report.event_id,
                    ?refusal_record.refusal,
                    "negotiation attempt refused before relay admission"
                );
                shared.refusal_sink.refused(refusal_record);
            }
            for (session, error) in &report.refused {
                warn!(
                    ?session,
                    ?error,
                    event_id = %report.event_id,
                    "negotiation delivery refused before frame allocation"
                );
            }
        } else {
            let _ = shared
                .presence_tx
                .send(Some(Arc::new(owned.value().clone())));
        }
    }
    shared.delivery.shutdown();
}

fn outbound_attempt(outbound: &NostrOutbound) -> Option<&str> {
    let NostrOutbound::DirectedToPeer { msg, .. } = outbound else {
        return None;
    };
    match msg {
        SignalingMessage::Offer { offer_id, .. }
        | SignalingMessage::Answer { offer_id, .. }
        | SignalingMessage::Candidate { offer_id, .. } => Some(offer_id),
        _ => None,
    }
}

fn translate_outbound_event(shared: &DriverShared, outbound: NostrOutbound) -> NostrEvent {
    match outbound {
        NostrOutbound::Announce => build_announce_event(shared),
        NostrOutbound::Leave => {
            let envelope = SignalingEnvelope {
                from: shared.device_id.clone(),
                to: None,
                msg: SignalingMessage::Leave {
                    peer_id: shared.device_id.clone(),
                },
            };
            make_event(
                &shared.identity,
                SIGNALING_EPHEMERAL_KIND,
                vec![
                    vec!["r".into(), shared.room_handle.clone()],
                    vec!["p".into(), shared.room_handle.clone()],
                ],
                serde_json::to_string(&envelope).expect("serialize ok"),
                now_secs(),
            )
        }
        NostrOutbound::DirectedToPeer { to, msg } => {
            let envelope = SignalingEnvelope {
                from: shared.device_id.clone(),
                to: Some(to.clone()),
                msg,
            };
            make_event(
                &shared.identity,
                SIGNALING_EPHEMERAL_KIND,
                vec![
                    vec!["r".into(), shared.room_handle.clone()],
                    vec!["p".into(), to],
                ],
                serde_json::to_string(&envelope).expect("serialize ok"),
                now_secs(),
            )
        }
    }
}

fn short(url: &str) -> &str {
    url.strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::event::NostrIdentity;
    use crate::OwnedSignal;
    use futures::task::{Context, Poll};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    // Only the controls build channels now: the driver itself takes an
    // `OutboundSource` and an `InboundSink`, and owns no queue in either
    // direction.
    use tokio::sync::mpsc;

    struct ParkedWriteGate {
        parked: tokio::sync::Notify,
        waker: Mutex<Option<std::task::Waker>>,
        announced: AtomicBool,
        released: AtomicBool,
    }

    impl ParkedWriteGate {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let waker = self.waker.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct ParkedSink {
        frames: Vec<WsMessage>,
        gate: Arc<ParkedWriteGate>,
    }

    impl Sink<WsMessage> for ParkedSink {
        type Error = std::convert::Infallible;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if !self.gate.released.load(Ordering::SeqCst) {
                if !self.gate.announced.swap(true, Ordering::SeqCst) {
                    self.gate.parked.notify_one();
                }
                *self.gate.waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn start_send(mut self: Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
            self.frames.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn fallback_holds_while_a_primary_is_up() {
        // Primary connected, fallback not running → leave it alone.
        assert_eq!(fallback_action(2, false, 0), FallbackAction::Hold);
        assert_eq!(
            fallback_action(1, false, FALLBACK_ACTIVATION_GRACE_MS * 10),
            FallbackAction::Hold
        );
    }

    #[test]
    fn fallback_waits_out_the_grace_then_activates() {
        // All primaries down, but not yet past the grace → hold…
        assert_eq!(fallback_action(0, false, 0), FallbackAction::Hold);
        assert_eq!(
            fallback_action(0, false, FALLBACK_ACTIVATION_GRACE_MS - 1),
            FallbackAction::Hold
        );
        // …then activate once the grace elapses.
        assert_eq!(
            fallback_action(0, false, FALLBACK_ACTIVATION_GRACE_MS),
            FallbackAction::Activate
        );
    }

    #[test]
    fn fallback_stands_down_when_a_primary_returns() {
        // Fallback running and a primary comes back → tear it down.
        assert_eq!(fallback_action(1, true, 999_999), FallbackAction::StandDown);
    }

    #[test]
    fn fallback_holds_while_active_and_primary_still_down() {
        // Already covering the outage; don't respawn every tick.
        assert_eq!(fallback_action(0, true, 999_999), FallbackAction::Hold);
    }

    #[tokio::test]
    async fn prearmed_delivery_survives_open_announcement_scan_wait_gap() {
        let shared = fixture_shared();
        let (session, _) = shared.delivery.open_session();
        let gate = Arc::new(ParkedWriteGate {
            parked: tokio::sync::Notify::new(),
            waker: Mutex::new(None),
            announced: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut sink = ParkedSink {
            frames: Vec::new(),
            gate: Arc::clone(&gate),
        };

        // Drive the exact production pre-arm -> initial scan -> open-write
        // helper, parking its open write before it enters the select loop.
        let mut preparation = Box::pin(prepare_relay_delivery(
            "wss://relay-gap",
            &mut sink,
            &shared,
            &shared.delivery,
            &session,
        ));
        let parked_wait = gate.parked.notified();
        tokio::select! {
            result = &mut preparation => panic!("preparation completed before parked write: {result:?}"),
            _ = parked_wait => {}
        }

        // The sole directed event is admitted while the open announcement is
        // parked, exactly the scan→wait gap under review.
        let outbound = NostrOutbound::DirectedToPeer {
            to: "peer-b".into(),
            msg: SignalingMessage::Offer {
                peer_id: "peer-b".into(),
                offer_id: "gap-attempt".into(),
                sdp: "v=0".into(),
            },
        };
        let event = translate_outbound_event(&shared, outbound);
        let event_id = event.id.clone();
        let report = shared.delivery.admit(
            "gap-attempt".into(),
            OwnedSignal::new(event, Box::new(()) as ErasedOwner),
        );
        assert_eq!(report.accepted_sessions, 1);

        gate.release();
        let delivery_notified = preparation.await.expect("open write gate settles");
        delivery_notified.await;
        send_pending_deliveries("wss://relay-gap", &mut sink, &shared.delivery, &session)
            .await
            .expect("same relay sends the admitted event");

        assert_eq!(sink.frames.len(), 2, "open announcement plus one EVENT");
        let frames = sink
            .frames
            .iter()
            .filter_map(|message| match message {
                WsMessage::Text(frame) => {
                    Some(serde_json::from_str::<Value>(frame).expect("EVENT frame is JSON"))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(frames.len(), 2, "both writes are EVENT frames");
        assert!(frames.iter().all(|frame| frame[0] == "EVENT"));
        assert_eq!(
            frames
                .iter()
                .filter(|frame| {
                    frame[1]["id"] == event_id && frame[1]["kind"] == SIGNALING_EPHEMERAL_KIND
                })
                .count(),
            1,
            "exactly one directed EVENT for the admitted id"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|frame| frame[1]["kind"] == SIGNALING_EVENT_KIND)
                .count(),
            1,
            "exactly one open announcement"
        );
    }

    fn fixture_shared() -> Arc<DriverShared> {
        let identity = NostrIdentity::generate();
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
        // The standalone shape: an unbounded source has no accountant, so its
        // owner is `()`, and erasing that is what lets the fixture hand the
        // driver the same concrete `ErasedOwner` the bridge does.
        let out_rx: Box<dyn OutboundSource<NostrOutbound, Owner = ErasedOwner>> = Box::new(
            crate::ErasedSource::new(crate::UnboundedSource::new(out_rx)),
        );
        Arc::new(DriverShared {
            identity,
            room_handle: "test-room".into(),
            device_id: "self-device".into(),
            relays: Mutex::new(Vec::new()),
            outbound: tokio::sync::Mutex::new(Some(out_rx)),
            delivery: DeliveryStore::new(Arc::new(UnmeteredDeliveryProvider)),
            refusal_sink: Arc::new(UnmeteredAttemptRefusalSink),
            presence_tx: watch::channel(None).0,
            force_reconnect: Arc::new(watch::channel(0u64).0),
            relay_connected: Arc::new(watch::channel(0u64).0),
        })
    }

    /// Build a Nostr `EVENT` frame carrying an Announce envelope
    /// from a fixed peer. The event ID is whatever the signer
    /// produced; we wrap it the same way a relay would so
    /// `handle_inbound_frame` parses it exactly like in production.
    fn announce_frame_for(peer: &str, signer: &NostrIdentity) -> (String, String) {
        let envelope = SignalingEnvelope {
            from: peer.into(),
            to: None,
            msg: SignalingMessage::Announce {
                peer_id: peer.into(),
            },
        };
        let content = serde_json::to_string(&envelope).unwrap();
        let event = crate::nostr::event::make_event(
            signer,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            content,
            1_700_000_000,
        );
        let frame = serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&event).unwrap()])
            .to_string();
        (frame, event.id)
    }

    /// **The same event from two relays is offered onward twice, because this
    /// layer no longer decides what a duplicate is.**
    ///
    /// It used to. A ring of event ids sat in front of the envelope parse, and
    /// the second relay's copy was dropped here. That was one layer too early in
    /// two separate ways: the id was recorded before the value was offered, and
    /// the offer's result was discarded — so a copy the consumer refused under
    /// pressure still poisoned the id, and the copy that would have rescued the
    /// attempt was swallowed on its way past.
    ///
    /// What happens to the second copy downstream depends on what it is, and the
    /// two answers are different on purpose.
    ///
    /// *Stamped negotiation* — an offer, answer or candidate — carries the
    /// engine-minted attempt correlation, so the duplicate is collapsed once,
    /// downstream, after acceptance and against that exact attempt (see
    /// `engine::signaling_ingress`).
    ///
    /// *Presence* — an announce or a leave — carries no such stamp, and is not
    /// de-duplicated at all: one copy per relay reaches the engine, **by
    /// design**. `ensure_peer_session` is idempotent, so the second copy is a
    /// no-op rather than a second session, and the alternative — a driver-side
    /// ring keyed on event id — is exactly what was deleted here and for good
    /// reason. Saying "it is deduped downstream" of presence would be false.
    ///
    /// What this control fixes in place is that the driver does not *also* have
    /// an opinion about either class: two relay copies produce two offers, and a
    /// policy that quietly reappeared here would fail this line rather than
    /// silently double-guard the boundary.
    #[test]
    fn every_relay_copy_is_offered_onward_from_this_layer() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let (frame, _event_id) = announce_frame_for(&peer_pub, &peer_signer);
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");
        handle_inbound_frame(
            "wss://relay-b",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("dup parses");
        handle_inbound_frame(
            "wss://relay-c",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("dup parses");

        for relay in ["a", "b", "c"] {
            match rx.try_recv() {
                Ok(NostrInbound::PeerAnnounced { device_id, .. }) => {
                    assert_eq!(device_id, peer_pub, "relay {relay}'s copy names the peer")
                }
                other => panic!("relay {relay}'s copy must be offered onward, got {other:?}"),
            }
        }
        assert!(
            rx.try_recv().is_err(),
            "non-vacuity: three copies in, exactly three out — the layer is not \
             inventing deliveries either"
        );
    }

    /// Different events from the same peer (e.g. periodic re-announces)
    /// must NOT be deduped — each one is a fresh signal that signaling
    /// is alive.
    ///
    /// Nothing is dropped here on an event id, either. The relay-replay case —
    /// several copies of one event id arriving from several relays — is offered
    /// onward from this layer too, which is what the control above this one
    /// pins. What becomes of a duplicate is decided downstream and differs by
    /// class: stamped negotiation is collapsed against its exact attempt, while
    /// unstamped presence is intentionally not de-duplicated at all and reaches
    /// the engine once per relay copy.
    #[test]
    fn distinct_events_each_fire_inbound() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let (frame1, id1) = announce_frame_for(&peer_pub, &peer_signer);

        // Bump the timestamp so the second event hashes to a
        // different id (NIP-01 events are content-addressed).
        let envelope = SignalingEnvelope {
            from: peer_pub.clone(),
            to: None,
            msg: SignalingMessage::Announce {
                peer_id: peer_pub.clone(),
            },
        };
        let ev2 = crate::nostr::event::make_event(
            &peer_signer,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            serde_json::to_string(&envelope).unwrap(),
            1_700_000_005,
        );
        let frame2 =
            serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&ev2).unwrap()]).to_string();
        assert_ne!(id1, ev2.id, "test fixture: events must have distinct ids");

        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);
        handle_inbound_frame(
            "wss://relay-a",
            &frame1,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame 1 parses");
        handle_inbound_frame(
            "wss://relay-a",
            &frame2,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame 2 parses");

        assert!(matches!(
            rx.try_recv().expect("first announce"),
            NostrInbound::PeerAnnounced { .. }
        ));
        assert!(matches!(
            rx.try_recv().expect("second announce"),
            NostrInbound::PeerAnnounced { .. }
        ));
    }

    /// Build a directed Offer frame from `peer` to `to`, signed by
    /// `signer`, on the given Nostr `kind`. Used to exercise the
    /// presence/negotiation kind guard from both sides.
    fn offer_frame_for(peer: &str, to: &str, signer: &NostrIdentity, kind: u16) -> String {
        let envelope = SignalingEnvelope {
            from: peer.into(),
            to: Some(to.into()),
            msg: SignalingMessage::Offer {
                peer_id: peer.into(),
                offer_id: "off-1".into(),
                sdp: "v=0\r\n".into(),
            },
        };
        let content = serde_json::to_string(&envelope).unwrap();
        let event = crate::nostr::event::make_event(
            signer,
            kind,
            vec![vec!["r".into(), "test-room".into()]],
            content,
            1_700_000_000,
        );
        serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&event).unwrap()]).to_string()
    }

    /// A live offer on the ephemeral kind is delivered to the engine.
    #[test]
    fn offer_on_ephemeral_kind_is_delivered() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let frame = offer_frame_for(
            &peer_pub,
            "self-device",
            &peer_signer,
            SIGNALING_EPHEMERAL_KIND,
        );
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");

        match rx.try_recv().expect("offer delivered") {
            NostrInbound::Message { from, msg } => {
                assert_eq!(from, peer_pub);
                assert!(matches!(msg, SignalingMessage::Offer { .. }));
            }
            other => panic!("expected Message(Offer), got {other:?}"),
        }
    }

    /// The replay-poisoning fix: an offer that arrives on the STORED
    /// presence kind is replayed history (or a pre-split build), not a
    /// live negotiation. It must be dropped so it can never bind a
    /// fresh PeerConnection to dead ICE credentials.
    #[test]
    fn offer_on_stored_kind_is_dropped() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let frame = offer_frame_for(&peer_pub, "self-device", &peer_signer, SIGNALING_EVENT_KIND);
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");

        assert!(
            rx.try_recv().is_err(),
            "a directed offer on the stored kind must be dropped, not applied"
        );
    }

    /// Mirror guard: presence is only honoured on the stored kind, so
    /// an Announce wrongly published on the ephemeral kind is ignored.
    #[test]
    fn announce_on_ephemeral_kind_is_dropped() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let envelope = SignalingEnvelope {
            from: peer_pub.clone(),
            to: None,
            msg: SignalingMessage::Announce {
                peer_id: peer_pub.clone(),
            },
        };
        let ev = crate::nostr::event::make_event(
            &peer_signer,
            SIGNALING_EPHEMERAL_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            serde_json::to_string(&envelope).unwrap(),
            1_700_000_000,
        );
        let frame =
            serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&ev).unwrap()]).to_string();
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");

        assert!(
            rx.try_recv().is_err(),
            "an announce on the ephemeral kind must be dropped"
        );
    }

    /// **One subscription shape, and nothing a peer publishes can widen it.**
    ///
    /// The filter set used to be three: presence, directed-to-me, and — while
    /// any announced peer had not advertised the recipient-tag capability — a
    /// room-wide catch-all that asked the relay for every pairwise negotiation
    /// in the room. Whether the third one was attached was decided by an
    /// unbounded map keyed on unauthenticated announce ids, so one sender could
    /// hold it on for everybody and read the room's whole negotiation traffic.
    ///
    /// Both assertions are the fix, and each is the other's non-vacuity: there
    /// are exactly two filters, and every filter that asks for the negotiation
    /// kind names us as its recipient. A re-introduced catch-all fails the
    /// second even if it kept the count at two.
    #[test]
    fn the_subscription_asks_only_for_presence_and_directed_to_me() {
        let shared = fixture_shared();
        let filters = desired_filters(&shared);
        assert_eq!(
            filters.len(),
            2,
            "presence + directed-to-me, with no room-wide third"
        );
        assert_eq!(
            filters[0]["kinds"][0],
            serde_json::json!(SIGNALING_EVENT_KIND),
            "presence filter carries the stored kind"
        );
        for filter in &filters {
            if filter["kinds"][0] == serde_json::json!(SIGNALING_EPHEMERAL_KIND) {
                assert!(
                    filter
                        .get("#p")
                        .and_then(|p| p.as_array())
                        .is_some_and(|p| p.iter().any(|v| v == "self-device")),
                    "a negotiation filter must name us as the recipient; an \
                     unconstrained one is the amplification this deleted"
                );
            }
        }
    }

    #[test]
    fn build_req_replaces_same_sub_id() {
        let shared = fixture_shared();
        let req = build_req(&shared, "mom-sig-1");
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v[0], "REQ");
        assert_eq!(v[1], "mom-sig-1");
        assert_eq!(
            v.as_array().unwrap().len(),
            2 + 2,
            "REQ + sub id + the two filters"
        );
    }

    #[test]
    fn jitter_stays_within_15_percent_and_is_deterministic() {
        for salt in 0..64u64 {
            let w = jittered_ms(120_000, "some-device", salt);
            assert!((102_000..=138_000).contains(&w), "±15% bound, got {w}");
            assert_eq!(
                w,
                jittered_ms(120_000, "some-device", salt),
                "same inputs, same wait"
            );
        }
        // Different nodes land on different offsets (not all identical).
        let a = jittered_ms(120_000, "device-a", 1);
        let b = jittered_ms(120_000, "device-b", 1);
        let c = jittered_ms(120_000, "device-c", 1);
        assert!(
            !(a == b && b == c),
            "three nodes shouldn't share one jitter offset"
        );
        assert_eq!(jittered_ms(0, "x", 0), 0, "zero base stays zero");
    }
}
