//! Signaling for MyOwnMesh. Two strategies ship today — [`nostr`]
//! (the remote default, relay-based) and [`mdns`] (LAN-local DNS-SD
//! discovery + unicast TCP exchange, on by default alongside the
//! remote strategy) — and sibling crates can add others (BitTorrent
//! trackers, MQTT, IPFS, Firebase); the engine picks at construction
//! time.
//!
//! Wire-compatibility note: the room-handle derivation and relay
//! shuffle in [`nostr`] are byte-compatible with upstream Trystero
//! `0.24.x` so a future hybrid deployment (JS Trystero peers + Rust
//! MyOwnMesh peers, both using the same TRYSTERO_APP_ID) is
//! possible. By default the app-ids differ
//! (`myownmesh-cloud-mesh-v1` vs `myownllm-cloud-mesh-v1`) so the
//! two ecosystems never meet on the wire.
//!
//! See [`upstream`] for the catalogue of upstream Trystero
//! limitations this implementation works around natively — without
//! requiring users to apply patches.

pub mod local;
pub mod mdns;
pub mod nostr;
pub mod server;
pub mod upstream;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Signaling-layer capability id: the sender stamps a recipient tag on
/// every ephemeral event it publishes — `["p", <device id>]` on directed
/// offer / answer / candidate, `["p", <room handle>]` on room-addressed
/// broadcasts (`leave`) — so subscribers can ask the relay for "directed
/// to me (or the room)" instead of receiving every pairwise negotiation
/// in the room. Advertised in the announce's `caps` so receivers know
/// when the whole room tags — see `nostr::driver` for the adaptive
/// subscription that drops the legacy catch-all filter once it does.
pub const SIG_CAP_PTAG: &str = "ptag";

/// How a driver came by the device id in a presence or withdrawal report.
///
/// Every driver reports presence and withdrawal, and the two ways it can know
/// who the report is about are worth very different things:
///
/// - [`Self::CarrierObserved`] - the carrier established the id itself and the
///   sender could not choose it. **At this revision exactly one driver produces
///   it: the in-process [`local::LocalBroker`], which stamps the registered id
///   of the handle that sent.**
/// - [`Self::SenderClaimed`] - the id reached the driver inside something a
///   sender wrote, and nothing checked it against an authenticated identity. It
///   is a string the sender picked, and it may name somebody else. Nostr
///   announces and departures are this, because the body `peer_id` and the
///   envelope `from` are both authored by the sender rather than bound to the
///   relay event's pubkey. **mDNS is this too, including browse resolve,
///   expiry and goodbye**: the device id comes from the advertisement's TXT
///   record, which any LAN participant may write with any value, so the daemon
///   observing a record appear or vanish establishes that *a record* moved and
///   not whose device it names.
///
/// A driver may only move from the second to the first by gaining an
/// independently authenticated binding between what it observed and the device
/// key - not by observing more carefully.
///
/// Neither is an authority: a device is admitted by endpoint authentication and
/// policy, never by being named in a signaling report. The distinction exists so
/// the consumer can refuse to let the second cancel the first - which is the
/// difference between "the LAN stopped seeing this device" and "somebody sent a
/// payload saying so".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierAttribution {
    /// The carrier established the id itself.
    CarrierObserved,
    /// The id was decoded from a payload the sender wrote.
    SenderClaimed,
}

/// Where a driver pulls the engine events it is meant to publish.
///
/// # Why a driver no longer owns an outbound queue either
///
/// The mirror of [`InboundSink`], and the same defect on the other side. A
/// caller used to translate its own messages into the driver's types and push
/// them into an unbounded channel the driver drained. Those translations are
/// allocations that outlive the call that made them, and a single claim over
/// "the queue" does not bound them: the consumer says how many exist, and the
/// consumer was the queue.
///
/// So there is no queue here either. The driver awaits this, and whoever
/// implements it decides — under whatever accounting it answers to — when a
/// value exists at all. A translation is built at the moment the driver takes
/// it, so nothing is ever queued in a translated form.
///
/// `None` means the source is finished and the pump exits, exactly as a closed
/// channel did.
///
/// # Why a trait rather than a channel with an owner attached
///
/// An earlier revision passed an `OwnedQueue<T, O>` — a receiver bound to an
/// opaque owner dropped after it — so a driver could hold something it never
/// read and release it in the right order. That was the correct shape for a
/// queue whose contents the caller had already paid for wholesale, and the
/// wrong shape for the question actually being asked, which is whether each
/// value should exist. With the queue gone there is nothing to own: the source
/// yields one value at a time and the caller has already decided.
#[async_trait]
pub trait OutboundSource<T>: Send {
    /// The next value for this driver to publish, or `None` when finished.
    async fn recv(&mut self) -> Option<T>;
}

/// An unbounded channel as a source.
///
/// The standalone case, and the same bargain as [`InboundSink::from_unbounded`]:
/// an embedder with no accountant may absolutely choose a buffer, and this makes
/// that choice appear in the source of whoever chose it rather than being
/// something the driver imposes.
pub struct UnboundedSource<T> {
    rx: tokio::sync::mpsc::UnboundedReceiver<T>,
}

impl<T> UnboundedSource<T> {
    pub fn new(rx: tokio::sync::mpsc::UnboundedReceiver<T>) -> Self {
        Self { rx }
    }
}

#[async_trait]
impl<T: Send> OutboundSource<T> for UnboundedSource<T> {
    async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }
}

/// Where a driver hands what it decoded, and the only thing that decides
/// whether it is kept.
///
/// # Why a driver no longer owns an inbound queue
///
/// A driver used to be handed an unbounded sender and push decoded reports into
/// it. Everything on the far side of that push was funded — the engine admits
/// what it retains — but the queue itself was not, and the queue is exactly
/// where an unauthenticated carrier's traffic accumulates: a relay that outruns
/// the engine, or a LAN peer that multicasts as fast as it likes, grows it
/// without bound and without anyone accounting for a byte of it. Giving that
/// queue a fixed depth would only have moved the guess.
///
/// So there is no queue. The driver offers each value to the consumer directly,
/// and the consumer's own admission decides on the spot whether it is retained.
/// The work stays on the driver's task either way, so a consumer under pressure
/// does not silently become a place to store things.
///
/// # Why a closure rather than a resource type
///
/// This crate is used standalone, where there is no accountant to answer to, and
/// teaching it a resource vocabulary would make every consumer implement one.
/// The sink is a
/// function from a value to "keep going", and what happens inside it — a funded
/// mailbox, a test channel, an in-process broker — is entirely the consumer's.
///
/// # What `false` means, and what it deliberately does not
///
/// The one bit that comes back says whether the *consumer still exists*, not
/// whether this value was kept. A consumer that refuses a value under local
/// pressure returns `Ok(())`: pressure is a lossy moment, and a driver that
/// tore down its relays over one would turn a full queue into an outage. Only a
/// gone consumer is [`SinkClosed`], and that is a driver's signal to stop.
pub struct InboundSink<T> {
    offer: std::sync::Arc<dyn Fn(T) -> bool + Send + Sync>,
}

/// The consumer is gone. Every other outcome is `Ok(())`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkClosed;

impl<T> InboundSink<T> {
    /// Build a sink from the consumer's admission. `false` = the consumer is
    /// gone for good; every recoverable outcome is `true`.
    pub fn new(offer: impl Fn(T) -> bool + Send + Sync + 'static) -> Self {
        Self {
            offer: std::sync::Arc::new(offer),
        }
    }

    /// A sink backed by an unbounded channel.
    ///
    /// For a consumer that has chosen to hold its own queue — a control that
    /// wants to inspect what a driver produced, or a standalone embedder with no
    /// accountant. Named so that choosing an unbounded buffer is a thing that
    /// appears in the source of whoever chose it, rather than something a driver
    /// does to a caller who never asked.
    pub fn from_unbounded(tx: tokio::sync::mpsc::UnboundedSender<T>) -> Self
    where
        T: Send + 'static,
    {
        Self::new(move |value| tx.send(value).is_ok())
    }

    /// Offer one value. `Err(SinkClosed)` means stop.
    pub fn send(&self, value: T) -> std::result::Result<(), SinkClosed> {
        if (self.offer)(value) {
            Ok(())
        } else {
            Err(SinkClosed)
        }
    }
}

impl<T> Clone for InboundSink<T> {
    fn clone(&self) -> Self {
        Self {
            offer: std::sync::Arc::clone(&self.offer),
        }
    }
}

impl<T> std::fmt::Debug for InboundSink<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InboundSink")
    }
}

/// One signaling message — either an offer/answer SDP exchange, an
/// ICE candidate, or the periodic presence-announce. Each carries
/// the sender's peer-id (Device ID) so receivers route correctly.
///
/// Candidate payloads carry the full RTCIceCandidateInit-equivalent
/// shape so the receiving WebRTC stack can apply them verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalingMessage {
    Announce {
        peer_id: String,
        /// Signaling-layer capabilities of the announcing build (e.g.
        /// [`SIG_CAP_PTAG`]). `default` so pre-caps announces decode as
        /// an empty list — receivers treat empty as "legacy build".
        #[serde(default)]
        caps: Vec<String>,
    },
    Offer {
        peer_id: String,
        offer_id: String,
        sdp: String,
    },
    Answer {
        peer_id: String,
        offer_id: String,
        sdp: String,
    },
    Candidate {
        peer_id: String,
        candidate: String,
        #[serde(default)]
        sdp_mid: Option<String>,
        #[serde(default)]
        sdp_mline_index: Option<u16>,
        #[serde(default)]
        username_fragment: Option<String>,
    },
    /// A peer left the room. Sent two ways, both as a pure accelerator over
    /// the heartbeat-timeout fallback:
    ///
    /// - **Self-announced** by a peer making a deliberate exit (network
    ///   remove, transport restart, daemon shutdown) so the others drop its
    ///   session immediately rather than stranding on a dead connection
    ///   whose ICE still reports `Connected` for ~90 s. This is what makes a
    ///   "reconnect" (leave-then-rejoin) come back promptly.
    /// - **Synthesised** by an intelligent [`server`] relay the instant a
    ///   member's WebSocket closes, covering crashes / yanked cables where
    ///   the peer never got to announce.
    ///
    /// Public relays never synthesise it; on those, a deliberate exit still
    /// self-announces, and an ungraceful one falls back to timeout-based
    /// detection.
    Leave { peer_id: String },
}

/// Per-relay health snapshot. Diagnostic-only — surfaced via the
/// mesh's [`crate::upstream::SIGNALING_HEALTH`] feed so the UI can
/// show "5/5 relays open" or "2/5 relays open, 3 retrying".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayHealth {
    /// Socket is open and we've received at least one inbound EVENT
    /// since opening (or since the last subscription replay).
    Live,
    /// Socket is open but no inbound EVENT seen yet — could be a
    /// fresh connection or a stuck subscription.
    Opening,
    /// Socket connecting / reconnecting.
    Reconnecting,
    /// Backed off after repeated failures; will retry per the
    /// per-socket schedule.
    BackedOff,
    /// Permanently denied (in the user-configured denylist).
    Denied,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("websocket: {0}")]
    Socket(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("no relays available")]
    NoRelays,
    /// The self-hosted signaling [`server`] couldn't bind its listener.
    #[error("bind {0}: {1}")]
    Bind(String, #[source] std::io::Error),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Strategy-agnostic signaling channel. The mesh engine talks to one
/// of these per joined network. Implementations spin up their own
/// background tasks for socket lifecycle, message routing, etc.
#[async_trait]
pub trait SignalingChannel: Send + Sync {
    /// Publish a message to the network room. Returns once at least
    /// one relay has accepted the publish; failures past the first
    /// success are logged but not propagated.
    async fn send(&self, msg: &SignalingMessage) -> Result<()>;

    /// Best-effort snapshot of per-relay health. Used by the
    /// engine's signaling-health watchdog.
    fn relay_health(&self) -> Vec<(String, RelayHealth)>;

    /// Disconnect from all relays and stop background tasks.
    async fn close(&self);
}
