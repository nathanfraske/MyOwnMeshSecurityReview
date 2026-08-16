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
/// - [`Self::CarrierObserved`] - the carrier itself knows. The in-process
///   broker stamps the registered id of the handle that sent; mDNS resolved or
///   expired its own browse record. The sender did not choose it.
/// - [`Self::SenderClaimed`] - the id was decoded out of a signaling payload.
///   It is never checked against the relay event's pubkey or the wire source,
///   so it is not an authenticated identity; it is a string the sender picked,
///   and it may name somebody else.
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

/// A driver queue's receiver and whatever the caller says funds it, in that
/// order.
///
/// # Why a driver takes an owner it never reads
///
/// The engine accounts for memory it hands to a driver, and a driver's outbound
/// queue is memory the engine fills: it translates its own messages into the
/// driver's types and pushes them in. Those translations are allocations that
/// outlive the call that made them, and nothing owned them once they were in
/// the queue.
///
/// This crate does not learn a resource vocabulary to fix that, and should not
/// — it is used standalone, where there is no accountant to answer to. It takes
/// an opaque `O` instead: it never reads it, never looks inside, never bounds
/// it beyond thread-safety, and guarantees only *when* it is dropped. That
/// guarantee is the whole contract.
///
/// # Why the order is the point
///
/// `rx` is declared first, so it is dropped first, and dropping it drops
/// everything still sitting in the queue — only then is the owner released.
/// Rust drops struct fields in declaration order, so this holds however the
/// value dies: a clean shutdown, a task cancelled mid-`recv`, a panic unwinding
/// through the driver. A pair of local `drop` calls at the end of a loop would
/// have covered only the first of those, and *locals* drop in the reverse of
/// the order they are declared, which is the opposite of what is wanted here
/// and easy to write backwards.
///
/// # Why `O` is generic rather than `Box<dyn Send + Sync>`
///
/// A box would have been simpler to pass around and wrong twice over. It is an
/// allocation of its own, which the engine would then have to account for; and
/// worse, `Box<T>` drops its payload *before* it frees its allocation, so a
/// boxed lease would release the claim and only then deallocate the box that
/// claim was supposed to cover. That is a false-release interval — the exact
/// defect this ordering exists to remove, reintroduced by the mechanism meant
/// to remove it. Storing `O` inline has neither problem: nothing is allocated,
/// and the owner is released after the values it stands for.
///
/// `O = ()` is the standalone case, costs nothing, and is what every
/// pre-existing entry point passes.
pub struct OwnedQueue<T, O> {
    rx: tokio::sync::mpsc::UnboundedReceiver<T>,
    _owner: O,
}

impl<T, O> OwnedQueue<T, O> {
    /// Bind a receiver to its owner.
    pub fn new(rx: tokio::sync::mpsc::UnboundedReceiver<T>, owner: O) -> Self {
        Self { rx, _owner: owner }
    }

    /// Receive the next queued value, as [`tokio::sync::mpsc::UnboundedReceiver::recv`].
    ///
    /// Deliberately the only way in: there is no accessor that hands out the
    /// receiver, because a caller holding the receiver alone could outlive the
    /// owner, and that is the state this type exists to rule out.
    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await
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
