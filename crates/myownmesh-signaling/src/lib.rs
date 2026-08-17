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
    /// What travels with each value and outlives every allocation derived from
    /// it. Opaque here: this crate has no resource vocabulary and does not want
    /// one, so the owner is whatever the producer says it is.
    type Owner: Send;

    /// The next value for this driver to publish, or `None` when the source is
    /// **closed**.
    ///
    /// `None` is terminal and means exactly one thing: nothing will ever arrive
    /// again. Every driver pump here is a `while let Some(..)` loop, and two of
    /// them consume the source to run it, so a `None` returned for any lesser
    /// reason — a transient refusal, a value the producer chose not to build —
    /// would silently retire that carrier for the life of the process and leave
    /// whatever is behind it undrained. A producer that cannot supply *this*
    /// value must skip it and keep going, not report the end of the world.
    async fn recv(&mut self) -> Option<OwnedSignal<T, Self::Owner>>;
}

/// One outbound value and the owner that funds everything reachable from it.
///
/// # The invariant, and why it needs a type rather than a convention
///
/// ```text
/// translated allocation, encoded event, broadcast clone, or replay entry exists
///     -> the exact finite owner that admitted it also exists
/// ```
///
/// Removing the second queue between the engine and a driver was correct, and it
/// did not make a multi-kilobyte translated value free. A driver receives a
/// value the engine paid for, then serializes it, clones it into an `Arc`, fans
/// that to every relay task and keeps it in a replay buffer — and until now none
/// of those allocations carried anything back to what admitted them. The owner
/// travelled as far as the pump's stack frame and was dropped there.
///
/// This binds the two together in the type system. The value and the owner are
/// **private**, there is no accessor that yields the value alone, and there is
/// no `into_value`, `split` or `take` — so there is no expression anywhere that
/// separates one from the other. A consumer either borrows through
/// [`Self::value`], or transforms with [`Self::map`], which consumes the whole
/// thing and rebuilds it around the same owner. Both keep the pair intact.
///
/// Field order is load-bearing: Rust drops fields in declaration order, so the
/// value and everything derived from it are destroyed *before* the owner that
/// paid for them is released.
pub struct OwnedSignal<T, O> {
    value: T,
    owner: O,
}

impl<T, O> OwnedSignal<T, O> {
    /// Pair a value with the owner that funds it.
    ///
    /// The owner has to be acquired **before** the value is built — the whole
    /// point is that a refusal happens instead of an allocation, not after one.
    /// This constructor cannot enforce that ordering; the producer's own
    /// acquire-then-translate sequence does, and every producer in this
    /// workspace does it that way.
    pub fn new(value: T, owner: O) -> Self {
        Self { value, owner }
    }

    /// Borrow the value. The only way to read it.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Transform the value, carrying the same owner onto the result.
    ///
    /// Consuming rather than borrowing, so a caller cannot end up holding the
    /// old value and the new one with one owner between them. This is how an
    /// encoded form — a serialized frame, a wire line — inherits the funding of
    /// the value it was encoded from instead of becoming an unowned allocation
    /// beside it.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> OwnedSignal<U, O> {
        OwnedSignal {
            value: f(self.value),
            owner: self.owner,
        }
    }
}

/// An owner whose type a driver does not need to know.
///
/// A driver holds the owner and never inspects it — that is the entire contract
/// — so the type it is holding buys nothing and costs a generic parameter on
/// every piece of shared state the value can reach: a connection table, a
/// broadcast bus, a replay buffer. Erasing it at the boundary keeps that state
/// concrete.
///
/// # Why `Sync` is in the bound and is not a convenience
///
/// The Nostr driver shares one published event across relay tasks as an `Arc`,
/// and `Arc<T>` is only `Send` when `T` is `Send + Sync`. A `Box<dyn Send>`
/// owner would therefore have made the broadcast bus un-sendable, and the
/// tempting repair — an `unsafe impl`, or a mutex around something that is never
/// mutated — would have been papering over a genuine constraint.
///
/// It is not one. The only owner this workspace erases is core's, and every part
/// of it is `Sync` already: a resource lease is an `Arc<dyn ResourceProvider>`
/// (that trait requires `Send + Sync`), an `Arc`-backed scope, a plain claim and
/// an authority tag; a mailbox delivery is that lease plus a value that is
/// itself plain data. So the bound is satisfied by what actually flows through
/// here, and requiring it is the smallest sound shape rather than the widest
/// convenient one. A future owner that genuinely is not `Sync` will fail to
/// erase — which is the correct outcome, because it also could not be shared
/// across the relay tasks that make this driver work.
pub type ErasedOwner = Box<dyn Send + Sync>;

impl<T, O: Send + Sync + 'static> OwnedSignal<T, O> {
    /// Forget the owner's *type*, not the owner.
    ///
    /// This is not a split: the pair survives, the value is still unreachable
    /// except by borrow, and the owner is still dropped after everything derived
    /// from the value. Only the static type of the thing being held changes, and
    /// a driver that cannot name it also cannot release it early.
    pub fn erase_owner(self) -> OwnedSignal<T, ErasedOwner> {
        OwnedSignal {
            value: self.value,
            owner: Box::new(self.owner),
        }
    }
}

/// A boxed source is a source.
///
/// Needed because the drivers take `S: OutboundSource<..>` by value now, and the
/// bridge hands them a trait object: without this, every call site would have to
/// choose between a box and a generic. Pure forwarding — it adds no behaviour and
/// cannot observe the owner.
#[async_trait]
impl<T, S> OutboundSource<T> for Box<S>
where
    T: Send,
    S: OutboundSource<T> + ?Sized + Send,
{
    type Owner = S::Owner;

    async fn recv(&mut self) -> Option<OwnedSignal<T, Self::Owner>> {
        (**self).recv().await
    }
}

/// A source whose owner type has been erased, so a driver's shared state can
/// stay concrete while the producer keeps whatever owner it needs.
pub struct ErasedSource<S>(S);

impl<S> ErasedSource<S> {
    pub fn new(source: S) -> Self {
        Self(source)
    }
}

#[async_trait]
impl<T, S> OutboundSource<T> for ErasedSource<S>
where
    T: Send,
    S: OutboundSource<T> + Send,
    S::Owner: Sync + 'static,
{
    type Owner = ErasedOwner;

    async fn recv(&mut self) -> Option<OwnedSignal<T, ErasedOwner>> {
        Some(self.0.recv().await?.erase_owner())
    }
}

impl<T: std::fmt::Debug, O> std::fmt::Debug for OwnedSignal<T, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedSignal")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
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
    /// **Explicitly nothing.** A standalone embedder has no accountant to name,
    /// so saying so in the type is more honest than inventing a placeholder
    /// owner that funds nothing. The unit owner also makes the two cases easy to
    /// tell apart when reading a driver: `O = ()` is the no-accountant path, and
    /// anything else came from a producer that had one.
    type Owner = ();

    async fn recv(&mut self) -> Option<OwnedSignal<T, ()>> {
        Some(OwnedSignal::new(self.rx.recv().await?, ()))
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
    /// Presence. Carries the announcing device and nothing else.
    ///
    /// It used to carry a capability list too, so a receiver could discover
    /// whether the whole room spoke the recipient-tagged shape and widen its
    /// subscription if not. That negotiation is gone: the cutover is hard, peers
    /// are same-build, and there is no downgrade for a capability list to
    /// select. Announces from a build that still sends one decode fine — serde
    /// ignores the field — and nothing reads it.
    Announce { peer_id: String },
    /// The offer that opens one connection attempt.
    ///
    /// `offer_id` is the **attempt correlation**: one opaque value minted once
    /// by the offering side, carried identically by every carrier this offer
    /// fans out to, echoed back on the [`Self::Answer`], and stamped on every
    /// [`Self::Candidate`] belonging to the same attempt.
    ///
    /// It used to be none of that. Each carrier's translation minted its own
    /// value, and the answer sent an empty string, so the field named nothing
    /// two parties could agree on and the two copies of one fanned-out offer
    /// disagreed about it. It is now the only thing that says which attempt a
    /// signal belongs to.
    ///
    /// **Correlation only, never authority.** It is sender-chosen and
    /// unauthenticated, so it may scope de-duplication and nothing else: it
    /// admits nobody, names no route, orders nothing, and no decision reads it
    /// as a preference.
    Offer {
        peer_id: String,
        offer_id: String,
        sdp: String,
    },
    /// The answer to one attempt. `offer_id` echoes the offer's correlation
    /// verbatim — see [`Self::Offer`].
    Answer {
        peer_id: String,
        offer_id: String,
        sdp: String,
    },
    /// One ICE candidate for an attempt in progress. `offer_id` carries the
    /// same attempt correlation — see [`Self::Offer`].
    ///
    /// `default` because a candidate's correlation is newer than the field's
    /// two siblings; an old frame without one decodes to the empty string,
    /// which correlates with nothing and is simply not de-duplicated.
    Candidate {
        peer_id: String,
        candidate: String,
        #[serde(default)]
        offer_id: String,
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
    ///   remove, transport restart, daemon shutdown).
    /// - **Synthesised** by an intelligent [`server`] relay the instant a
    ///   member's WebSocket closes, covering crashes / yanked cables where
    ///   the peer never got to announce.
    ///
    /// # What a receiver may do with it, which is less than this used to claim
    ///
    /// It is **reachability evidence, not a teardown**. This frame carries a
    /// device id out of a body the sender wrote, and nothing on a network
    /// carrier authenticated that the sender is the device it names. A receiver
    /// may use it to stop pacing a dial or to cancel speculative work that never
    /// became a session; it may not use it to retire a session holding a
    /// promoted capability, and on a network carrier it retires nothing in any
    /// state.
    ///
    /// Prompt teardown belongs to the authenticated `SessionControl::Depart`
    /// sent over the session itself, where the sender is known. This frame is a
    /// hint that may arrive first, and the backstops behind it are exact
    /// connector closure and the heartbeat timeout.
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
