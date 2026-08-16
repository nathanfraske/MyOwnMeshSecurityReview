//! The Signaling Node's ephemeral-transport ingress: the one place a carrier
//! observation is admitted, and the only place it becomes an engine domain
//! value.
//!
//! `ARCHITECTURE.md` §4 states that signaling carries two disjoint categories —
//! durable semantic exchange and ephemeral transport control — and
//! `CURRENT-TO-TARGET-MIGRATION-MATRIX.md` requires that the two be
//! distinguished "before domain parsing". **This module is the ephemeral one,
//! and it is the only one that exists.** No carrier variant carries a durable
//! signed fact, so there is no durable ingress to write and none is pretended:
//! the distinction is carried by the type this module produces rather than by a
//! tag whose other value nothing can hold.
//!
//! What is enforced, and enforced by the compiler rather than by convention:
//!
//! - A carrier pump can only build a [`CarrierObservation`], whose constructors
//!   decide the [`EphemeralSignal`] kind. The parse into a domain value lives
//!   behind [`CarrierObservation::into_ingress`] and is private here, so
//!   "admit, then parse" is the only sequence that compiles.
//! - [`admit`] and [`outbound_signal`] are exhaustive with no wildcard arm. A
//!   new carrier variant does not inherit a kind; whoever adds one has to come
//!   here and say what it is, and a variant that is *not* ephemeral transport
//!   control has no kind to choose — which is the review this boundary exists
//!   to force.
//!
//! [`SignalingRuntime`] is the owner on this side of the boundary: it mints one
//! opaque [`CarrierInstance`] per attach, owns cross-carrier de-duplication, and
//! owns availability — which carrier instances currently observe a device — so
//! that a withdrawal reaches the engine as evidence of unreachability rather
//! than as one carrier's opinion.
//!
//! # What this boundary is not
//!
//! It moves no traffic on its own. It adds no anti-entropy, no proof delivery,
//! no retry, timer, poll, or acknowledgement, and it changes no eviction
//! behaviour. Nothing here can grant, revoke, or record membership.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{trace, warn};

use myownmesh_signaling::SignalingMessage;

use crate::resource::{
    mailbox_retained_claim, ResourceClaim, ResourceMailboxItem, ResourceMailboxItemError,
    ResourceMailboxSendError, ResourceMailboxSender,
};
use crate::transport::LocalIceCandidate;

use super::state::{SignalingInbound, SignalingOutbound};

/// Which carrier observed a signaling message.
///
/// **Bounded provenance, and the bound is the point.** A closed set of three
/// unit variants: it records that a message arrived over the LAN rather than a
/// relay, and nothing else. No relay URL, no socket, no address, no key and no
/// peer-supplied string, so it cannot grow into a second identity for a device.
/// `Signaling Node` in `TRANSITION-PLAYBOOK.md` §6 owns "bounded carrier
/// provenance" and must never own "endpoint identity"; a closed enum is how
/// those two stay different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalingCarrier {
    /// The in-process [`myownmesh_signaling::local::LocalBroker`].
    Local,
    /// The Nostr relay driver.
    Nostr,
    /// The LAN mDNS driver.
    Mdns,
}

impl SignalingCarrier {
    /// Stable lowercase name for traces and diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Nostr => "nostr",
            Self::Mdns => "mdns",
        }
    }

    /// Whether this carrier can return one emission as two different-looking
    /// messages, which is the only thing de-duplication is for.
    ///
    /// Nostr and mDNS each stamp their own envelope — a different event id, a
    /// different offer id — around a payload the engine sent once, so a fan-out
    /// to both comes back twice and only the content identifies the pair.
    /// Applying the same remote description twice wedges WebRTC permanently.
    ///
    /// The in-process broker stamps nothing: a repeat over it is a genuine
    /// repeat send, which is the engine's own retry pacing, and swallowing it
    /// would silently change the behaviour the deterministic suite runs on.
    fn restamps_duplicates(self) -> bool {
        match self {
            Self::Local => false,
            Self::Nostr | Self::Mdns => true,
        }
    }
}

/// One attach of one carrier, as an opaque process-local receipt.
///
/// **Opaque, process-local, and not peer-choosable.** The wrapped counter is
/// minted by [`SignalingRuntime::attach`] and never leaves the process: it is
/// not on any wire, not derived from anything a peer sends, and carries no
/// address, relay or key. It is a receipt for "this attach of this carrier", so
/// that when the same driver is detached and reattached the availability the old
/// attach claimed does not survive as the new one's.
///
/// It is deliberately **not** a route identity and not a path generation: it
/// names no path, orders nothing, and no decision anywhere reads it as a
/// preference. The only questions it answers are "same attach?" and "how many
/// distinct attaches still see this device?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CarrierInstance(u64);

/// How a carrier came by the device id in a presence or withdrawal report.
///
/// Re-exported from the signaling crate rather than restated here: the driver
/// that saw the message arrive is the only thing that can honestly decide this,
/// so the type belongs where the decision is made and a second copy on this side
/// would be a place for the two to disagree.
///
/// What this side does with it: a [`CarrierAttribution::SenderClaimed`]
/// withdrawal cannot cancel a [`CarrierAttribution::CarrierObserved`] presence,
/// so naming a third party in a payload cannot make the runtime forget that the
/// third party is reachable. Neither value mints authority — a device is
/// admitted by endpoint authentication and policy, never by being named here.
pub(crate) use myownmesh_signaling::CarrierAttribution;

/// The ephemeral transport signal kinds this ingress admits.
///
/// `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md` §2.2 defines the ephemeral
/// transport signal as a typed, bounded union unavailable as a generic
/// application byte carrier. This is that union as this codebase inhabits it,
/// and its closure is the implementation refinement `FORMAL-PROOFS.md` Theorem
/// 11.1 asks for: the theorem holds only if the signaling union has no variant
/// containing application bytes and an application consumer, and this has no
/// such variant. It equally has no durable-authority, roster-mutation or
/// durable-leave kind, which is how a carrier observation stays unable to grant,
/// revoke or record membership however the carrier is fed.
///
/// It is decided from the carrier value **before** the domain parse, and it is
/// read in production — [`SignalingRuntime`] keys de-duplication and
/// availability off it — so it is a working part rather than a tag kept alive to
/// look complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EphemeralSignal {
    /// A carrier saw a device advertise itself. Discovery evidence only: it
    /// records nothing durable and admits nobody.
    Presence,
    /// A carrier stopped seeing a device, or a device said it was going.
    /// Reachability evidence about the live attempt — never the roster, never a
    /// durable fact, and never enough to retire an authenticated session.
    Withdrawal,
    /// Connect intent: the offer that opens one transport attempt.
    ConnectIntent,
    /// The answer to one transport attempt.
    ConnectAnswer,
    /// One ICE candidate hint for an attempt in progress.
    CandidateHint,
}

impl EphemeralSignal {
    /// Stable name for traces and diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Presence => "presence",
            Self::Withdrawal => "withdrawal",
            Self::ConnectIntent => "connect_intent",
            Self::ConnectAnswer => "connect_answer",
            Self::CandidateHint => "candidate_hint",
        }
    }

    /// Whether this kind reports on a device's availability rather than on one
    /// transport attempt.
    fn is_availability(self) -> bool {
        matches!(self, Self::Presence | Self::Withdrawal)
    }
}

/// One carrier observation whose kind has been decided and whose domain value
/// does not exist yet.
///
/// Built by a driver pump directly from what the carrier reported, which is why
/// the constructors take the carrier's own shape rather than anything the engine
/// understands. The kind is fixed at construction, so by the time
/// [`Self::into_ingress`] runs the admission has already happened and cannot be
/// influenced by the parse.
///
/// No `Debug`, deliberately: this holds the undecided carrier message whole —
/// SDP body, candidate string, device ids — one step upstream of the point where
/// [`EphemeralIngress`]'s redacting formatter takes over. A derive here would
/// hand that payload a formatter before the redaction exists.
#[must_use = "an observation that is never delivered is a message silently dropped"]
pub(crate) struct CarrierObservation {
    carrier: SignalingCarrier,
    instance: CarrierInstance,
    signal: EphemeralSignal,
    body: ObservationBody,
}

/// What the carrier actually reported. Private: the parse below is the only
/// consumer, and keeping the shape closed here is what stops a caller from
/// assembling a domain value without an admission. No `Debug`, for the reason
/// given on [`CarrierObservation`]: this is where the payload lives.
enum ObservationBody {
    Presence {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Withdrawal {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Directed {
        from: String,
        message: SignalingMessage,
    },
}

impl CarrierObservation {
    /// Parse into the engine's domain value, keeping the provenance.
    ///
    /// The only route from a carrier value to a [`SignalingInbound`] the engine
    /// can be handed, and it is reachable only from a value already admitted.
    pub(super) fn into_ingress(self) -> EphemeralIngress {
        let Self {
            carrier,
            instance,
            signal,
            body,
        } = self;
        let (inbound, attribution) = match body {
            ObservationBody::Presence {
                device_id,
                attribution,
            } => (SignalingInbound::PeerAnnounced { device_id }, attribution),
            ObservationBody::Withdrawal {
                device_id,
                attribution,
            } => (SignalingInbound::PeerLeft { device_id }, attribution),
            // A directed message is attributed to the sender the carrier routed
            // from, which for the two network carriers is itself a decoded
            // field — hence `SenderClaimed`. See [`parse_directed`].
            ObservationBody::Directed { from, message } => (
                parse_directed(from, message),
                CarrierAttribution::SenderClaimed,
            ),
        };
        EphemeralIngress {
            carrier,
            instance,
            signal,
            attribution,
            inbound,
        }
    }
}

/// An admitted, parsed ephemeral transport signal on its way to the engine.
///
/// This is what the engine's inbound mailbox carries. The carrier, the attach
/// instance and the attribution travel with the value rather than being computed
/// and discarded at the boundary, because "retained provenance" only means
/// something if the consumer can still see it.
pub(crate) struct EphemeralIngress {
    carrier: SignalingCarrier,
    instance: CarrierInstance,
    signal: EphemeralSignal,
    attribution: CarrierAttribution,
    inbound: SignalingInbound,
}

/// Redacting, and the derive it replaces was the reason.
///
/// A derived `Debug` prints the whole [`SignalingInbound`]: the full SDP body of
/// an offer or answer, the candidate string with its addresses, and the device
/// id. Those reach a log the moment anything formats a value with `{:?}` — a
/// `tracing` field, an `unwrap` message, a panic payload — and none of those call
/// sites has to be reviewed for it to happen.
///
/// What remains is bounded and closed — three field-less enums, a process-local
/// counter, and a `&'static str` — so nothing peer-supplied can appear here
/// however the peer builds its message. `finish_non_exhaustive` prints the
/// trailing `..`, so a reader sees that something was withheld rather than
/// believing the value is this small. The payload is not lost, only unprinted.
impl std::fmt::Debug for EphemeralIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralIngress")
            // The stable names rather than the derived variant spellings, so a
            // `Debug` line and a `tracing` line read the same way.
            .field("carrier", &self.carrier.name())
            .field("instance", &self.instance.0)
            .field("signal", &self.signal.name())
            .field("attribution", &self.attribution)
            .field("kind", &self.inbound.kind_name())
            .finish_non_exhaustive()
    }
}

impl EphemeralIngress {
    /// Which carrier observed it.
    pub(crate) fn carrier(&self) -> SignalingCarrier {
        self.carrier
    }

    /// Which attach of that carrier observed it.
    ///
    /// `cfg(test)`: production acts on the instance only inside this module,
    /// where the runtime owns the value and reads it off the field. The controls
    /// read it through here to assert what the engine would see if it ever
    /// asked, which is the one question the field access cannot answer.
    #[cfg(test)]
    pub(crate) fn instance(&self) -> CarrierInstance {
        self.instance
    }

    /// The kind this input was admitted as, before it was parsed.
    pub(crate) fn signal(&self) -> EphemeralSignal {
        self.signal
    }

    /// How the carrier came by the device id.
    ///
    /// **Production, and narrowly so.** One consumer outside this module: the
    /// carrier-withdrawal arm in `engine/mod.rs`, where a `SenderClaimed`
    /// withdrawal is teardown-inert in every session state and only a
    /// `CarrierObserved` one may retire a session that is not live. That
    /// decision cannot be made here — the runtime owns reachability, not the
    /// Peer Session lifecycle — so the value has to survive the boundary rather
    /// than being consumed at it. Nothing else reads it.
    pub(crate) fn attribution(&self) -> CarrierAttribution {
        self.attribution
    }

    /// The parsed input, borrowed.
    pub(crate) fn inbound(&self) -> &SignalingInbound {
        &self.inbound
    }

    /// Take the parsed input, dropping the provenance.
    pub(crate) fn into_inbound(self) -> SignalingInbound {
        self.inbound
    }

    /// Variant name for driver-liveness traces — cheap, no payload.
    pub(crate) fn kind_name(&self) -> &'static str {
        self.inbound.kind_name()
    }
}

#[cfg(test)]
impl EphemeralIngress {
    /// Build a delivered value without a runtime, for engine controls that hand
    /// one straight to a handler instead of driving a carrier.
    ///
    /// **This bypasses the runtime, not the admission.** The kind still comes
    /// from the same constructors production uses, and the parse is still
    /// [`CarrierObservation::into_ingress`], so a control cannot manufacture a
    /// shape production could not produce — it only skips the de-duplication and
    /// availability the runtime would have applied on the way past, which is
    /// exactly what a handler-level control is not testing.
    fn for_control(
        carrier: SignalingCarrier,
        signal: EphemeralSignal,
        body: ObservationBody,
    ) -> Self {
        CarrierObservation {
            carrier,
            instance: CarrierInstance(0),
            signal,
            body,
        }
        .into_ingress()
    }

    /// A carrier saw a device advertise itself. See [`Self::for_control`].
    pub(crate) fn presence_for_control(carrier: SignalingCarrier, device_id: &str) -> Self {
        Self::for_control(
            carrier,
            EphemeralSignal::Presence,
            ObservationBody::Presence {
                device_id: device_id.to_string(),
                attribution: CarrierAttribution::CarrierObserved,
            },
        )
    }

    /// A carrier stopped seeing a device, or a payload said it had.
    ///
    /// The attribution is a parameter and not a default, because it is the one
    /// thing the engine's withdrawal arm reads: a control that could only build
    /// the carrier-observed shape could not tell the two rules apart. See
    /// [`Self::for_control`].
    pub(crate) fn withdrawal_for_control(
        carrier: SignalingCarrier,
        device_id: &str,
        attribution: CarrierAttribution,
    ) -> Self {
        Self::for_control(
            carrier,
            EphemeralSignal::Withdrawal,
            ObservationBody::Withdrawal {
                device_id: device_id.to_string(),
                attribution,
            },
        )
    }

    /// A peer addressed us directly. See [`Self::for_control`].
    pub(crate) fn directed_for_control(
        carrier: SignalingCarrier,
        from: &str,
        message: SignalingMessage,
    ) -> Self {
        Self::for_control(
            carrier,
            admit(&message),
            ObservationBody::Directed {
                from: from.to_string(),
                message,
            },
        )
    }
}

impl ResourceMailboxItem for EphemeralIngress {
    fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
        // Carrier, instance, signal and attribution are `Copy` and field-less or
        // a counter: they reach nothing, allocate nothing, and their inline bytes
        // are already inside `size_of::<Self>()`. So the measurement is the
        // inbound value's, priced against this type's own footprint.
        let measure = self.inbound.string_measure()?;
        mailbox_retained_claim::<Self>(measure.0, measure.1, measure.2)
    }
}

/// Admit one carrier message as an ephemeral transport signal, before it is
/// translated.
///
/// Exhaustive with no wildcard arm, by design: a new carrier variant must not be
/// able to reach the engine by inheriting some default kind. Adding one to
/// [`SignalingMessage`] breaks this match, and the break is the review — a
/// variant that carries a durable signed fact has no kind here to choose and
/// needs its own ingress rather than a seat in this one.
fn admit(message: &SignalingMessage) -> EphemeralSignal {
    match message {
        SignalingMessage::Announce { .. } => EphemeralSignal::Presence,
        SignalingMessage::Leave { .. } => EphemeralSignal::Withdrawal,
        SignalingMessage::Offer { .. } => EphemeralSignal::ConnectIntent,
        SignalingMessage::Answer { .. } => EphemeralSignal::ConnectAnswer,
        SignalingMessage::Candidate { .. } => EphemeralSignal::CandidateHint,
    }
}

/// Admit one outbound emission.
///
/// The boundary is two-sided for the same reason it is exhaustive: a new
/// outbound variant must choose a kind rather than acquire one, where the fan-out
/// can see it rather than at whichever driver happens to carry it.
pub(crate) fn outbound_signal(outbound: &SignalingOutbound) -> EphemeralSignal {
    match outbound {
        SignalingOutbound::Announce => EphemeralSignal::Presence,
        SignalingOutbound::Leave => EphemeralSignal::Withdrawal,
        SignalingOutbound::Offer { .. } => EphemeralSignal::ConnectIntent,
        SignalingOutbound::Answer { .. } => EphemeralSignal::ConnectAnswer,
        SignalingOutbound::Candidate { .. } => EphemeralSignal::CandidateHint,
    }
}

/// Translate one directed carrier message into the engine's inbound shape.
///
/// **Private, and reachable only through [`CarrierObservation::into_ingress`].**
/// This is the domain parse the migration matrix requires admission to precede;
/// a `pub` version, or one beside the driver pumps, would let a caller skip
/// straight to a domain value and the ordering would be a convention again.
///
/// # `from` wins over the body, and what that is worth by carrier
///
/// Every variant with a device id in its body is attributed to `from` instead.
/// On `LocalBroker` that is genuine routing attribution — the broker stamps the
/// sending handle's registered id and the sender cannot choose it. On Nostr and
/// mDNS it is a decoded field of the signaling envelope, never checked against
/// the relay event's pubkey or the wire source, so there it buys consistency
/// rather than proof; that is why a directed observation is delivered as
/// [`CarrierAttribution::SenderClaimed`].
///
/// The load-bearing part does not depend on either field being trustworthy:
/// **neither one mints authority**, because no kind in [`EphemeralSignal`] could.
/// What the rule buys everywhere is that when the two fields disagree — exactly
/// when somebody is naming a third party — the effect lands on the sender rather
/// than on a device that sent nothing.
fn parse_directed(from: String, message: SignalingMessage) -> SignalingInbound {
    match message {
        SignalingMessage::Announce { peer_id, caps } => {
            let _ = (peer_id, caps);
            SignalingInbound::PeerAnnounced { device_id: from }
        }
        SignalingMessage::Leave { peer_id } => {
            let _ = peer_id;
            SignalingInbound::PeerLeft { device_id: from }
        }
        SignalingMessage::Offer { sdp, .. } => SignalingInbound::Offer {
            device_id: from,
            sdp,
        },
        SignalingMessage::Answer { sdp, .. } => SignalingInbound::Answer {
            device_id: from,
            sdp,
        },
        SignalingMessage::Candidate {
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment,
            ..
        } => SignalingInbound::Candidate {
            device_id: from,
            candidate: LocalIceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
            },
        },
    }
}

/// Window of the cross-carrier de-duplication ring. Same order of magnitude as
/// the Nostr driver's per-event ring — comfortably covers the busiest realistic
/// mesh without unbounded growth.
const SEEN_CAPACITY: usize = 2048;

/// How many devices the availability owner will track at once.
///
/// A bound, not a budget: it is not a peer limit and nothing reads it as one.
/// Past it, a device the runtime is not tracking has its withdrawals delivered
/// unconditionally — the behaviour this owner refines, so overflow degrades to
/// the plain hint rather than to silence.
const AVAILABILITY_CAPACITY: usize = 2048;

/// The Signaling Node's runtime owner for one network.
///
/// Owns exactly three things, and each is one this side of the boundary is
/// entitled to: the [`CarrierInstance`] receipts it mints at attach,
/// cross-carrier de-duplication, and availability. It owns no roster decision,
/// no endpoint identity and no application delivery, and it has no way to
/// acquire one — everything it can emit is a [`SignalingInbound`], which is the
/// [`EphemeralSignal`] union and nothing else.
pub(crate) struct SignalingRuntime {
    tx: ResourceMailboxSender<EphemeralIngress>,
    instances: AtomicU64,
    seen: Mutex<VecDeque<u64>>,
    /// Which attaches currently observe each device, and whether any of those
    /// observations was the carrier's own rather than a sender's claim.
    availability: Mutex<HashMap<String, Availability>>,
}

/// Per-device availability: who still sees it, and on what evidence.
#[derive(Default)]
struct Availability {
    observed: HashSet<CarrierInstance>,
    claimed: HashSet<CarrierInstance>,
}

impl SignalingRuntime {
    pub(crate) fn new(tx: ResourceMailboxSender<EphemeralIngress>) -> Arc<Self> {
        Arc::new(Self {
            tx,
            instances: AtomicU64::new(0),
            seen: Mutex::new(VecDeque::with_capacity(SEEN_CAPACITY)),
            availability: Mutex::new(HashMap::new()),
        })
    }

    /// Register one carrier attach and hand back its ingress.
    ///
    /// The receipt is minted here and nowhere else, which is what makes it a
    /// receipt: a pump cannot invent an instance, and two attaches of the same
    /// carrier are distinguishable without either of them naming anything.
    pub(crate) fn attach(runtime: &Arc<Self>, carrier: SignalingCarrier) -> CarrierAttach {
        CarrierAttach {
            carrier,
            instance: CarrierInstance(runtime.instances.fetch_add(1, Ordering::Relaxed)),
            runtime: Arc::clone(runtime),
        }
    }

    /// Deliver an admitted observation, unless the runtime owns a reason not to.
    ///
    /// Returns `false` once the engine side is gone, which is the pump's signal
    /// to exit. Every other outcome is `true`: signaling ingress is explicitly
    /// lossy under local resource pressure, and a dropped observation leaves a
    /// later bounded one to recover the connection.
    fn deliver(&self, observation: CarrierObservation) -> bool {
        let ingress = observation.into_ingress();

        if ingress.signal.is_availability() {
            if !self.record_availability(&ingress) {
                return true;
            }
        } else if let Some(key) = ingress
            .carrier
            .restamps_duplicates()
            .then(|| dedup_key(&ingress))
            .flatten()
        {
            let mut seen = self.seen.lock();
            if seen.contains(&key) {
                trace!(
                    kind = ingress.kind_name(),
                    "cross-carrier duplicate dropped"
                );
                return true;
            }
            if seen.len() >= SEEN_CAPACITY {
                seen.pop_front();
            }
            seen.push_back(key);
        }

        let kind = ingress.kind_name();
        match self.tx.send(ingress) {
            Ok(()) => true,
            Err(ResourceMailboxSendError::Closed(_)) => false,
            Err(ResourceMailboxSendError::Pressure { error, .. }) => {
                warn!(
                    kind,
                    ?error,
                    "inbound signaling dropped under declared resource pressure"
                );
                true
            }
            Err(ResourceMailboxSendError::Claim { error, .. }) => {
                warn!(kind, %error, "unrepresentable inbound signaling dropped");
                true
            }
        }
    }

    /// Fold one presence or withdrawal into the availability the runtime owns.
    /// Returns whether the observation is still worth delivering.
    ///
    /// A presence is always worth delivering: the engine paces dialling on it and
    /// a repeat is that pacing, not noise.
    ///
    /// A withdrawal is worth delivering only when nothing still sees the device.
    /// That is what makes it evidence of unreachability rather than one carrier's
    /// opinion, and it is the whole reason this owner exists: with Nostr and mDNS
    /// both attached, losing the LAN is not losing the device.
    ///
    /// **A sender-claimed withdrawal cannot cancel a carrier-observed presence.**
    /// Naming a third party in a payload therefore cannot make the runtime forget
    /// that the third party is reachable — the strongest thing it can do is
    /// withdraw a claim the same kind of payload made.
    fn record_availability(&self, ingress: &EphemeralIngress) -> bool {
        let device_id = match ingress.inbound() {
            SignalingInbound::PeerAnnounced { device_id }
            | SignalingInbound::PeerLeft { device_id } => device_id,
            // Unreachable by construction: `is_availability` is true for exactly
            // the two kinds these two variants parse from. Delivering is the safe
            // reading if that ever stops being true.
            _ => return true,
        };
        let mut availability = self.availability.lock();
        match ingress.signal {
            EphemeralSignal::Presence => {
                if !availability.contains_key(device_id)
                    && availability.len() >= AVAILABILITY_CAPACITY
                {
                    return true;
                }
                let entry = availability.entry(device_id.clone()).or_default();
                match ingress.attribution {
                    CarrierAttribution::CarrierObserved => entry.observed.insert(ingress.instance),
                    CarrierAttribution::SenderClaimed => entry.claimed.insert(ingress.instance),
                };
                true
            }
            EphemeralSignal::Withdrawal => {
                let Some(entry) = availability.get_mut(device_id) else {
                    return true;
                };
                match ingress.attribution {
                    CarrierAttribution::CarrierObserved => {
                        entry.observed.remove(&ingress.instance);
                        entry.claimed.remove(&ingress.instance);
                    }
                    CarrierAttribution::SenderClaimed => {
                        entry.claimed.remove(&ingress.instance);
                    }
                }
                if entry.observed.is_empty() && entry.claimed.is_empty() {
                    availability.remove(device_id);
                    return true;
                }
                trace!(
                    carrier = ingress.carrier.name(),
                    "withdrawal held: another attach still observes this device"
                );
                false
            }
            _ => true,
        }
    }
}

/// One carrier's attach: the handle a driver pump observes through.
///
/// It cannot reach anything but its own instance and the runtime's delivery
/// path, so a pump can neither mint a second receipt nor build a domain value
/// without going through the admission above.
pub(crate) struct CarrierAttach {
    runtime: Arc<SignalingRuntime>,
    carrier: SignalingCarrier,
    instance: CarrierInstance,
}

impl CarrierAttach {
    /// A carrier reported that a device is present.
    ///
    /// Presence paces dialling and nothing else. The device id is not a claim of
    /// membership — the engine still runs the full endpoint-authentication and
    /// policy path before this peer is anything.
    pub(crate) fn presence(
        &self,
        device_id: String,
        attribution: CarrierAttribution,
    ) -> CarrierObservation {
        self.observation(
            EphemeralSignal::Presence,
            ObservationBody::Presence {
                device_id,
                attribution,
            },
        )
    }

    /// A carrier stopped seeing a device, or the device announced its departure.
    ///
    /// Reachability evidence. It cannot be a durable leave: this boundary has no
    /// kind that records one, the roster is the Semantic Node's to change, and
    /// the engine will not let it retire a healthy authenticated session.
    pub(crate) fn withdrawal(
        &self,
        device_id: String,
        attribution: CarrierAttribution,
    ) -> CarrierObservation {
        self.observation(
            EphemeralSignal::Withdrawal,
            ObservationBody::Withdrawal {
                device_id,
                attribution,
            },
        )
    }

    /// A peer addressed us directly over this carrier.
    pub(crate) fn directed(&self, from: String, message: SignalingMessage) -> CarrierObservation {
        // Admission happens on the carrier value, before anything is translated:
        // this is the whole ordering the module exists to fix.
        let signal = admit(&message);
        self.observation(signal, ObservationBody::Directed { from, message })
    }

    fn observation(&self, signal: EphemeralSignal, body: ObservationBody) -> CarrierObservation {
        CarrierObservation {
            carrier: self.carrier,
            instance: self.instance,
            signal,
            body,
        }
    }

    /// Hand an observation to the runtime. `false` once the engine side is gone.
    pub(crate) fn deliver(&self, observation: CarrierObservation) -> bool {
        self.runtime.deliver(observation)
    }
}

/// Content key for de-duplication. `None` = never deduped.
///
/// **Keyed on the message content and deliberately not on the carrier.** The
/// duplicate this exists to catch is one engine emission that fanned out to
/// Nostr and mDNS and came back over both, so the two copies differ in exactly
/// the field a carrier-aware key would separate them by. Applying an offer twice
/// via `set_remote_description` wedges WebRTC permanently. Retained provenance is
/// for the engine to read, not for the key; the first carrier to arrive is the
/// one whose provenance is delivered.
fn dedup_key(ingress: &EphemeralIngress) -> Option<u64> {
    let mut h = DefaultHasher::new();
    match ingress.inbound() {
        SignalingInbound::Offer { device_id, sdp } => {
            (1u8, device_id, sdp).hash(&mut h);
        }
        SignalingInbound::Answer { device_id, sdp } => {
            (2u8, device_id, sdp).hash(&mut h);
        }
        SignalingInbound::Candidate {
            device_id,
            candidate,
        } => {
            (
                3u8,
                device_id,
                &candidate.candidate,
                &candidate.sdp_mid,
                &candidate.sdp_mline_index,
                &candidate.username_fragment,
            )
                .hash(&mut h);
        }
        SignalingInbound::PeerAnnounced { .. } | SignalingInbound::PeerLeft { .. } => return None,
    }
    Some(h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_CARRIER: [SignalingCarrier; 3] = [
        SignalingCarrier::Local,
        SignalingCarrier::Nostr,
        SignalingCarrier::Mdns,
    ];

    fn offer(sdp: &str) -> SignalingMessage {
        SignalingMessage::Offer {
            peer_id: "body-claimed-id".into(),
            offer_id: "offer-1".into(),
            sdp: sdp.into(),
        }
    }

    /// A runtime with a funded mailbox behind it, and the receiver to drain.
    pub(super) fn runtime_with_rx() -> (
        Arc<SignalingRuntime>,
        crate::resource::ResourceMailboxReceiver<EphemeralIngress>,
    ) {
        let grant = crate::resource::ResourceClaim::try_from_entries(
            crate::resource::ResourceClass::ALL.map(|dimension| (dimension, 1_000_000)),
        )
        .expect("test grant is representable");
        let provider = crate::resource::ResourceProviderPort::new(
            crate::resource::FiniteResourceProvider::new(grant),
        )
        .expect("test grant funds process bookkeeping");
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_local_application_provider(provider)
            .expect("isolated root accepts its provider");
        let (tx, rx) = crate::resource::resource_mailbox(
            root.issue_local_application_scope()
                .expect("test local-application scope"),
        )
        .expect("test mailbox");
        (SignalingRuntime::new(tx), rx)
    }

    /// One attach, for the admission-only controls that never deliver.
    fn lone_attach(carrier: SignalingCarrier) -> CarrierAttach {
        SignalingRuntime::attach(&runtime_with_rx().0, carrier)
    }

    /// **Negative control: a body-claimed identity never displaces the `from`
    /// that reached this boundary.**
    ///
    /// # Scope, because the obvious reading is wider than the truth
    ///
    /// This is a rule about values that reach [`parse_directed`]. Offer, answer
    /// and candidate reach it from all three carriers, so there it is the live
    /// behaviour everywhere. A directed announce or leave reaches it from
    /// `LocalBroker` alone — the two network drivers normalize those into their
    /// own presence and withdrawal reports first, and what *they* attribute is
    /// covered by [`CarrierAttribution`] and by the availability control below.
    ///
    /// The stronger property holds on every carrier and is structural rather
    /// than asserted: neither field mints authority, because no kind could.
    #[test]
    fn a_body_claimed_identity_never_displaces_the_sender_attribution() {
        for carrier in EVERY_CARRIER {
            let attach = lone_attach(carrier);
            let offered = attach
                .directed(
                    "sender-peer".into(),
                    SignalingMessage::Offer {
                        peer_id: "third-party-peer".into(),
                        offer_id: "offer-1".into(),
                        sdp: "sdp-1".into(),
                    },
                )
                .into_ingress();
            assert_eq!(offered.signal(), EphemeralSignal::ConnectIntent);
            assert_eq!(offered.carrier(), carrier, "provenance survives the parse");
            assert_eq!(offered.attribution(), CarrierAttribution::SenderClaimed);
            match offered.inbound() {
                SignalingInbound::Offer { device_id, .. } => assert_eq!(
                    device_id, "sender-peer",
                    "a negotiation frame is attributed to the sender the carrier \
                     routed from, on every carrier"
                ),
                other => panic!("an offer parses as connect intent, got {other:?}"),
            }

            let left = attach
                .directed(
                    "sender-peer".into(),
                    SignalingMessage::Leave {
                        peer_id: "third-party-peer".into(),
                    },
                )
                .into_ingress();
            assert_eq!(left.signal(), EphemeralSignal::Withdrawal);
            match left.inbound() {
                SignalingInbound::PeerLeft { device_id } => assert_eq!(
                    device_id, "sender-peer",
                    "a departure the sender did not make is not the sender's to declare"
                ),
                other => panic!("a leave parses as a withdrawal, got {other:?}"),
            }
        }
    }

    /// **The union has no application-delivery and no durable-authority kind.**
    ///
    /// The implementation half of `FORMAL-PROOFS.md` Theorem 11.1: every input
    /// this boundary can produce lands in the closed [`EphemeralSignal`] set, so
    /// application payload and durable authority are absent from the union rather
    /// than merely unreachable from today's inputs. Both directions are checked,
    /// because an outbound variant that acquired a kind by default would widen
    /// the same union.
    #[test]
    fn every_admitted_signal_is_ephemeral_transport_control() {
        let inbound = [
            SignalingMessage::Announce {
                peer_id: "peer-a".into(),
                caps: Vec::new(),
            },
            SignalingMessage::Leave {
                peer_id: "peer-a".into(),
            },
            offer("sdp-1"),
            SignalingMessage::Answer {
                peer_id: "peer-a".into(),
                offer_id: "offer-1".into(),
                sdp: "sdp-1".into(),
            },
            SignalingMessage::Candidate {
                peer_id: "peer-a".into(),
                candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            },
        ];
        let admitted: Vec<EphemeralSignal> = inbound.iter().map(admit).collect();
        assert_eq!(
            admitted,
            [
                EphemeralSignal::Presence,
                EphemeralSignal::Withdrawal,
                EphemeralSignal::ConnectIntent,
                EphemeralSignal::ConnectAnswer,
                EphemeralSignal::CandidateHint,
            ],
            "no current carrier variant carries a durable signed fact"
        );

        let outbound = [
            SignalingOutbound::Announce,
            SignalingOutbound::Leave,
            SignalingOutbound::Offer {
                device_id: "peer-a".into(),
                sdp: "sdp-1".into(),
            },
            SignalingOutbound::Answer {
                device_id: "peer-a".into(),
                sdp: "sdp-1".into(),
            },
            SignalingOutbound::Candidate {
                device_id: "peer-a".into(),
                candidate: LocalIceCandidate {
                    candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                    sdp_mid: Some("0".into()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                },
            },
        ];
        for emission in &outbound {
            let signal = outbound_signal(emission);
            assert!(
                matches!(
                    signal,
                    EphemeralSignal::Presence
                        | EphemeralSignal::Withdrawal
                        | EphemeralSignal::ConnectIntent
                        | EphemeralSignal::ConnectAnswer
                        | EphemeralSignal::CandidateHint
                ),
                "unexpected kind {signal:?} — the union has grown"
            );
        }
    }

    /// **The instance receipt is per-attach, opaque, and not peer-choosable.**
    ///
    /// Two attaches of the *same* carrier are distinguishable, which is what
    /// makes availability survive a driver restart honestly; and nothing a peer
    /// sends changes the receipt, which is what keeps it from becoming a route
    /// identity.
    #[test]
    fn each_attach_receives_its_own_opaque_instance() {
        let (runtime, _rx) = runtime_with_rx();
        let first = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let second = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        assert_ne!(
            first.instance, second.instance,
            "two attaches of one carrier are not one attach"
        );

        let a = first
            .directed("peer-a".into(), offer("sdp-1"))
            .into_ingress();
        let b = first
            .directed("hostile".into(), offer("v=0 whatever"))
            .into_ingress();
        assert_eq!(
            a.instance(),
            b.instance(),
            "the receipt is the attach's, not the message's"
        );
        assert_ne!(a.instance(), second.instance);
    }

    /// **A sender-claimed withdrawal cannot cancel a carrier-observed presence.**
    ///
    /// The discriminating control for the availability owner: while any attach
    /// still observes a device, a withdrawal is held as one carrier's opinion
    /// rather than delivered as evidence that the device is gone.
    ///
    /// **What it does not prove, and must not be read as proving.** This is the
    /// *multi-carrier* hold. On a single attach - a Nostr-only network, say -
    /// there is nothing left observing the device once that attach withdraws,
    /// so the withdrawal is delivered, and on Nostr both the presence and the
    /// departure are `SenderClaimed`. The property that a *delivered*
    /// withdrawal still cannot retire a healthy authenticated session is the
    /// engine's, and is asserted by
    /// `v4_m2_a_carrier_withdrawal_leaves_a_healthy_authenticated_session_intact`
    /// in `engine/mod.rs`. Neither control subsumes the other.
    #[test]
    fn a_withdrawal_is_delivered_only_when_nothing_still_observes_the_device() {
        let (runtime, mut rx) = runtime_with_rx();
        let lan = SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns);
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);

        let seen = lan.presence("peer-a".into(), CarrierAttribution::CarrierObserved);
        assert!(lan.deliver(seen));
        let claimed = relay.presence("peer-a".into(), CarrierAttribution::SenderClaimed);
        assert!(relay.deliver(claimed));

        // A payload naming the device cannot undo what mDNS resolved itself.
        let hostile = relay.withdrawal("peer-a".into(), CarrierAttribution::SenderClaimed);
        assert!(relay.deliver(hostile));

        // Nor can the relay attach's own carrier-observed loss, while the LAN
        // still sees it.
        let relay_gone = relay.withdrawal("peer-a".into(), CarrierAttribution::CarrierObserved);
        assert!(relay.deliver(relay_gone));

        // Only the last observer leaving is evidence of unreachability.
        let lan_gone = lan.withdrawal("peer-a".into(), CarrierAttribution::CarrierObserved);
        assert!(lan.deliver(lan_gone));

        let mut delivered = Vec::new();
        while let Some(item) = rx.try_recv() {
            delivered.push(item.value().signal());
        }
        assert_eq!(
            delivered,
            [
                EphemeralSignal::Presence,
                EphemeralSignal::Presence,
                EphemeralSignal::Withdrawal,
            ],
            "two presences reached the engine and exactly one withdrawal did"
        );
    }

    /// **One emission that fanned out to two carriers reaches the engine once;
    /// everything else still gets through, in any order.**
    ///
    /// The wedge case the de-duplication owner exists for, and its three
    /// discriminations in one control: the duplicate is caught *across* carriers
    /// (a carrier-aware key would miss it, since provenance is the only field
    /// the two copies differ in), distinct content is never held back however
    /// similar, and nothing waits for a predecessor — a candidate that overtakes
    /// its offer on a relay still lands.
    #[test]
    fn cross_carrier_duplicates_are_swallowed_and_distinct_content_is_not() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        let lan = SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns);

        let candidate = |mid: &str| SignalingMessage::Candidate {
            peer_id: "body-claimed-id".into(),
            candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
            sdp_mid: Some(mid.to_string()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        };

        // Candidates ahead of the offer they belong to, then the same offer over
        // both carriers, then a distinct one.
        assert!(lan.deliver(lan.directed("peer-a".into(), candidate("1"))));
        assert!(relay.deliver(relay.directed("peer-a".into(), candidate("0"))));
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-1"))));
        assert!(lan.deliver(lan.directed("peer-a".into(), offer("sdp-1"))));
        assert!(relay.deliver(relay.directed("peer-a".into(), offer("sdp-2"))));
        assert!(relay.deliver(relay.directed("peer-b".into(), offer("sdp-1"))));

        let mut delivered = Vec::new();
        while let Some(item) = rx.try_recv() {
            delivered.push((item.value().signal(), item.value().carrier()));
        }
        assert_eq!(
            delivered,
            [
                (EphemeralSignal::CandidateHint, SignalingCarrier::Mdns),
                (EphemeralSignal::CandidateHint, SignalingCarrier::Nostr),
                // The carrier that got there first is the provenance the engine
                // sees; the mDNS copy of the same offer is the one swallowed.
                (EphemeralSignal::ConnectIntent, SignalingCarrier::Nostr),
                (EphemeralSignal::ConnectIntent, SignalingCarrier::Nostr),
                (EphemeralSignal::ConnectIntent, SignalingCarrier::Nostr),
            ],
            "one duplicate swallowed, five distinct inputs through"
        );
    }

    /// The de-duplication ring is bounded, and the bound is not a peer limit.
    #[test]
    fn the_dedup_ring_is_bounded() {
        let (runtime, mut rx) = runtime_with_rx();
        let relay = SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr);
        for i in 0..(SEEN_CAPACITY + 10) {
            assert!(relay.deliver(relay.directed("peer-a".into(), offer(&format!("sdp-{i}")))));
        }
        assert_eq!(runtime.seen.lock().len(), SEEN_CAPACITY);
        while rx.try_recv().is_some() {}
    }

    /// **The `Debug` output carries the diagnostic fields and none of the
    /// payload.**
    ///
    /// Every sentinel is a value a derived `Debug` would have printed, checked by
    /// its own substring rather than by an overall shape, so a partial leak fails
    /// as loudly as a total one. The positive half is asserted too — a `Debug`
    /// that printed nothing would pass a redaction check while being useless.
    #[test]
    fn the_debug_output_omits_payload_and_keeps_the_bounded_fields() {
        const SECRET_SDP: &str = "v=0-SENTINEL-SDP-BODY-a=fingerprint";
        const SECRET_DEVICE: &str = "SENTINEL-DEVICE-ID";
        const SECRET_ADDRESS: &str = "203.0.113.7";

        let attach = lone_attach(SignalingCarrier::Nostr);
        let offered = attach
            .directed(
                SECRET_DEVICE.into(),
                SignalingMessage::Offer {
                    peer_id: SECRET_DEVICE.into(),
                    offer_id: "offer-1".into(),
                    sdp: SECRET_SDP.into(),
                },
            )
            .into_ingress();
        let rendered = format!("{offered:?}");
        for secret in [SECRET_SDP, SECRET_DEVICE] {
            assert!(
                !rendered.contains(secret),
                "payload must not reach a log through Debug: {secret} in {rendered}"
            );
        }
        assert!(
            rendered.contains("nostr") && rendered.contains("connect_intent"),
            "carrier and kind are the point of the value and must survive, got {rendered}"
        );

        // A candidate carries an address rather than an SDP body, so it is
        // checked separately: one redacted field does not imply the other.
        let mdns = lone_attach(SignalingCarrier::Mdns);
        let candidate = mdns
            .directed(
                SECRET_DEVICE.into(),
                SignalingMessage::Candidate {
                    peer_id: SECRET_DEVICE.into(),
                    candidate: format!("candidate:1 1 UDP 1 {SECRET_ADDRESS} 5000 typ host"),
                    sdp_mid: Some("0".into()),
                    sdp_mline_index: Some(0),
                    username_fragment: Some("SENTINEL-UFRAG".into()),
                },
            )
            .into_ingress();
        let rendered = format!("{candidate:?}");
        for secret in [SECRET_ADDRESS, SECRET_DEVICE, "SENTINEL-UFRAG"] {
            assert!(
                !rendered.contains(secret),
                "candidate payload must not reach a log through Debug: {secret} in {rendered}"
            );
        }
        assert!(rendered.contains("mdns") && rendered.contains("candidate_hint"));
    }
}
