//! The Signaling Node's lane boundary: the one place a carrier observation is
//! sorted into a signaling category, and the only place it becomes an engine
//! domain value.
//!
//! `ARCHITECTURE.md` §4 states that signaling carries two disjoint categories —
//! durable semantic exchange and ephemeral transport control — and
//! `CURRENT-TO-TARGET-MIGRATION-MATRIX.md` requires that "durable and ephemeral
//! lanes are classified before domain parsing". Before this module the two
//! steps were one: each driver pump matched a carrier message straight into a
//! [`SignalingInbound`], so nothing named the lane, nothing retained which
//! carrier had observed the message, and a new carrier variant could reach the
//! engine without anyone deciding what kind of signaling it was.
//!
//! The order is enforced by the types rather than by convention. A carrier pump
//! can only build a [`CarrierObservation`], whose constructors decide the lane;
//! the parse into a domain value lives behind
//! [`CarrierObservation::into_delivery`] and is private to this module, so
//! "classify, then parse" is the only sequence that compiles. What comes out is
//! a [`LaneDelivery`], which carries the lane and the bounded carrier
//! provenance to the engine instead of dropping them at the boundary.
//!
//! # What this boundary is not
//!
//! It moves no traffic on its own. It adds no anti-entropy, no proof delivery,
//! no retry, timer, poll, or acknowledgement, and it changes no eviction
//! behaviour. It is the boundary a later durable-semantic unit has to pass
//! through, built and proven first so that unit is a lane decision rather than
//! a new parallel path.
//!
//! # The durable-semantic lane has no carrier variant yet
//!
//! Every variant of the current carrier schema
//! ([`myownmesh_signaling::SignalingMessage`]) is presence or transport
//! negotiation, so [`classify`] maps all of them to
//! [`SignalingLane::EphemeralTransport`] and
//! [`SignalingLane::DurableSemantic`] is a lane the wire cannot yet reach.
//! That is the honest state of the boundary and
//! `every_current_carrier_variant_is_ephemeral_transport` asserts exactly it:
//! the control is what will fail, deliberately, on the day a durable-semantic
//! variant is added without a lane decision.

use myownmesh_signaling::SignalingMessage;

use crate::resource::{
    mailbox_retained_claim, ResourceClaim, ResourceMailboxItem, ResourceMailboxItemError,
};
use crate::transport::LocalIceCandidate;

use super::state::{SignalingInbound, SignalingOutbound};

/// Which carrier observed a signaling message.
///
/// **Bounded provenance, and the bound is the point.** This is a closed set of
/// three unit variants: it records that a message arrived over the LAN rather
/// than a relay, and nothing else. It carries no relay URL, no socket, no
/// address, no key and no peer-supplied string, so it cannot grow into a second
/// identity for a device or a place to smuggle carrier state into the engine.
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
}

/// The two disjoint signaling categories of `ARCHITECTURE.md` §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalingLane {
    /// Durable signed facts, inventories, exact dependency requests, and
    /// compacted-basis proofs where adopted. Nothing in the current carrier
    /// schema classifies here — see the module documentation.
    ///
    /// **The expectation below is the variant's exit obligation, and it
    /// expires by itself.** Under `not(test)` nothing constructs this yet, so
    /// `dead_code` fires and is expected. The moment the semantic unit makes
    /// [`classify`] return it, the lint stops firing, the expectation goes
    /// unfulfilled, and `-D warnings` turns that into an error — so the
    /// attribute has to be deleted by whoever inhabits the lane. A broad
    /// `allow` would have gone quiet at exactly that moment instead. If the
    /// semantic unit never arrives, this variant is a §7.3 deletion item, not
    /// something to keep suppressed.
    ///
    /// `cfg_attr(not(test), …)` rather than a bare `expect` because the
    /// controls do construct it, so under `cfg(test)` the lint does not fire
    /// and an unconditional expectation would itself be unfulfilled.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the two-lane type is the boundary this unit exists to \
                      create, and the durable lane is deliberately uninhabited \
                      until the semantic unit classifies something into it. \
                      Constructing it here to quiet the lint would be a fake \
                      inhabitant and would make the classifier lie about what \
                      the wire can carry"
        )
    )]
    DurableSemantic,
    /// Connect intent, offers and answers, candidates and candidate updates,
    /// and the presence observations that pace them. Typed, bounded, and
    /// unavailable to application payload APIs.
    EphemeralTransport,
}

impl SignalingLane {
    /// Stable name for traces and diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::DurableSemantic => "durable_semantic",
            Self::EphemeralTransport => "ephemeral_transport",
        }
    }
}

/// The complete set of effects a classified signaling input may produce.
///
/// **The union is closed here, and its closure is the implementation
/// refinement `FORMAL-PROOFS.md` Theorem 11.1 asks for.** That theorem holds
/// only if the signaling effect union has no variant containing application
/// bytes and an application consumer; this enum is that union, and it has no
/// such variant. It equally has no durable-authority, roster-mutation or
/// durable-leave variant, which is how a carrier observation stays unable to
/// grant, revoke, or record membership no matter what a carrier claims.
///
/// [`LaneDelivery::effect`] is an exhaustive match with no wildcard arm, so a
/// new inbound variant does not compile until someone chooses its effect from
/// this set — and adding a variant *to* this set is the visible, reviewable act
/// that widening the boundary requires.
///
/// **`cfg(test)`, and the limit of that is worth stating.** Nothing in the
/// production path reads an effect — the driver dispatches on the inbound
/// variant itself — so in a release build this union does not exist and the
/// exhaustiveness gate below is not compiled. It binds whenever the crate is
/// compiled for test, which is every `cargo test` and every
/// `cargo clippy --all-targets`, so a new `SignalingInbound` variant still
/// cannot reach CI without choosing an effect. It is not a release-build
/// guarantee, and it is not claimed as one. Giving the driver a runtime use
/// for the effect purely to keep the union alive would be a use invented for
/// the lint rather than for the engine.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalingEffect {
    /// A carrier saw a peer advertise itself. Discovery evidence only: it
    /// records nothing durable and admits nobody.
    CarrierPresence,
    /// A carrier stopped seeing a peer, or a peer said it was going. Affects
    /// the live session only — never the roster and never a durable fact.
    CarrierWithdrawal,
    /// An offer or answer for the transport negotiation of one attempt.
    TransportNegotiation,
    /// One ICE candidate observation for an attempt in progress.
    TransportCandidate,
}

/// One carrier observation whose lane has been decided and whose domain value
/// does not exist yet.
///
/// Constructed by a driver pump directly from what the carrier reported, which
/// is why the constructors take the carrier's own shape (a presence event, a
/// withdrawal, or a directed [`SignalingMessage`]) rather than anything the
/// engine understands. The lane is fixed at construction, so by the time
/// [`Self::into_delivery`] runs the classification has already happened and
/// cannot be influenced by it.
/// No `Debug`, deliberately. This holds the undecided carrier message whole —
/// SDP body, candidate string, device ids — one step upstream of the point
/// where [`LaneDelivery`]'s redacting formatter takes over. A derive here would
/// hand that payload a formatter before the redaction exists, so the type
/// simply has no way to print itself.
#[must_use = "an observation that is never delivered is a message silently dropped"]
pub(crate) struct CarrierObservation {
    carrier: SignalingCarrier,
    lane: SignalingLane,
    body: ObservationBody,
}

/// What the carrier actually reported. Private: the parse below is the only
/// consumer, and keeping the shape closed here is what stops a caller from
/// assembling a domain value without a lane.
/// No `Debug`, for the reason given on [`CarrierObservation`]: this is where
/// the payload actually lives.
enum ObservationBody {
    Presence {
        device_id: String,
    },
    Withdrawal {
        device_id: String,
    },
    Directed {
        from: String,
        message: SignalingMessage,
    },
}

impl CarrierObservation {
    /// A carrier reported that a peer is present.
    ///
    /// Presence is transport control: it paces dialling and nothing else. The
    /// device id is the carrier's own routing attribution, not a claim of
    /// membership — the engine still runs the full endpoint-authentication and
    /// policy path before this peer is anything.
    pub(crate) fn presence(carrier: SignalingCarrier, device_id: String) -> Self {
        Self {
            carrier,
            lane: SignalingLane::EphemeralTransport,
            body: ObservationBody::Presence { device_id },
        }
    }

    /// A carrier stopped seeing a peer, or the peer announced its departure.
    ///
    /// A withdrawal is an availability observation, so it classifies as
    /// transport control and its effect is `SignalingEffect::CarrierWithdrawal`.
    /// It cannot be a durable leave: this boundary has no effect that records
    /// one, and the roster is the Semantic Node's to change.
    pub(crate) fn withdrawal(carrier: SignalingCarrier, device_id: String) -> Self {
        Self {
            carrier,
            lane: SignalingLane::EphemeralTransport,
            body: ObservationBody::Withdrawal { device_id },
        }
    }

    /// A peer addressed us directly over this carrier.
    ///
    /// `from` is the carrier's routing attribution for the sender. It is the
    /// only sender attribution this boundary trusts, and the parse below uses
    /// it in preference to any device id inside the message body.
    pub(crate) fn directed(
        carrier: SignalingCarrier,
        from: String,
        message: SignalingMessage,
    ) -> Self {
        // Classification happens on the carrier value, before anything is
        // translated: this is the whole ordering the module exists to fix.
        let lane = classify(&message);
        Self {
            carrier,
            lane,
            body: ObservationBody::Directed { from, message },
        }
    }

    /// The lane this observation was classified into.
    ///
    /// `cfg(test)`, with [`Self::carrier`] below: production never reads either
    /// off an observation, because the pumps hand the observation straight to
    /// [`Self::into_delivery`] and the engine reads lane and provenance off the
    /// [`LaneDelivery`] instead. The controls read them here to prove the
    /// classification is fixed *before* the parse rather than derived from it,
    /// which is the one question a delivery cannot answer.
    #[cfg(test)]
    pub(crate) fn lane(&self) -> SignalingLane {
        self.lane
    }

    /// Which carrier observed it. `cfg(test)`; see [`Self::lane`].
    #[cfg(test)]
    pub(crate) fn carrier(&self) -> SignalingCarrier {
        self.carrier
    }

    /// Parse into the engine's domain value, keeping the lane and provenance.
    ///
    /// The only route from a carrier value to a [`SignalingInbound`] the engine
    /// can be handed, and it is reachable only from a value whose lane is
    /// already decided.
    pub(crate) fn into_delivery(self) -> LaneDelivery {
        let Self {
            carrier,
            lane,
            body,
        } = self;
        let inbound = match body {
            ObservationBody::Presence { device_id } => {
                SignalingInbound::PeerAnnounced { device_id }
            }
            ObservationBody::Withdrawal { device_id } => SignalingInbound::PeerLeft { device_id },
            ObservationBody::Directed { from, message } => parse_directed(from, message),
        };
        LaneDelivery {
            carrier,
            lane,
            inbound,
        }
    }
}

/// A classified, parsed signaling input on its way to the engine.
///
/// This is what the engine's inbound mailbox carries. The lane and the carrier
/// travel with the value rather than being computed and discarded at the
/// boundary, because "retained provenance" means the consumer can still see it.
pub struct LaneDelivery {
    carrier: SignalingCarrier,
    lane: SignalingLane,
    inbound: SignalingInbound,
}

/// Redacting, and the derive it replaces was the reason.
///
/// A derived `Debug` prints the whole [`SignalingInbound`]: the full SDP body
/// of an offer or answer, the candidate string with its addresses, and the
/// device id. Those reach a log the moment anything formats a delivery with
/// `{:?}` — a `tracing` field, an `unwrap` message, a panic payload — and none
/// of those call sites has to be reviewed for it to happen. This is the whole
/// value the type is allowed to say about itself.
///
/// **Exactly what remains: carrier, lane, and the variant's kind name.** All
/// three are bounded and closed — two field-less enums and a `&'static str` —
/// so nothing peer-supplied can appear here however the peer builds its
/// message. `finish_non_exhaustive` prints the trailing `..`, so a reader sees
/// that something was withheld rather than believing the value is this small.
///
/// The payload is not lost, only unprinted: the driver still receives it and
/// the engine's own handlers still work on it in full.
impl std::fmt::Debug for LaneDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneDelivery")
            // The stable names rather than the derived variant spellings, so a
            // `Debug` line and a `tracing` line name the same carrier and lane
            // the same way.
            .field("carrier", &self.carrier.name())
            .field("lane", &self.lane.name())
            .field("kind", &self.inbound.kind_name())
            .finish_non_exhaustive()
    }
}

impl LaneDelivery {
    /// The lane this input was classified into, before it was parsed.
    pub(crate) fn lane(&self) -> SignalingLane {
        self.lane
    }

    /// Which carrier observed it.
    pub(crate) fn carrier(&self) -> SignalingCarrier {
        self.carrier
    }

    /// The parsed input, borrowed.
    pub(crate) fn inbound(&self) -> &SignalingInbound {
        &self.inbound
    }

    /// Take the parsed input, dropping the lane and provenance.
    pub(crate) fn into_inbound(self) -> SignalingInbound {
        self.inbound
    }

    /// Variant name for driver-liveness traces — cheap, no payload.
    pub(crate) fn kind_name(&self) -> &'static str {
        self.inbound.kind_name()
    }

    /// The one effect this input may produce.
    ///
    /// Exhaustive with no wildcard: a new [`SignalingInbound`] variant fails to
    /// compile here until its effect is chosen from [`SignalingEffect`], and
    /// that set contains no application delivery and no durable authority.
    ///
    /// `cfg(test)` for the reason given on [`SignalingEffect`]: the driver
    /// dispatches on the inbound variant, so nothing in production asks this.
    #[cfg(test)]
    pub(crate) fn effect(&self) -> SignalingEffect {
        match &self.inbound {
            SignalingInbound::PeerAnnounced { .. } => SignalingEffect::CarrierPresence,
            SignalingInbound::PeerLeft { .. } => SignalingEffect::CarrierWithdrawal,
            SignalingInbound::Offer { .. } | SignalingInbound::Answer { .. } => {
                SignalingEffect::TransportNegotiation
            }
            SignalingInbound::Candidate { .. } => SignalingEffect::TransportCandidate,
        }
    }
}

impl ResourceMailboxItem for LaneDelivery {
    fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
        // The lane and the carrier are field-less `Copy` enums: they reach
        // nothing, allocate nothing, and their inline bytes are already inside
        // `size_of::<Self>()`. So the measurement is the inbound value's, priced
        // against this type's own footprint.
        let measure = self.inbound.string_measure()?;
        mailbox_retained_claim::<Self>(measure.0, measure.1, measure.2)
    }
}

/// Decide the lane of one carrier message, before it is translated.
///
/// Exhaustive with no wildcard arm, by design: a new carrier variant must not
/// be able to reach the engine by inheriting some default lane. Adding one to
/// [`SignalingMessage`] breaks this match, and the break is the review.
fn classify(message: &SignalingMessage) -> SignalingLane {
    match message {
        // Presence, departure and the offer/answer/candidate exchange are all
        // ephemeral transport control: bounded, not retained forever, not
        // projected as durable state, and none of them a signed fact.
        SignalingMessage::Announce { .. }
        | SignalingMessage::Leave { .. }
        | SignalingMessage::Offer { .. }
        | SignalingMessage::Answer { .. }
        | SignalingMessage::Candidate { .. } => SignalingLane::EphemeralTransport,
    }
}

/// Decide the lane of one outbound emission.
///
/// The boundary is two-sided for the same reason it is exhaustive: a new
/// outbound variant must choose a lane rather than acquire one, and an engine
/// emission that belongs on the durable lane must say so where the fan-out can
/// see it rather than at the driver that happens to carry it.
pub(crate) fn outbound_lane(outbound: &SignalingOutbound) -> SignalingLane {
    match outbound {
        SignalingOutbound::Announce
        | SignalingOutbound::Leave
        | SignalingOutbound::Offer { .. }
        | SignalingOutbound::Answer { .. }
        | SignalingOutbound::Candidate { .. } => SignalingLane::EphemeralTransport,
    }
}

/// Translate one directed carrier message into the engine's inbound shape.
///
/// **Private, and reachable only through [`CarrierObservation::into_delivery`].**
/// This is the domain parse the migration matrix requires classification to
/// precede; a `pub` version of it, or one that lived beside the driver pumps,
/// would let a caller skip straight to a domain value and the ordering would be
/// a convention again.
///
/// Shared by every carrier so the transports cannot drift.
///
/// # `from` wins over the body, and what that is worth by carrier
///
/// Every variant with a device id in its body is attributed to `from` instead.
/// **What `from` actually is differs by carrier, and the rule is worth no more
/// than the weakest one:**
///
/// - `LocalBroker` supplies genuine routing attribution — the broker stamps the
///   *sending peer handle's* registered id, and the sender cannot choose it.
/// - Nostr and mDNS supply a decoded field of the signaling envelope
///   (`envelope.from` and `frame.from`). That is sender-supplied payload. It is
///   never checked against the relay event's pubkey or the wire source, so on a
///   network carrier `from` is not an authenticated identity — it is a
///   *different* sender-supplied field from `peer_id`, and preferring it buys
///   consistency rather than proof.
///
/// The load-bearing part holds on every carrier and does not depend on either
/// field being trustworthy: **neither one mints authority.** A device is
/// admitted by endpoint authentication and policy, never by being named here,
/// and no effect on this boundary can grant, revoke or record membership.
///
/// What the rule still buys everywhere is that when the two fields disagree —
/// which is exactly when somebody is naming a third party — the transport
/// control effect lands on the sender rather than on a device that sent
/// nothing.
fn parse_directed(from: String, message: SignalingMessage) -> SignalingInbound {
    match message {
        // Announce and leave reach this parse from `LocalBroker` alone. Both
        // network drivers normalize the two variants into their own presence
        // and withdrawal reports before the bridge sees them: mDNS from
        // `frame.from` for announce but from the body `peer_id` for leave
        // (`myownmesh-signaling/src/mdns/driver.rs`), and Nostr from the body
        // `peer_id` for both (`nostr/driver.rs`). So the third-party
        // attribution these two arms close is still open upstream for those
        // carriers. Closing it there is signaling-driver work and deliberately
        // not this unit's — it would mean changing what each driver reports,
        // which is a wire-behaviour change rather than a lane boundary.
        SignalingMessage::Announce { peer_id, caps } => {
            let _ = (peer_id, caps);
            SignalingInbound::PeerAnnounced { device_id: from }
        }
        SignalingMessage::Leave { peer_id } => {
            let _ = peer_id;
            SignalingInbound::PeerLeft { device_id: from }
        }
        // Offer, answer and candidate reach this parse from all three carriers,
        // so for those the rule below is the live behaviour everywhere — under
        // the `from` caveat above.
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

    fn candidate(mid: &str) -> SignalingMessage {
        SignalingMessage::Candidate {
            peer_id: "body-claimed-id".into(),
            candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
            sdp_mid: Some(mid.into()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        }
    }

    /// The current carrier schema is entirely ephemeral transport control, and
    /// this control says so out loud rather than leaving it implied.
    ///
    /// It is written to fail on the day a durable-semantic carrier variant is
    /// added: whoever adds one has to come here, see that the durable lane was
    /// deliberately uninhabited, and state the new classification. That is the
    /// review this boundary exists to force.
    #[test]
    fn every_current_carrier_variant_is_ephemeral_transport() {
        let every_variant = [
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
            candidate("0"),
        ];
        for message in every_variant {
            assert_eq!(
                classify(&message),
                SignalingLane::EphemeralTransport,
                "no current carrier variant carries a durable signed fact"
            );
        }
    }

    /// Every outbound emission is transport control too, on the same terms.
    #[test]
    fn every_current_outbound_variant_is_ephemeral_transport() {
        let every_variant = [
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
        for outbound in every_variant {
            assert_eq!(outbound_lane(&outbound), SignalingLane::EphemeralTransport);
        }
    }

    /// The lane and the carrier survive the parse — that is what "retained
    /// provenance" has to mean to be worth anything.
    ///
    /// Asserted for all three carriers because the point of provenance is that
    /// the three are distinguishable at the far end, not that the field exists.
    #[test]
    fn every_carrier_delivers_its_own_provenance_and_lane() {
        for carrier in EVERY_CARRIER {
            let observation =
                CarrierObservation::directed(carrier, "peer-a".into(), offer("sdp-1"));
            assert_eq!(observation.carrier(), carrier);
            assert_eq!(observation.lane(), SignalingLane::EphemeralTransport);

            let delivered = observation.into_delivery();
            assert_eq!(
                delivered.carrier(),
                carrier,
                "provenance survives the parse"
            );
            assert_eq!(delivered.lane(), SignalingLane::EphemeralTransport);
            assert_eq!(delivered.effect(), SignalingEffect::TransportNegotiation);
        }
    }

    /// **Negative control: a body-claimed identity never displaces the `from`
    /// that reached this boundary.**
    ///
    /// # Scope, because the obvious reading of this is wider than the truth
    ///
    /// What is asserted is a rule about values that reach [`parse_directed`].
    /// That is not the same as an end-to-end guarantee for every carrier:
    ///
    /// - **Offer, answer and candidate** reach the parse from all three
    ///   carriers, so there the rule is the live behaviour everywhere.
    /// - **Announce and leave** reach it from `LocalBroker` alone, which is
    ///   also the only carrier that supplies a `from` the sender could not
    ///   choose. Nostr and mDNS normalize both variants into their own
    ///   presence and withdrawal reports first, taking the body `peer_id` while
    ///   they do it (mDNS for leave, Nostr for both) — so for those two the
    ///   third-party gap the announce and leave arms close is still open
    ///   upstream, in the signaling drivers. Closing it there is later
    ///   signaling-driver work, deliberately outside this unit.
    ///
    /// The loop below still runs every carrier because it is exercising the
    /// module's rule, which is carrier-agnostic by construction. It is not
    /// evidence that a hostile Nostr or mDNS leave is attributed this way in
    /// production, and must not be cited as such.
    ///
    /// The stronger property does hold on every carrier and is structural
    /// rather than asserted here: neither field mints authority, because the
    /// effect union contains no variant that could.
    #[test]
    fn a_body_claimed_identity_never_displaces_the_from_that_reached_this_boundary() {
        for carrier in EVERY_CARRIER {
            // Live on every carrier.
            let offered = CarrierObservation::directed(
                carrier,
                "sender-peer".into(),
                SignalingMessage::Offer {
                    peer_id: "third-party-peer".into(),
                    offer_id: "offer-1".into(),
                    sdp: "sdp-1".into(),
                },
            )
            .into_delivery();
            match offered.inbound() {
                SignalingInbound::Offer { device_id, .. } => {
                    assert_eq!(
                        device_id, "sender-peer",
                        "a negotiation frame is attributed to the sender the \
                         carrier routed from, on every carrier"
                    );
                }
                other => panic!("an offer parses as negotiation, got {other:?}"),
            }

            // Module rule; live only where a directed announce reaches the
            // parse, which today is `LocalBroker`.
            let announced = CarrierObservation::directed(
                carrier,
                "sender-peer".into(),
                SignalingMessage::Announce {
                    peer_id: "third-party-peer".into(),
                    caps: Vec::new(),
                },
            )
            .into_delivery();
            match announced.inbound() {
                SignalingInbound::PeerAnnounced { device_id } => {
                    assert_eq!(
                        device_id, "sender-peer",
                        "the body does not name the sender"
                    );
                }
                other => panic!("an announce parses as presence, got {other:?}"),
            }
            assert_eq!(announced.effect(), SignalingEffect::CarrierPresence);

            // Same scope: `LocalBroker` is the live path for a directed leave.
            let left = CarrierObservation::directed(
                carrier,
                "sender-peer".into(),
                SignalingMessage::Leave {
                    peer_id: "third-party-peer".into(),
                },
            )
            .into_delivery();
            match left.inbound() {
                SignalingInbound::PeerLeft { device_id } => {
                    assert_eq!(
                        device_id, "sender-peer",
                        "a departure the sender did not make is not the sender's to declare"
                    );
                }
                other => panic!("a leave parses as a withdrawal, got {other:?}"),
            }
        }
    }

    /// **Negative control: a carrier withdrawal is a carrier withdrawal.**
    ///
    /// Whichever way a carrier reports that a peer is gone — an out-of-band
    /// withdrawal or a directed departure — the effect is
    /// [`SignalingEffect::CarrierWithdrawal`], and there is no durable-leave or
    /// roster-mutation effect for it to be instead. The engine-side half of
    /// this, that the roster row survives, is asserted in `engine/mod.rs`.
    ///
    /// The out-of-band half is the live path on all three carriers: every
    /// driver reports its own `PeerLeft`, and the bridge turns each into a
    /// withdrawal. The directed half reaches the parse from `LocalBroker` only,
    /// for the reason given on
    /// `a_body_claimed_identity_never_displaces_the_from_that_reached_this_boundary`.
    /// Both are asserted because both are shapes this module must classify the
    /// same way, not because both arrive from every carrier today.
    #[test]
    fn a_carrier_withdrawal_has_no_durable_effect_to_produce() {
        for carrier in EVERY_CARRIER {
            let out_of_band =
                CarrierObservation::withdrawal(carrier, "peer-a".into()).into_delivery();
            assert_eq!(out_of_band.lane(), SignalingLane::EphemeralTransport);
            assert_eq!(out_of_band.effect(), SignalingEffect::CarrierWithdrawal);

            let announced_departure = CarrierObservation::directed(
                carrier,
                "peer-a".into(),
                SignalingMessage::Leave {
                    peer_id: "peer-a".into(),
                },
            )
            .into_delivery();
            assert_eq!(
                announced_departure.effect(),
                SignalingEffect::CarrierWithdrawal,
                "both ways of learning a peer is gone produce the same effect"
            );
        }
    }

    /// Every effect a classified input can produce is transport control or
    /// presence. Application delivery and durable authority are absent from the
    /// union, not merely unreachable from today's inputs.
    #[test]
    fn no_input_produces_an_application_or_authority_effect() {
        let every_input = [
            CarrierObservation::presence(SignalingCarrier::Local, "peer-a".into()),
            CarrierObservation::withdrawal(SignalingCarrier::Local, "peer-a".into()),
            CarrierObservation::directed(SignalingCarrier::Local, "peer-a".into(), offer("sdp-1")),
            CarrierObservation::directed(
                SignalingCarrier::Local,
                "peer-a".into(),
                SignalingMessage::Answer {
                    peer_id: "peer-a".into(),
                    offer_id: "offer-1".into(),
                    sdp: "sdp-1".into(),
                },
            ),
            CarrierObservation::directed(SignalingCarrier::Local, "peer-a".into(), candidate("0")),
        ];
        for observation in every_input {
            let effect = observation.into_delivery().effect();
            assert!(
                matches!(
                    effect,
                    SignalingEffect::CarrierPresence
                        | SignalingEffect::CarrierWithdrawal
                        | SignalingEffect::TransportNegotiation
                        | SignalingEffect::TransportCandidate
                ),
                "unexpected effect {effect:?} — the union has grown"
            );
        }
    }

    /// Classification does not depend on arrival order.
    ///
    /// A carrier may cache, delay, duplicate, reorder or censor
    /// (`ARCHITECTURE.md` §4), so a candidate that arrives before the offer it
    /// belongs to must classify identically to one that arrives after. The
    /// boundary holds no per-peer state for it to depend on; this control is
    /// what would notice if it grew some.
    #[test]
    fn classification_is_independent_of_arrival_order() {
        let in_order = [offer("sdp-1"), candidate("0"), candidate("1")];
        let reversed = [candidate("1"), candidate("0"), offer("sdp-1")];

        let lanes = |messages: [SignalingMessage; 3]| {
            messages.map(|message| {
                CarrierObservation::directed(SignalingCarrier::Nostr, "peer-a".into(), message)
                    .into_delivery()
                    .lane()
            })
        };
        // Compared position by position after reversing one of them, so the
        // assertion is "the same three messages, whichever order they arrived
        // in" rather than "two multisets happen to match".
        let forward = lanes(in_order);
        let mut backward = lanes(reversed);
        backward.reverse();
        assert_eq!(forward, backward);
    }

    /// The same content observed twice classifies twice the same way, and each
    /// observation keeps the provenance of the carrier that saw it.
    ///
    /// De-duplication is not this boundary's job — the engine-facing gate in
    /// `signaling_bridge` owns cross-carrier duplicates, and its own controls
    /// cover them. What matters here is that a duplicate is not silently
    /// reclassified or re-attributed on the way through.
    #[test]
    fn a_duplicate_observation_classifies_and_attributes_identically() {
        let first =
            CarrierObservation::directed(SignalingCarrier::Nostr, "peer-a".into(), offer("sdp-1"))
                .into_delivery();
        let again =
            CarrierObservation::directed(SignalingCarrier::Mdns, "peer-a".into(), offer("sdp-1"))
                .into_delivery();

        assert_eq!(first.lane(), again.lane());
        assert_eq!(first.effect(), again.effect());
        assert_eq!(first.carrier(), SignalingCarrier::Nostr);
        assert_eq!(again.carrier(), SignalingCarrier::Mdns);
    }

    /// **The `Debug` output carries the diagnostic fields and none of the
    /// payload.**
    ///
    /// The discriminating control for the redacting impl: every sentinel below
    /// is a value a derived `Debug` would have printed, and each is checked by
    /// its own substring rather than by an overall shape, so a partial leak
    /// fails as loudly as a total one. The positive half is asserted too — a
    /// `Debug` that printed nothing would pass a redaction check while being
    /// useless, so the bounded fields have to survive.
    #[test]
    fn the_debug_output_omits_payload_and_keeps_the_bounded_fields() {
        const SECRET_SDP: &str = "v=0-SENTINEL-SDP-BODY-a=fingerprint";
        const SECRET_DEVICE: &str = "SENTINEL-DEVICE-ID";
        const SECRET_ADDRESS: &str = "203.0.113.7";

        let offered = CarrierObservation::directed(
            SignalingCarrier::Nostr,
            SECRET_DEVICE.into(),
            SignalingMessage::Offer {
                peer_id: SECRET_DEVICE.into(),
                offer_id: "offer-1".into(),
                sdp: SECRET_SDP.into(),
            },
        )
        .into_delivery();
        let rendered = format!("{offered:?}");
        assert!(
            !rendered.contains(SECRET_SDP),
            "the SDP body must not reach a log through Debug, got {rendered}"
        );
        assert!(
            !rendered.contains(SECRET_DEVICE),
            "nor the device id, got {rendered}"
        );
        assert!(
            rendered.contains("nostr") && rendered.contains("ephemeral_transport"),
            "carrier and lane are the point of the value and must survive, got {rendered}"
        );
        assert!(
            rendered.contains("offer"),
            "and the kind is what makes the line worth reading, got {rendered}"
        );

        // A candidate carries an address rather than an SDP body, so it is
        // checked separately: one redacted field does not imply the other.
        let candidate = CarrierObservation::directed(
            SignalingCarrier::Mdns,
            SECRET_DEVICE.into(),
            SignalingMessage::Candidate {
                peer_id: SECRET_DEVICE.into(),
                candidate: format!("candidate:1 1 UDP 1 {SECRET_ADDRESS} 5000 typ host"),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: Some("SENTINEL-UFRAG".into()),
            },
        )
        .into_delivery();
        let rendered = format!("{candidate:?}");
        for secret in [SECRET_ADDRESS, SECRET_DEVICE, "SENTINEL-UFRAG"] {
            assert!(
                !rendered.contains(secret),
                "candidate payload must not reach a log through Debug: {secret} in {rendered}"
            );
        }
        assert!(rendered.contains("mdns") && rendered.contains("candidate"));
    }

    /// Carrier and lane names are stable strings other subsystems read.
    #[test]
    fn carrier_and_lane_names_are_stable() {
        assert_eq!(SignalingCarrier::Local.name(), "local");
        assert_eq!(SignalingCarrier::Nostr.name(), "nostr");
        assert_eq!(SignalingCarrier::Mdns.name(), "mdns");
        assert_eq!(SignalingLane::DurableSemantic.name(), "durable_semantic");
        assert_eq!(
            SignalingLane::EphemeralTransport.name(),
            "ephemeral_transport"
        );
    }
}
