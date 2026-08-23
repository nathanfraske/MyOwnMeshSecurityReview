//! Adapter that connects an [`crate::engine::state::NetworkState`]
//! to one or more signaling drivers. The signaling crate emits its
//! own generic [`myownmesh_signaling::SignalingMessage`] type; every
//! inbound pump here hands that shape to the ingress boundary in
//! [`super::signaling_ingress`], which admits it and only then
//! produces the engine's `SignalingInbound`. Outbound, this module
//! still renders the engine's `SignalingOutbound` into each driver's
//! own type.
//!
//! **The pumps no longer parse, and no longer decide.** A pump builds
//! a [`CarrierObservation`] through its own [`CarrierAttach`] and
//! hands it back; the translation into a domain value is private to
//! the ingress module, and de-duplication belongs to
//! the [`SignalingRuntime`] behind the attach. So "admit, then parse"
//! is not a rule this module follows, it is the only sequence
//! available to it - and the carrier and the attach that observed each
//! message reach the engine instead of being forgotten at the
//! boundary.
//!
//! Entry points:
//!
//! - [`attach_signaling`] - the production path: reads the network's
//!   `SignalingConfig` and attaches the remote strategy (`"nostr"` /
//!   `"none"`) plus, when `mdns` is on (the default), the LAN mDNS
//!   driver. With both attached, a fan-out task clones each engine
//!   emission to every driver (the engine's outbound receiver is
//!   single-consumer) and the two attaches share one
//!   [`SignalingRuntime`], which is what lets it see that the two
//!   copies coming back are one emission.
//! - [`attach_nostr`] / [`attach_mdns`] - single-driver attaches for
//!   embedders that pick a transport directly.
//! - [`attach_local`] - an in-process
//!   [`myownmesh_signaling::local::LocalBroker`] (tests and
//!   single-process apps).

use std::sync::{Arc, Weak};

use myownmesh_signaling::local::{LocalBroker, LocalInbound, LocalOutbound};
use myownmesh_signaling::mdns::{
    self as mdns_driver, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound,
};
use myownmesh_signaling::nostr::delivery::{
    DeliveryLease, DeliveryProvider, DeliveryRefusal, DeliveryRetention, DeliveryTerminal,
    RelaySessionId,
};
use myownmesh_signaling::nostr::driver::{
    self as nostr_driver, NostrDriverConfig, NostrDriverHandle, NostrInbound, NostrOutbound,
};
use myownmesh_signaling::{
    AttemptOutcome, AttemptOutcomeSink, AttemptRefusal, AttemptRefusalSink, InboundSink,
    NegotiationRefusal, OutboundSource, OwnedSignal, SignalingMessage,
};
use tracing::{trace, warn};

use crate::resource::{
    LocalApplicationResourceScope, ResourceClaim, ResourceLease, ResourceMailboxDelivery,
    ResourceMailboxReceiver, ResourceMailboxSendError, ResourceMailboxSender,
};

use super::signaling_ingress::{
    outbound_signal, CarrierAttach, CarrierAttribution, CarrierObservation, SignalingCarrier,
    SignalingRuntime,
};
use super::state::{NetworkCmd, NetworkState, SignalingOutbound};

/// One driver's outbound side: the engine's admitted values, translated on the
/// driver's own pull.
///
/// # What this replaces, and why the thing it replaces was not enough
///
/// There used to be a second queue here. A pump on this side read the engine's
/// funded mailbox, built a driver-shaped message — a peer id, an offer id, a
/// copy of the SDP or candidate — and pushed that translation into a plain
/// unbounded `tokio::mpsc` inside a crate with no resource vocabulary. One
/// standing residual was acquired for "the queue" and held for as long as it
/// could hold anything.
///
/// That named the subsystem without bounding it. The translations are the
/// allocations, the queue's depth is how many of them exist at once, and a
/// single claim says nothing about that number however long it is held. The
/// review asks for every translated value to be admitted before it is queued,
/// and the honest way to satisfy that is the one the inbound side already took:
/// **do not queue it**. The engine's per-driver mailbox is already funded and
/// already admits each `SignalingOutbound` before retaining it; this pulls from
/// that mailbox and builds the driver's type at the moment the driver asks for
/// one. A translation now lives on the driver's own task for exactly as long as
/// the driver is using it, and never longer.
///
/// So there is no queue lease, because there is no queue.
struct TranslatedOutbound<T> {
    /// Something the caller wants published before it drains anything — the
    /// broker join announce. Yielded once and then forgotten.
    ///
    /// It has no delivery behind it because the engine never sent it, so its
    /// owner is the derived-allocation lease alone. Acquired when the source is
    /// built, which is what makes a zero grant refuse before the announce is
    /// constructed rather than after.
    first: Option<(LocalOutboundFirst<T>, ResourceLease)>,
    rx: ResourceMailboxReceiver<SignalingOutbound>,
    scope: LocalApplicationResourceScope,
    translate: Box<dyn Fn(&SignalingOutbound) -> T + Send>,
    refusal_sink: Option<Arc<dyn AttemptRefusalSink>>,
}

/// The pre-drain value, built only once its lease exists.
type LocalOutboundFirst<T> = T;

/// What funds one translated outbound value and everything derived from it.
///
/// # Two leases, because there are two allocations and one of them is new
///
/// The delivery is the engine's own admission of the `SignalingOutbound`: it
/// funds *that* value, the one the mailbox accepted. Carrying it is necessary —
/// it is the provenance, and it must not be released while anything built from
/// the value it holds is still alive — but it is **not permission for a second
/// graph**. The translation allocates a driver-shaped message with copies of the
/// device id, the SDP or the candidate; the driver then serializes that, clones
/// it into an `Arc`, fans it to every relay task and may keep it in a replay
/// buffer. None of that was priced when the engine admitted the original.
///
/// So the owner is both: the whole delivery, and a separately acquired lease for
/// the derived allocations. The derived lease is taken **before** the translation
/// builder runs, so a provider with nothing left refuses instead of paying for a
/// copy after the fact.
///
/// Field order is the release order. `_source` is declared first so it drops
/// first; the derived lease outlives it and goes last, after everything it paid
/// for is gone.
///
/// # Why the names carry a leading underscore
///
/// Nothing ever reads either field, and nothing should: an owner is held, not
/// consulted. Its whole job is to exist until the value it funded is gone and
/// then run its own `Drop`. The underscore says that in the name rather than in
/// a suppression — a reader who goes looking for the accessor learns there is
/// none, and a future `let CoreOutboundOwner::Delivery { _source, .. }` that
/// tried to inspect the admitted value would be visibly against the grain.
///
/// # Why the delivery is boxed, and why the owner is still whole
///
/// A `ResourceMailboxDelivery<SignalingOutbound>` is far larger than a lease, so
/// an unboxed `Delivery` would set the size of the whole enum and every `First`
/// — the join announce, which has no delivery at all — would carry that
/// footprint for nothing. One indirection on the single large field levels the
/// two variants.
///
/// The box changes where the delivery lives, not what it is. The same value
/// moves in intact, is never taken apart, is never observed, has no second
/// handle, and is dropped as one thing at exactly the moment it was dropped
/// before. Provenance is a lifetime claim, and an indirection does not shorten
/// or fork a lifetime — so "the exact owner travels whole with what it funded"
/// is as true through a `Box` as it was without one.
///
/// The allocation the box performs is itself part of the derived graph, which is
/// why it happens in `recv` only after [`DERIVED_OUTBOUND_CLAIM`] is already in
/// hand. Boxing before that would be the same mistake as translating before it:
/// an allocation made first and funded afterwards.
enum CoreOutboundOwner {
    /// A value the engine admitted, plus the funding for what was built from it.
    Delivery {
        _source: Box<ResourceMailboxDelivery<SignalingOutbound>>,
        _derived: ResourceLease,
    },
    /// The broker join announce: no delivery, because the engine never sent it.
    First { _derived: ResourceLease },
}

/// Provider adapter for Church's attempt-owned Nostr delivery store.
///
/// The store owns the admitted `OwnedSignal` and calls this adapter once for
/// each exact `(attempt, relay-session)` entry.  Admission first measures the
/// driver's compact `EVENT` envelope without constructing its frame, then
/// acquires the exact encoded-byte and one-entry structural claims.  The
/// driver's later frame allocation is therefore covered by the lease that is
/// settled for this exact relay/session terminal.
pub(crate) struct CoreNostrDeliveryProvider {
    scope: LocalApplicationResourceScope,
}

struct CoreNostrDeliveryLease {
    _lease: ResourceLease,
}

/// Routes a typed Nostr attempt admission refusal through the exact owner
/// token captured for the still-current attempt.  Unknown or replaced
/// attempts are deliberately ignored; there is no device-id fallback.
struct CoreAttemptRefusalSink {
    state: Weak<NetworkState>,
}

impl AttemptRefusalSink for CoreAttemptRefusalSink {
    fn refused(&self, refusal: AttemptRefusal) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let Some(owner) = super::owner_for_signaling_attempt(&state, &refusal.attempt) else {
            return;
        };
        if owner.connection().attempt() != refusal.attempt {
            return;
        }
        let _ = state
            .cmd_tx
            .send(NetworkCmd::AttemptRefused { owner, refusal });
    }
}

/// Routes authoritative provider outcomes through the exact current owner.
/// The engine handler rechecks both the installation token and correlation;
/// this sink never settles delivery recursively and never falls back to a
/// device-id lookup.
struct CoreAttemptOutcomeSink {
    state: Weak<NetworkState>,
}

impl AttemptOutcomeSink for CoreAttemptOutcomeSink {
    fn outcome(&self, outcome: AttemptOutcome) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let Some(owner) = super::owner_for_signaling_attempt(&state, &outcome.attempt) else {
            return;
        };
        if owner.connection().attempt() != outcome.attempt {
            return;
        }
        let _ = state
            .cmd_tx
            .send(NetworkCmd::AttemptOutcome { owner, outcome });
    }
}

impl DeliveryLease for CoreNostrDeliveryLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
        // Dropping the exact lease is the settlement.  The terminal is
        // intentionally observational here; attempt/session identity is
        // enforced by DeliveryStore before it calls this method.
    }
}

impl CoreNostrDeliveryProvider {
    fn lease_for_bytes(
        &self,
        bytes: usize,
        label: &str,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| DeliveryRefusal::Provider(format!("{label} retention overflow")))?;
        let claim = ResourceClaim::try_from_entries([
            (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|error| DeliveryRefusal::Provider(error.to_string()))?;
        let lease = self
            .scope
            .acquire(claim)
            .map_err(|error| DeliveryRefusal::Provider(error.to_string()))?;
        Ok(Box::new(CoreNostrDeliveryLease { _lease: lease }))
    }
}

impl DeliveryProvider for CoreNostrDeliveryProvider {
    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        retention: myownmesh_signaling::nostr::delivery::SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.session_record_bytes, "session record")
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        retention: myownmesh_signaling::nostr::delivery::SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.session_set_node_bytes, "session set node")
    }

    fn reserve_session_set_growth(
        &self,
        _session: RelaySessionId,
        retention: myownmesh_signaling::nostr::delivery::SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.session_set_growth_bytes, "session set growth")
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.attempt_record_bytes, "attempt record")
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.attempt_key_bytes, "attempt key")
    }

    fn reserve_attempt_map_growth(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.attempt_map_growth_bytes, "attempt map growth")
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        let bytes = retention
            .encoded_event_bytes
            .checked_add(retention.structural_entry_bytes)
            .ok_or_else(|| DeliveryRefusal::Provider("EVENT retention overflow".to_string()))?;
        self.lease_for_bytes(bytes, "relay delivery")
    }

    fn reserve_relay_map_growth(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.relay_map_growth_bytes, "relay map growth")
    }
}

/// Construct the exact provider adapter passed to the Nostr attempt store.
///
/// Kept crate-visible so the Nostr driver integration can pass the provider
/// without giving the signaling crate a core-resource constructor or a global
/// ledger.
pub(crate) fn nostr_delivery_provider(
    scope: LocalApplicationResourceScope,
) -> Arc<dyn DeliveryProvider> {
    Arc::new(CoreNostrDeliveryProvider { scope })
}

/// What one translated outbound value and its downstream copies cost.
///
/// A structural charge for one derived graph, not a magnitude: it says the
/// translation, the encoded form and the shared clones are things the accountant
/// knows about, and the finite provider decides how many exist at once. Nothing
/// here reads it as a peer limit or a queue depth — there is no queue.
const DERIVED_OUTBOUND_CLAIM: ResourceClaim =
    ResourceClaim::single(crate::resource::ResourceClass::OpaqueDependencyResidual, 1);

fn outbound_attempt(value: &SignalingOutbound) -> Option<&str> {
    match value {
        SignalingOutbound::Offer { attempt, .. }
        | SignalingOutbound::Answer { attempt, .. }
        | SignalingOutbound::Candidate { attempt, .. } => Some(attempt),
        SignalingOutbound::Announce | SignalingOutbound::Leave => None,
    }
}

#[async_trait::async_trait]
impl<T: Send> OutboundSource<T> for TranslatedOutbound<T> {
    type Owner = CoreOutboundOwner;

    async fn recv(&mut self) -> Option<OwnedSignal<T, CoreOutboundOwner>> {
        if let Some((first, derived)) = self.first.take() {
            return Some(OwnedSignal::new(
                first,
                CoreOutboundOwner::First { _derived: derived },
            ));
        }
        // One iteration per admitted emission. The loop exists so that a
        // refusal is scoped to the emission it refused: `None` leaves this
        // function only where the mailbox itself is closed, because that is the
        // only thing a driver's `while let Some(..)` pump can correctly read as
        // "finished". See [`OutboundSource::recv`].
        loop {
            let delivery = self.rx.recv().await?;
            // Acquire before translating. A refusal here means nothing is built:
            // the delivery is dropped whole, its own funding goes back, and the
            // driver simply does not see this emission. That ordering is the fix
            // — the alternative is to build the copy and then discover nobody is
            // paying for it, which is exactly what "admitted before it is queued"
            // was asking to prevent.
            let derived = match self.scope.acquire(DERIVED_OUTBOUND_CLAIM) {
                Ok(lease) => lease,
                Err(error) => {
                    if let (Some(sink), Some(attempt)) = (
                        self.refusal_sink.as_ref(),
                        outbound_attempt(delivery.value()),
                    ) {
                        sink.refused(AttemptRefusal {
                            attempt: attempt.to_string(),
                            event_id: String::new(),
                            refusal: NegotiationRefusal::Provider(error.to_string()),
                        });
                    }
                    // This emission is dropped, and only this emission. The
                    // delivery falls out of scope at the end of the iteration,
                    // which releases the funding the engine put behind it, and
                    // the next admitted value gets its own fresh attempt at the
                    // derived claim.
                    //
                    // It is not re-tried, re-queued or deferred: there is no
                    // timer here and no second buffer, and inventing one would
                    // rebuild the queue this type exists to have removed. A
                    // signaling emission that cannot be funded *now* is stale
                    // shortly after anyway — the engine re-announces, and a lost
                    // offer is re-sent by the negotiation that wanted it.
                    warn!(
                        ?error,
                        "outbound emission dropped: no derived funding for this one"
                    );
                    continue;
                }
            };
            // Read, not taken apart. The translation is a different type
            // carrying fields the engine never sent, so this was never a forward
            // of the delivered value: the delivery stays whole and travels with
            // the result as its owner, alongside the lease that pays for the
            // result itself.
            let value = (self.translate)(delivery.value());
            // The box is allocated here, after the derived lease exists and
            // after the translation it pays for — never before the funding. The
            // delivery moves into it whole; nothing is read out of it, then or
            // ever.
            return Some(OwnedSignal::new(
                value,
                CoreOutboundOwner::Delivery {
                    _source: Box::new(delivery),
                    _derived: derived,
                },
            ));
        }
    }
}

/// The network's local-application scope, or nothing and a reason.
fn local_scope(
    state: &Arc<NetworkState>,
    driver: &str,
) -> Option<crate::resource::LocalApplicationResourceScope> {
    match state.local_application_resource_scope() {
        Ok(scope) => Some(scope),
        Err(error) => {
            warn!(
                network = %state.network_id,
                driver,
                %error,
                "signaling driver not attached: no local application resource scope"
            );
            None
        }
    }
}

/// The ingress runtime for one network, funded by that network's scope.
///
/// The scope is what bounds every record the runtime retains, so a runtime that
/// cannot get one is not built at all rather than built with an invented
/// capacity: there is no unfunded mode to fall back to.
fn signaling_runtime(state: &Arc<NetworkState>, driver: &str) -> Option<Arc<SignalingRuntime>> {
    let runtime = SignalingRuntime::new(
        state.signaling_inbound_tx.clone(),
        local_scope(state, driver)?,
    );
    // Published so the peer lifecycle can tell it when an attempt ends. It is
    // the only consumer, and it only ever releases: nothing outside this module
    // can deliver through the runtime or read what it remembers.
    state.publish_signaling_runtime(&runtime);
    Some(runtime)
}

/// Attach an existing [`NetworkState`] to a [`LocalBroker`] room.
/// Spawns two pump tasks (outbound engine → broker, inbound
/// broker → engine) that live until either side closes its
/// queue. Returns once both pumps are spawned.
pub fn attach_local(state: &Arc<NetworkState>, broker: &LocalBroker) {
    let room = myownmesh_signaling::nostr::handle::derive_room_handle(
        &resolve_app_id(),
        &state.network_id,
    );
    let device_id = state.identity.public_id().to_string();

    // Outbound: engine → broker. Claimed before anything else, so a second
    // attach costs nothing: only one consumer is allowed, and a no-op attach
    // must not join a room or acquire funding it will never use.
    let Some(outbound_rx) = state.take_signaling_outbound_rx() else {
        return;
    };
    // Inbound: broker → engine, through the same ingress boundary the network
    // carriers use. The in-process broker gets the identical typed treatment —
    // admission, provenance, one shared parse — because a local transport that
    // reached the engine by a shorter route would be a second ingress with its
    // own behaviour, and the deterministic suite runs on this one.
    //
    // Its own runtime, because a broker attach is the whole signaling picture
    // for the network it serves: there is no second carrier for it to share
    // de-duplication with. Built before the join, because the join announces:
    // a peer already in the room is told about us inside the call, and there
    // must be somewhere for its reply to land by then.
    let Some(runtime) = signaling_runtime(state, "local") else {
        return;
    };
    // Announce ourselves on join so peers learn we're here even if the engine
    // doesn't emit anything immediately — the source yields it before it drains
    // anything, which is where the pump used to push it.
    let Some(scope) = local_scope(state, "local") else {
        return;
    };
    // **Zero grant builds nothing.** The join announce is an allocation like any
    // other, so its lease is acquired here, before the value exists. A provider
    // with nothing left means the announce is never constructed — not
    // constructed and then found to be unfunded — and the attach returns.
    let Some(first) = scope.acquire(DERIVED_OUTBOUND_CLAIM).ok().map(|derived| {
        (
            LocalOutbound::Announce {
                device_id: device_id.clone(),
            },
            derived,
        )
    }) else {
        warn!(
            network = %state.network_id,
            "local signaling not attached: no funding for the join announce"
        );
        return;
    };
    let device_id_for_out = device_id.clone();
    let outbound: Box<dyn OutboundSource<LocalOutbound, Owner = CoreOutboundOwner>> =
        Box::new(TranslatedOutbound {
            first: Some(first),
            rx: outbound_rx,
            scope,
            translate: Box::new(move |outbound| match outbound {
                SignalingOutbound::Announce => LocalOutbound::Announce {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Leave => LocalOutbound::Leave {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Offer {
                    device_id: to,
                    attempt,
                    sdp,
                } => LocalOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Offer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: attempt.clone(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Answer {
                    device_id: to,
                    attempt,
                    sdp,
                } => LocalOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Answer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: attempt.clone(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    attempt,
                    candidate,
                } => LocalOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Candidate {
                        offer_id: attempt.clone(),
                        peer_id: device_id_for_out.clone(),
                        candidate: candidate.candidate.clone(),
                        sdp_mid: candidate.sdp_mid.clone(),
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment.clone(),
                    },
                },
            }),
            refusal_sink: None,
        });
    let _ = state.with_local_signaling_forwarder(|| {
        let forwarder = broker.join_with_sink(
            &room,
            &device_id,
            outbound,
            carrier_sink(SignalingRuntime::attach(&runtime, SignalingCarrier::Local)),
        );
        ((), forwarder)
    });
}

/// The engine's admission, as the thing a driver hands each report to.
///
/// This is where finding 7's queue used to be. A driver pushed into an unbounded
/// channel, a pump on this side drained it, and the stretch in between was
/// unaccounted memory that an unauthenticated carrier filled at whatever rate it
/// liked. There is no channel and no pump now: the driver's own task carries the
/// value through admission and finds out immediately whether the engine kept it.
///
/// The `false` that stops a driver is the engine being gone — never local
/// pressure, which is a lossy moment a later report recovers from and not a
/// reason to tear down a relay.
fn carrier_sink<R>(attach: CarrierAttach) -> InboundSink<R>
where
    R: Into<CarrierReport> + Send + 'static,
{
    InboundSink::new(move |report: R| {
        let observed = observe(&attach, report.into());
        attach.deliver(observed)
    })
}

/// What a driver reported, in the one shape every driver reports it in.
///
/// The three carrier inbound enums are structurally identical and each is
/// private to its own driver, so this is where they meet. Kept deliberately
/// dumb: it names the three things a carrier can tell us and holds nothing
/// else, because everything downstream of it is the lane boundary's.
enum CarrierReport {
    Announced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Left {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Directed {
        from: String,
        msg: SignalingMessage,
    },
}

impl From<LocalInbound> for CarrierReport {
    fn from(inbound: LocalInbound) -> Self {
        match inbound {
            LocalInbound::PeerAnnounced {
                device_id,
                attribution,
            } => Self::Announced {
                device_id,
                attribution,
            },
            LocalInbound::PeerLeft {
                device_id,
                attribution,
            } => Self::Left {
                device_id,
                attribution,
            },
            LocalInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

impl From<NostrInbound> for CarrierReport {
    fn from(inbound: NostrInbound) -> Self {
        match inbound {
            NostrInbound::PeerAnnounced {
                device_id,
                attribution,
            } => Self::Announced {
                device_id,
                attribution,
            },
            // A relay reported that the peer's signaling socket dropped, or the
            // peer published its own `leave`. Both arrive here as
            // `SenderClaimed`, because either way the device id is one a payload
            // carried and neither the relay nor the event author is
            // authenticated to that device.
            //
            // So this is reachability evidence and nothing more: it may update
            // availability, cancel speculative work, and prompt a look at the
            // connector, and it retires no session in any state. Teardown is
            // exact connector closure, the authenticated
            // `SessionControl::Depart` over the session itself, or the heartbeat.
            // This comment used to say the engine tore the peer down promptly on
            // it, which was true and is not — see `NostrInbound::PeerLeft`.
            NostrInbound::PeerLeft {
                device_id,
                attribution,
            } => Self::Left {
                device_id,
                attribution,
            },
            NostrInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

impl From<MdnsInbound> for CarrierReport {
    fn from(inbound: MdnsInbound) -> Self {
        match inbound {
            MdnsInbound::PeerAnnounced {
                device_id,
                attribution,
            } => Self::Announced {
                device_id,
                attribution,
            },
            MdnsInbound::PeerLeft {
                device_id,
                attribution,
            } => Self::Left {
                device_id,
                attribution,
            },
            MdnsInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

/// Admit one carrier report. The single entry to the ingress boundary, shared
/// by every pump so the carriers cannot drift in how they are admitted.
///
/// The attribution the driver reported is carried across unchanged: this
/// module's job is to hand it on, not to decide it, and the only thing that
/// could honestly decide it is the driver that saw the message arrive.
fn observe(attach: &CarrierAttach, report: CarrierReport) -> CarrierObservation {
    match report {
        CarrierReport::Announced {
            device_id,
            attribution,
        } => attach.presence(device_id, attribution),
        CarrierReport::Left {
            device_id,
            attribution,
        } => attach.withdrawal(device_id, attribution),
        CarrierReport::Directed { from, msg } => attach.directed(from, msg),
    }
}

fn resolve_app_id() -> String {
    std::env::var("MYOWNMESH_TRYSTERO_APP_ID")
        .unwrap_or_else(|_| crate::TRYSTERO_APP_ID.to_string())
}

/// Attach the engine to the production Nostr signaling driver.
/// Returns the driver handle — drop or call `.stop()` to detach.
/// Prefer [`attach_signaling`] unless you specifically want Nostr
/// regardless of the network's configured strategy.
pub fn attach_nostr(state: &Arc<NetworkState>) -> Option<NostrDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let runtime = signaling_runtime(state, "nostr")?;
    attach_nostr_with(
        state,
        outbound_rx,
        SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr),
    )
}

/// [`attach_nostr`] with an explicit outbound receiver + carrier
/// attach, so [`attach_signaling`]'s fan-out can feed several drivers
/// from the one engine receiver and one runtime.
fn attach_nostr_with(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<NostrDriverHandle> {
    let cfg = state.config.read();
    let nostr_cfg = NostrDriverConfig {
        app_id: resolve_app_id(),
        network_id: cfg.network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        servers: cfg.signaling.servers.clone(),
        denylist: cfg.signaling.denylist.clone(),
        redundancy: cfg.signaling.redundancy as usize,
        public_fallback: cfg.signaling.public_fallback,
    };
    let redundancy = nostr_cfg.redundancy;
    drop(cfg);

    let room_handle = myownmesh_signaling::nostr::handle::derive_room_handle(
        &nostr_cfg.app_id,
        &nostr_cfg.network_id,
    );
    state.log_diag(
        crate::events::DiagLevel::Info,
        "signaling",
        format!(
            "online — listening for peers in room {}… ({} relays)",
            &room_handle[..room_handle.len().min(12)],
            redundancy,
        ),
    );

    let device_id = state.identity.public_id().to_string();

    // Outbound: engine SignalingOutbound → NostrOutbound, built when the driver
    // pulls. No explicit startup announce — the Nostr driver's `run_announcer`
    // fires immediately at t=0 and then follows the adaptive backoff schedule
    // (see `upstream.rs` item 7). A second announce from the bridge would just
    // publish a duplicate event (different timestamp → distinct sha256 id, so
    // receiver-side dedup wouldn't collapse it) — wasted relay bandwidth for no
    // benefit.
    let device_id_for_out = device_id.clone();
    let scope = local_scope(state, "nostr")?;
    let provider = nostr_delivery_provider(scope.clone());
    let outbound: Box<dyn OutboundSource<NostrOutbound, Owner = CoreOutboundOwner>> =
        Box::new(TranslatedOutbound {
            first: None,
            rx: outbound_rx,
            scope,
            translate: Box::new(move |outbound| match outbound {
                SignalingOutbound::Announce => NostrOutbound::Announce,
                SignalingOutbound::Leave => NostrOutbound::Leave,
                SignalingOutbound::Offer {
                    device_id: to,
                    attempt,
                    sdp,
                } => NostrOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Offer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: attempt.clone(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Answer {
                    device_id: to,
                    attempt,
                    sdp,
                } => NostrOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Answer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: attempt.clone(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    attempt,
                    candidate,
                } => NostrOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Candidate {
                        offer_id: attempt.clone(),
                        peer_id: device_id_for_out.clone(),
                        candidate: candidate.candidate.clone(),
                        sdp_mid: candidate.sdp_mid.clone(),
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment.clone(),
                    },
                },
            }),
            refusal_sink: Some(Arc::new(CoreAttemptRefusalSink {
                state: Arc::downgrade(state),
            })),
        });

    // Inbound: NostrInbound → engine SignalingInbound on the driver's own task,
    // through this carrier's attach on the shared runtime.
    let handle = nostr_driver::start_with_delivery_provider_and_sinks(
        nostr_cfg,
        outbound,
        carrier_sink(attach),
        provider,
        Arc::new(CoreAttemptRefusalSink {
            state: Arc::downgrade(state),
        }),
        Arc::new(CoreAttemptOutcomeSink {
            state: Arc::downgrade(state),
        }),
    );
    // Hand the engine the force-reconnect signal so resume-from-sleep
    // (and any other recovery path) can make every relay redial at
    // once instead of waiting out a zombie socket. See
    // `wake::on_wake` and `NetworkState::request_relay_reconnect`.
    state.set_relay_reconnect(handle.reconnect_signal());
    // …and the relay-connected signal, so a network-change renegotiation can
    // wait for signaling to actually come back before it offers (see
    // `network_watch::on_network_change`).
    state.set_relay_connected_signal(handle.connected_signal());
    Some(handle)
}

/// Attach Nostr while retaining the exact driver handle behind the network's
/// settlement seam.  The public single-driver helper keeps its historical
/// owning return type; the production multi-driver path uses this wrapper so
/// engine lifecycle events can settle the driver's exact attempt map without
/// resolving a peer by device id.
fn attach_nostr_shared(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<Arc<NostrDriverHandle>> {
    let handle = Arc::new(attach_nostr_with(state, outbound_rx, attach)?);
    let settlement_handle = Arc::clone(&handle);
    state.set_attempt_settlement(Arc::new(move |attempt, terminal| {
        settlement_handle.finish_attempt(attempt, terminal)
    }));
    Some(handle)
}

/// Attach the engine to the LAN mDNS signaling driver. Returns the
/// driver handle — drop or call `.stop()` to withdraw the DNS-SD
/// advertisement and detach. `None` if another consumer already took
/// the engine's outbound receiver, or if the mDNS daemon / exchange
/// listener couldn't come up (no usable socket, no multicast).
/// Prefer [`attach_signaling`] unless you specifically want mDNS
/// regardless of the network's configured strategy.
pub fn attach_mdns(state: &Arc<NetworkState>) -> Option<MdnsDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let runtime = signaling_runtime(state, "mdns")?;
    attach_mdns_with(
        state,
        outbound_rx,
        SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns),
    )
}

/// [`attach_mdns`] with an explicit outbound receiver + carrier
/// attach — the fan-out building block. On driver-start failure the
/// receiver is dropped (a fan-out sender to it becomes a no-op) and
/// a warning names the network.
fn attach_mdns_with(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<MdnsDriverHandle> {
    let mdns_cfg = MdnsDriverConfig {
        app_id: resolve_app_id(),
        network_id: state.config.read().network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        service_port: 0,
    };

    let device_id = state.identity.public_id().to_string();

    // Outbound: engine SignalingOutbound → MdnsOutbound, built when the driver
    // pulls. The driver's registration doubles as the announce, so Announce is
    // a cheap idempotent nudge.
    let scope = local_scope(state, "mdns")?;
    let outbound: Box<dyn OutboundSource<MdnsOutbound, Owner = CoreOutboundOwner>> =
        Box::new(TranslatedOutbound {
            first: None,
            rx: outbound_rx,
            scope,
            translate: Box::new(move |outbound| match outbound {
                SignalingOutbound::Announce => MdnsOutbound::Announce,
                SignalingOutbound::Leave => MdnsOutbound::Leave,
                SignalingOutbound::Offer {
                    device_id: to,
                    attempt,
                    sdp,
                } => MdnsOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Offer {
                        peer_id: device_id.clone(),
                        offer_id: attempt.clone(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Answer {
                    device_id: to,
                    attempt,
                    sdp,
                } => MdnsOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Answer {
                        peer_id: device_id.clone(),
                        offer_id: attempt.clone(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    attempt,
                    candidate,
                } => MdnsOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Candidate {
                        offer_id: attempt.clone(),
                        peer_id: device_id.clone(),
                        candidate: candidate.candidate.clone(),
                        sdp_mid: candidate.sdp_mid.clone(),
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment.clone(),
                    },
                },
            }),
            refusal_sink: None,
        });

    // The driver's setup is synchronously fallible (mDNS daemon, TCP listener),
    // unlike Nostr's lazy socket dials, so it starts here and a failure returns
    // before anything else is consumed. Reports in both directions ride the
    // driver's own task; there is no queue on either side.
    let handle = match mdns_driver::start(mdns_cfg, outbound, carrier_sink(attach)) {
        Ok(h) => h,
        Err(e) => {
            warn!(network = %state.network_id, "mdns signaling unavailable: {e}");
            return None;
        }
    };

    state.log_diag(
        crate::events::DiagLevel::Info,
        "signaling",
        "LAN signaling online — advertising on this network via mDNS".to_string(),
    );

    Some(handle)
}

/// Every signaling driver attached to one network, plus the fan-out
/// task feeding them. Stop-on-drop: the fan-out is aborted and each
/// driver handle's own `Drop` detaches it — so the registry tears
/// signaling down for a network by dropping this value, exactly as
/// it did with the bare Nostr handle before mDNS existed.
pub struct SignalingDrivers {
    nostr: Option<Arc<NostrDriverHandle>>,
    mdns: Option<MdnsDriverHandle>,
    fanout: Option<tokio::task::JoinHandle<()>>,
}

impl SignalingDrivers {
    /// Which drivers are live — for logs/diagnostics.
    pub fn describe(&self) -> String {
        match (&self.nostr, &self.mdns) {
            (Some(_), Some(_)) => "nostr+mdns".into(),
            (Some(_), None) => "nostr".into(),
            (None, Some(_)) => "mdns".into(),
            (None, None) => "none".into(),
        }
    }

    /// Settle every live Nostr relay entry for one exact attempt correlation.
    ///
    /// The engine's authoritative attempt owner calls this at completion,
    /// replacement, or cancellation.  mDNS has no Nostr delivery store, so
    /// the result is zero when this network has no Nostr driver.  Shutdown is
    /// owned by [`Drop`] on the exact driver handle and therefore needs no
    /// second registry or callback here.
    pub fn finish_attempt(&self, attempt: &str, terminal: DeliveryTerminal) -> usize {
        self.nostr
            .as_ref()
            .map(|handle| handle.finish_attempt(attempt, terminal))
            .unwrap_or(0)
    }

    /// Settle a successfully completed attempt on every Nostr relay session.
    pub fn complete_attempt(&self, attempt: &str) -> usize {
        self.finish_attempt(attempt, DeliveryTerminal::AttemptCompleted)
    }

    /// Settle an attempt displaced by an exact replacement.
    pub fn replace_attempt(&self, attempt: &str) -> usize {
        self.finish_attempt(attempt, DeliveryTerminal::AttemptReplaced)
    }

    /// Settle an attempt cancelled by its authoritative owner.
    pub fn cancel_attempt(&self, attempt: &str) -> usize {
        self.finish_attempt(attempt, DeliveryTerminal::Cancelled)
    }
}

impl Drop for SignalingDrivers {
    fn drop(&mut self) {
        if let Some(fanout) = self.fanout.take() {
            fanout.abort();
        }
        // nostr / mdns handles stop via their own Drop impls.
    }
}

/// Attach the signaling driver(s) a network's `SignalingConfig`
/// selects — the production entry point used by the daemon:
///
/// - `strategy`: `""`/`"nostr"` → the Nostr relay driver; `"none"` →
///   no remote driver; anything else → **no remote driver, loudly**
///   (never a silent Nostr fallback).
/// - `mdns: true` (default) additionally attaches the LAN mDNS
///   driver.
///
/// With two drivers, a fan-out task clones each engine emission to
/// both (the engine's outbound receiver is single-consumer) and the
/// one [`SignalingRuntime`] behind both attaches is what lets it see
/// that the two copies coming back are one emission.
///
/// Returns `None` when the outbound receiver was already taken by an
/// earlier attach. A `Some` whose every driver failed (e.g. mdns-only
/// config in a multicast-less environment) still drains the engine's
/// outbound queue so it can't grow unboundedly — the network is
/// simply unreachable, and warnings say so.
pub fn attach_signaling(state: &Arc<NetworkState>) -> crate::Result<Option<SignalingDrivers>> {
    let (strategy, mdns_on) = {
        let cfg = state.config.read();
        (cfg.signaling.strategy.clone(), cfg.signaling.mdns)
    };
    let want_nostr = match strategy.as_str() {
        "" | "nostr" => true,
        "none" => false,
        other => {
            warn!(
                network = %state.network_id,
                strategy = %other,
                "unknown signaling strategy — attaching NO remote driver \
                 (no silent Nostr fallback); check the network's signaling config"
            );
            false
        }
    };

    let Some(outbound_rx) = state.take_signaling_outbound_rx() else {
        return Ok(None);
    };
    // One runtime for the network, one attach per carrier. Sharing it is what
    // makes cross-carrier de-duplication possible at all: two runtimes would
    // each see half the traffic and each swallow nothing.
    let runtime = SignalingRuntime::new(
        state.signaling_inbound_tx.clone(),
        state.local_application_resource_scope()?,
    );
    state.publish_signaling_runtime(&runtime);

    let drivers = match (want_nostr, mdns_on) {
        (true, true) => {
            let (nostr_tx, nostr_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let (mdns_tx, mdns_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let fanout = spawn_fanout(state.clone(), outbound_rx, vec![nostr_tx, mdns_tx]);
            let nostr = attach_nostr_shared(
                state,
                nostr_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr),
            );
            let mdns = attach_mdns_with(
                state,
                mdns_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns),
            );
            SignalingDrivers {
                nostr,
                mdns,
                fanout: Some(fanout),
            }
        }
        (true, false) => SignalingDrivers {
            nostr: attach_nostr_shared(
                state,
                outbound_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr),
            ),
            mdns: None,
            fanout: None,
        },
        (false, true) => {
            let mdns = attach_mdns_with(
                state,
                outbound_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns),
            );
            if mdns.is_none() {
                warn!(
                    network = %state.network_id,
                    "mdns-only signaling failed to start — this network has NO signaling \
                     and is invisible to peers until it is re-joined"
                );
            }
            SignalingDrivers {
                nostr: None,
                mdns,
                fanout: None,
            }
        }
        (false, false) => {
            warn!(
                network = %state.network_id,
                "signaling fully disabled (strategy off and mdns off) — \
                 this network is invisible to peers"
            );
            // Drain the engine's outbound queue so it can't grow
            // unboundedly against a receiver nobody holds.
            SignalingDrivers {
                nostr: None,
                mdns: None,
                fanout: Some(spawn_fanout(state.clone(), outbound_rx, Vec::new())),
            }
        }
    };
    Ok(Some(drivers))
}

/// Clone every engine emission to each driver's queue. A closed
/// driver queue is skipped silently (its driver failed or detached);
/// the task exits when the engine side closes. This is also the one
/// place every outbound signaling event passes exactly once, so the
/// per-network traffic accounting counts publishes here — per logical
/// event, not per driver copy.
fn spawn_fanout(
    state: Arc<NetworkState>,
    mut outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    driver_txs: Vec<ResourceMailboxSender<SignalingOutbound>>,
) -> tokio::task::JoinHandle<()> {
    // While stood-down (signed-evicted), announces are suppressed — but
    // not forever silenced: one probe per this interval still goes out, so
    // a device that gets RE-ADMITTED in place (a fresh signed grant, no
    // re-claim flow) isn't deaf to its own pardon. The probe costs one
    // handshake+deny per interval while still evicted; the moment the
    // members' verdict clears, that same probe is what revives the links.
    const EVICTED_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
    let mut last_evicted_probe: Option<std::time::Instant> = None;
    tokio::spawn(async move {
        while let Some(delivery) = outbound_rx.recv().await {
            // Read, never taken apart. Every driver copy below is separately
            // admitted through its own `ResourceMailboxSender`, so this pump
            // never owns a translated allocation of its own and has no reason
            // to hold the delivered value away from what funds it.
            let msg = delivery.value();
            // A stood-down engine stops advertising itself: an announce is
            // an invitation to dial us, and every member would answer it
            // with a denial. Directed signaling (offers/answers already in
            // flight) still passes — only the broadcast self-advertisement
            // is throttled, to the slow re-admit probe above.
            if matches!(msg, SignalingOutbound::Announce)
                && state.self_evicted.load(std::sync::atomic::Ordering::SeqCst)
            {
                let due = last_evicted_probe
                    .map(|at| at.elapsed() >= EVICTED_PROBE_INTERVAL)
                    .unwrap_or(true);
                if !due {
                    continue;
                }
                last_evicted_probe = Some(std::time::Instant::now());
            }
            state
                .traffic
                .record_signaling_tx(matches!(msg, SignalingOutbound::Announce));
            // The outbound half of the ingress boundary. Nothing routes on
            // it — every emission is transport control — but a dropped copy is
            // named by the signal kind it carried as well as its variant, and
            // the admission is exhaustive, so an emission that is not ephemeral
            // transport control cannot be added without deciding that here.
            let signal = outbound_signal(msg).name();
            let attempt = outbound_attempt(msg).map(str::to_owned);
            let mut delivered = false;
            let mut refusal_reason = None;
            for tx in &driver_txs {
                let kind = match msg {
                    SignalingOutbound::Announce => "announce",
                    SignalingOutbound::Leave => "leave",
                    SignalingOutbound::Offer { .. } => "offer",
                    SignalingOutbound::Answer { .. } => "answer",
                    SignalingOutbound::Candidate { .. } => "candidate",
                };
                match tx.send(msg.clone()) {
                    Ok(()) => delivered = true,
                    Err(ResourceMailboxSendError::Closed(_)) => {
                        refusal_reason = Some("signaling carrier unavailable".to_string());
                    }
                    Err(ResourceMailboxSendError::Pressure { error, .. }) => {
                        refusal_reason = Some(error.to_string());
                        warn!(
                            kind,
                            signal,
                            ?error,
                            "signaling driver copy dropped under declared resource pressure"
                        );
                    }
                    Err(ResourceMailboxSendError::Claim { error, .. }) => {
                        refusal_reason = Some(error.to_string());
                        warn!(kind, signal, %error, "unrepresentable signaling driver copy dropped");
                    }
                }
            }
            if !delivered && !driver_txs.is_empty() {
                if let (Some(attempt), Some(reason)) = (attempt, refusal_reason) {
                    CoreAttemptRefusalSink {
                        state: Arc::downgrade(&state),
                    }
                    .refused(AttemptRefusal {
                        attempt,
                        event_id: String::new(),
                        refusal: NegotiationRefusal::Provider(reason),
                    });
                }
            }
        }
        trace!("signaling fan-out exiting");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::signaling_ingress::{self, EphemeralSignal};

    /// A scope on an isolated provider whose per-dimension grant is `budget`,
    /// plus a handle on the provider itself.
    ///
    /// The provider handle is returned because a control that wants to observe a
    /// refusal needs to *cause* one, and squeezing the grant is not a reliable
    /// way to do that: leases come and go inside the code under test, so a
    /// refusal timed by exhaustion is a refusal timed by whatever released last.
    /// `FiniteResourceProvider` is `Clone` over shared state, so this handle and
    /// the one inside the port are the same accountant.
    fn scoped(
        budget: impl Fn(crate::resource::ResourceClass) -> u64,
    ) -> (
        crate::resource::ProcessResourceRoot,
        LocalApplicationResourceScope,
        crate::resource::FiniteResourceProvider,
    ) {
        let grant = ResourceClaim::try_from_entries(
            crate::resource::ResourceClass::ALL.map(|dimension| (dimension, budget(dimension))),
        )
        .expect("test grant is representable");
        let accountant = crate::resource::FiniteResourceProvider::new(grant);
        let provider = crate::resource::ResourceProviderPort::new(accountant.clone())
            .expect("test grant funds process bookkeeping");
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_local_application_provider(provider)
            .expect("isolated root accepts its provider");
        let scope = root
            .issue_local_application_scope()
            .expect("test local-application scope");
        (root, scope, accountant)
    }

    /// One emission, labelled so a control can tell which one arrived.
    fn labelled(device_id: &str) -> SignalingOutbound {
        SignalingOutbound::Offer {
            device_id: device_id.to_string(),
            attempt: "attempt-1".to_string(),
            sdp: "sdp".to_string(),
        }
    }

    /// A source whose translation reports the label and counts its own runs.
    fn labelling_source(
        rx: crate::resource::ResourceMailboxReceiver<SignalingOutbound>,
        scope: LocalApplicationResourceScope,
        built: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> TranslatedOutbound<String> {
        let counter = Arc::clone(built);
        TranslatedOutbound {
            first: None,
            rx,
            scope,
            translate: Box::new(move |outbound: &SignalingOutbound| {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match outbound {
                    SignalingOutbound::Offer { device_id, .. } => device_id.clone(),
                    other => unreachable!("this control only emits offers, not {other:?}"),
                }
            }),
            refusal_sink: None,
        }
    }

    /// **A derived allocation that cannot be funded is never built.**
    ///
    /// The ordering claim in [`CoreOutboundOwner`], stated as the failure it
    /// exists to prevent: the version that translates first and discovers
    /// afterwards that nobody is paying is the bug, because by then the copy
    /// exists.
    ///
    /// The discrimination is in the labels rather than in a bare count. Two
    /// emissions are admitted and the first is refused, so a correct
    /// implementation yields `"b"` having run the builder exactly once. An
    /// implementation that translated before acquiring would have run it twice,
    /// and one that translated the refused value would yield `"a"`.
    ///
    /// # Why the refusal is scripted rather than squeezed
    ///
    /// The obvious harness — hold leases until the provider is empty, then pull —
    /// does not work here, and the way it fails is instructive. `recv` pops the
    /// mailbox entry *before* it acquires the derived claim, and the pop releases
    /// that entry's queue-node lease. A grant squeezed to zero is therefore back
    /// above zero by exactly the moment the derived acquire runs, so the acquire
    /// succeeds and the control reads as a production ordering failure when the
    /// ordering is correct.
    ///
    /// Scripting one pressure on the residual dimension removes the timing from
    /// the question entirely: the next reservation that charges that dimension is
    /// refused, whatever the balance happens to be. What is under test is the
    /// order of two steps, not the arithmetic of a grant, so the harness should
    /// not depend on the arithmetic either.
    #[tokio::test]
    async fn a_derived_outbound_allocation_that_cannot_be_funded_is_never_built() {
        let (_root, scope, accountant) = scoped(|_| 1_000_000);
        let (tx, rx) = crate::resource::resource_mailbox::<SignalingOutbound>(scope.clone())
            .expect("test mailbox");

        // Admit first, then script. Every mailbox admission charges the residual
        // dimension too, so scripting before the sends would spend the one
        // refusal on an admission instead of on the derived claim under test.
        assert!(tx.send(labelled("a")).is_ok(), "the mailbox admits `a`");
        assert!(tx.send(labelled("b")).is_ok(), "the mailbox admits `b`");
        accountant.script_pressure(crate::resource::ResourceClass::OpaqueDependencyResidual);

        let built = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut source = labelling_source(rx, scope.clone(), &built);

        let owned = source
            .recv()
            .await
            .expect("a fundable translation is produced");
        assert_eq!(
            owned.value(),
            "b",
            "the refused emission was translated and handed on anyway"
        );
        assert_eq!(
            built.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the builder ran for the emission whose funding was refused"
        );
    }

    /// **A refusal costs one emission; only a closed source ends the pump.**
    ///
    /// The failure this exists for is not subtle once seen. Both drivers drain
    /// with `while let Some(outbound) = source.recv().await`, and the Nostr
    /// driver `take`s the source to do it — so a `None` returned for a transient
    /// local refusal would retire that carrier for the rest of the process and
    /// leave everything still in its mailbox undrained. One momentary pressure
    /// on a shared residual dimension would silently cost a node its relay
    /// transport until restart.
    ///
    /// So this control runs the driver's loop verbatim rather than calling `recv`
    /// once. Three emissions are admitted, the sender is dropped so the loop can
    /// legitimately end, and one refusal is scripted before the pump starts.
    ///
    /// Every clause is load-bearing:
    /// * `["b", "c"]` — the refusal cost exactly the emission it refused, and
    ///   the two behind it were still drained. The old shape yields `[]`.
    /// * the builder ran twice — `"a"` was refused *before* translation, so this
    ///   also re-states the acquire-before-translate ordering under a pump.
    /// * the loop terminated at all — genuine closure still returns `None`, so
    ///   the repair did not turn a finished source into a hang.
    #[tokio::test]
    async fn a_refused_emission_costs_one_value_and_only_closure_ends_the_pump() {
        let (_root, scope, accountant) = scoped(|_| 1_000_000);
        let (tx, rx) = crate::resource::resource_mailbox::<SignalingOutbound>(scope.clone())
            .expect("test mailbox");

        for label in ["a", "b", "c"] {
            assert!(
                tx.send(labelled(label)).is_ok(),
                "the mailbox admits every emission this control sends"
            );
        }
        // Closed, but not drained: `close` sets the flag and leaves the queue
        // alone, so the pump sees all three and *then* sees the end.
        drop(tx);
        accountant.script_pressure(crate::resource::ResourceClass::OpaqueDependencyResidual);

        let built = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut source = labelling_source(rx, scope.clone(), &built);

        // The driver's own loop, character for character.
        let mut published = Vec::new();
        while let Some(outbound) = source.recv().await {
            published.push(outbound.value().clone());
        }

        assert_eq!(
            published,
            vec!["b".to_string(), "c".to_string()],
            "a refusal must cost its own emission and nothing behind it"
        );
        assert_eq!(
            built.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the refused emission reached the builder"
        );
    }

    /// **Every carrier reaches the engine through the ingress boundary, and the
    /// engine can still tell which one it was and what the report was worth.**
    ///
    /// The three drivers report the same three things in three private enums;
    /// this is the control that says all nine paths converge on one admission
    /// and keep their provenance. Asserted per carrier rather than once, because
    /// "the field exists" is not the property — "the three are distinguishable
    /// at the far end" is.
    ///
    /// The attribution half is the discriminating part: it is the one thing this
    /// module must carry across without deciding, and a pump that dropped it
    /// would silently turn a payload's claim into a carrier's observation.
    #[test]
    fn every_carrier_report_is_admitted_with_its_provenance_and_attribution() {
        for carrier in [
            SignalingCarrier::Local,
            SignalingCarrier::Nostr,
            SignalingCarrier::Mdns,
        ] {
            let (runtime, _rx) = signaling_ingress::tests::runtime_with_rx();
            let attach = SignalingRuntime::attach(&runtime, carrier);
            let every_report = [
                (
                    CarrierReport::Announced {
                        device_id: "peer-a".into(),
                        attribution: CarrierAttribution::CarrierObserved,
                    },
                    EphemeralSignal::Presence,
                    CarrierAttribution::CarrierObserved,
                ),
                (
                    CarrierReport::Left {
                        device_id: "peer-a".into(),
                        attribution: CarrierAttribution::SenderClaimed,
                    },
                    EphemeralSignal::Withdrawal,
                    CarrierAttribution::SenderClaimed,
                ),
                (
                    CarrierReport::Directed {
                        from: "peer-a".into(),
                        msg: SignalingMessage::Offer {
                            peer_id: "peer-a".into(),
                            offer_id: "offer-1".into(),
                            sdp: "sdp-1".into(),
                        },
                    },
                    EphemeralSignal::ConnectIntent,
                    CarrierAttribution::SenderClaimed,
                ),
            ];
            for (report, signal, attribution) in every_report {
                let admitted = observe(&attach, report).into_ingress();
                assert_eq!(admitted.carrier(), carrier);
                assert_eq!(admitted.signal(), signal);
                assert_eq!(
                    admitted.attribution(),
                    attribution,
                    "the driver decides what its report was worth; the bridge \
                     carries it across"
                );
            }
        }
    }
}
