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

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use myownmesh_signaling::local::{LocalBroker, LocalInbound, LocalOutbound};
use myownmesh_signaling::mdns::{
    self as mdns_driver, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound,
};
use myownmesh_signaling::nostr::delivery::{
    AdmissionSource, DeliveryLease, DeliveryProvider, DeliveryRefusal, DeliveryRetention,
    DeliveryTerminal, RelaySessionId,
};
use myownmesh_signaling::nostr::driver::{
    self as nostr_driver, NostrDriverConfig, NostrDriverHandle, NostrInbound, NostrOutbound,
};
use myownmesh_signaling::{
    AttemptOutcome, AttemptOutcomeSink, AttemptRefusal, AttemptRefusalSink, InboundSink,
    OutboundSource, OwnedSignal, SignalingMessage,
};
use tracing::{trace, warn};

use crate::events::DropReason;
use crate::resource::{
    LocalApplicationResourceScope, ResourceClaim, ResourceLease, ResourceMailboxDelivery,
    ResourceMailboxReceiver, ResourceMailboxSendError, ResourceMailboxSender,
};

use super::signaling_ingress::{
    outbound_signal, CarrierAttach, CarrierAttribution, CarrierInstanceGuard, CarrierObservation,
    SignalingCarrier, SignalingRuntime,
};
use super::state::{
    CarrierEmissionAdmission, CarrierEmissionRecord, NetworkCmd, NetworkState,
    RecoveryCarrierInstance, SignalingEmissionId, SignalingOutbound,
};

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
    recovery_state: Option<Weak<NetworkState>>,
    recovery_instance: Option<RecoveryCarrierInstance>,
    guard: Arc<CarrierInstanceGuard>,
    allow_untracked_emission: bool,
    /// Nostr source admission only proves that a value reached the driver's
    /// delivery boundary. Its provider must report the carrier outcome before
    /// this attempt cohort is marked accepted; local/mDNS sources have no
    /// downstream delivery store and may settle at source admission.
    defer_attempt_acceptance: bool,
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
    guard: Arc<CarrierInstanceGuard>,
    ledger: Arc<std::sync::atomic::AtomicU64>,
}

struct CoreNostrDeliveryLease {
    _lease: ResourceLease,
    ledger: Arc<std::sync::atomic::AtomicU64>,
    bytes: u64,
}

impl Drop for CoreNostrDeliveryLease {
    fn drop(&mut self) {
        self.ledger
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Routes a typed Nostr attempt admission refusal through the exact owner
/// token captured for the still-current attempt.  Unknown or replaced
/// attempts are deliberately ignored; there is no device-id fallback.
struct CoreAttemptRefusalSink {
    state: Weak<NetworkState>,
    instance: Option<RecoveryCarrierInstance>,
    guard: Arc<CarrierInstanceGuard>,
}

impl CoreAttemptRefusalSink {
    fn refused_for(&self, emission: SignalingEmissionId, refusal: AttemptRefusal) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let Some(instance) = self.instance else {
            return;
        };
        let settlement =
            state.record_carrier_emission_with_owner(emission, &refusal.attempt, instance, false);
        self.guard
            .settle_attempt_and_acknowledge(&state, emission, &refusal.attempt, instance);
        if settlement.record != CarrierEmissionRecord::FinalRefusal {
            return;
        }
        if !state.settle_final_refusal_carrier(emission, &refusal.attempt) {
            return;
        }
        let Some(owner) = settlement.owner else {
            return;
        };
        let owner_matches_attempt = owner.connection().attempt() == refusal.attempt
            || owner.worker().is_some_and(|worker| {
                owner.connection().attempt_for_worker(worker).as_deref()
                    == Some(refusal.attempt.as_str())
                    || owner
                        .connection()
                        .speculative_is_exact(&refusal.attempt, worker)
            });
        if !owner_matches_attempt {
            return;
        }
        let fallback_owner = owner.clone();
        let fallback_attempt = refusal.attempt.clone();
        if state
            .cmd_tx
            .send(NetworkCmd::AttemptRefused { owner, refusal })
            .is_err()
        {
            schedule_exact_terminal_cleanup(
                &state,
                fallback_owner,
                fallback_attempt,
                "Nostr attempt refusal command was not accepted",
            );
        }
    }

    fn drop_unadmitted(
        &self,
        emission: Option<SignalingEmissionId>,
        owner: Option<super::peer_registry::PeerOwnerToken>,
        attempt: String,
        reason: impl Into<String>,
    ) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        if let Some(emission) = emission {
            let _ = state.settle_final_refusal_carrier(emission, &attempt);
        }
        let Some(owner) = owner else {
            return;
        };
        let fallback_owner = owner.clone();
        let fallback_correlation = attempt.clone();
        let command = NetworkCmd::DropPeerIfCurrent {
            owner,
            attempt,
            reason: DropReason::TransportError {
                message: reason.into(),
            },
        };
        if state.cmd_tx.send(command).is_err() {
            // The refusal effect is exact-owner work, not a best-effort
            // mailbox notification. If the funded command queue is already
            // closed or pressured, run the same exact candidate/promoted
            // terminal coordinator as the command arm; never fall back to a
            // device-id removal or broad attempt settle.
            schedule_exact_terminal_cleanup(
                &state,
                fallback_owner,
                fallback_correlation,
                "exact refusal cleanup command was not accepted",
            );
        }
    }
}

fn schedule_exact_terminal_cleanup(
    state: &Arc<NetworkState>,
    owner: super::peer_registry::PeerOwnerToken,
    correlation: String,
    message: &'static str,
) {
    super::drop_carrier_if_current_now(
        state,
        &owner,
        DropReason::TransportError {
            message: message.to_string(),
        },
        correlation.as_str(),
    );
}

impl AttemptRefusalSink for CoreAttemptRefusalSink {
    fn refused(&self, refusal: AttemptRefusal) {
        let emission = self.guard.emission_for_source(refusal.source);
        let Some(emission) = emission else {
            return;
        };
        self.refused_for(emission, refusal);
    }
}

/// Routes authoritative provider outcomes through the exact current owner.
/// The engine handler rechecks both the installation token and correlation;
/// this sink never settles delivery recursively and never falls back to a
/// device-id lookup.
struct CoreAttemptOutcomeSink {
    state: Weak<NetworkState>,
    instance: Option<RecoveryCarrierInstance>,
    guard: Arc<CarrierInstanceGuard>,
}

impl AttemptOutcomeSink for CoreAttemptOutcomeSink {
    fn outcome(&self, outcome: AttemptOutcome) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let emission = self.guard.emission_for_source(outcome.source);
        let Some(instance) = self.instance else {
            return;
        };
        let Some(emission) = emission else {
            return;
        };
        let accepted = matches!(
            &outcome.kind,
            myownmesh_signaling::AttemptOutcomeKind::Accepted { .. }
        );
        let settlement = state.record_carrier_emission_with_owner(
            emission,
            &outcome.attempt,
            instance,
            accepted,
        );
        self.guard
            .settle_attempt_and_acknowledge(&state, emission, &outcome.attempt, instance);
        if !outcome_record_is_routable(&outcome.kind, settlement.record) {
            return;
        }
        if settlement.record == CarrierEmissionRecord::FinalRefusal
            && !state.settle_final_refusal_carrier(emission, &outcome.attempt)
        {
            return;
        }
        let Some(owner) = settlement.owner else {
            return;
        };
        let owner_matches_attempt = owner.connection().attempt() == outcome.attempt
            || owner.worker().is_some_and(|worker| {
                owner.connection().attempt_for_worker(worker).as_deref()
                    == Some(outcome.attempt.as_str())
                    || owner
                        .connection()
                        .speculative_is_exact(&outcome.attempt, worker)
            });
        if !owner_matches_attempt {
            return;
        }
        let refusal_terminal = matches!(
            &outcome.kind,
            myownmesh_signaling::AttemptOutcomeKind::TypedRefused(_)
                | myownmesh_signaling::AttemptOutcomeKind::CarrierUnavailable
        );
        let fallback_owner = owner.clone();
        let fallback_attempt = outcome.attempt.clone();
        if state
            .cmd_tx
            .send(NetworkCmd::AttemptOutcome { owner, outcome })
            .is_err()
            && refusal_terminal
        {
            schedule_exact_terminal_cleanup(
                &state,
                fallback_owner,
                fallback_attempt,
                "Nostr attempt outcome command was not accepted",
            );
        }
    }
}

fn outcome_record_is_routable(
    kind: &myownmesh_signaling::AttemptOutcomeKind,
    record: super::state::CarrierEmissionRecord,
) -> bool {
    match kind {
        myownmesh_signaling::AttemptOutcomeKind::Accepted { .. } => {
            record == super::state::CarrierEmissionRecord::Accepted
        }
        myownmesh_signaling::AttemptOutcomeKind::TypedRefused(_)
        | myownmesh_signaling::AttemptOutcomeKind::CarrierUnavailable => {
            record == super::state::CarrierEmissionRecord::FinalRefusal
        }
        myownmesh_signaling::AttemptOutcomeKind::Cancelled
        | myownmesh_signaling::AttemptOutcomeKind::Replaced => false,
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
        self.ledger
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(CoreNostrDeliveryLease {
            _lease: lease,
            ledger: Arc::clone(&self.ledger),
            bytes,
        }))
    }
}

impl DeliveryProvider for CoreNostrDeliveryProvider {
    fn on_admission_source(&self, source: AdmissionSource, attempt: &str, _event_id: &str) {
        // DeliveryStore invokes this before duplicate detection. Bind the
        // fresh process-local source to the already claimed physical emission;
        // refusal routing can therefore ignore attempt/event aliases.
        let _ = self.guard.bind_admission_source(source, attempt);
    }

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
        _retention: myownmesh_signaling::nostr::delivery::SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        // Compatibility growth is the same allocation as the canonical
        // session entry. Charge it exactly once in `reserve_session_entry`.
        self.lease_for_bytes(0, "session set growth alias")
    }

    fn reserve_session_entry(
        &self,
        _session: RelaySessionId,
        retention: myownmesh_signaling::nostr::delivery::SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.session_entry_bytes, "session entry")
    }

    fn reserve_attempt_record(
        &self,
        attempt: &str,
        event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        if self.guard.bind_event_id(attempt, &event.id).is_none() {
            return Err(DeliveryRefusal::Provider(
                "Nostr event has no exact funded signaling emission".to_string(),
            ));
        }
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
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        // Compatibility growth is the same allocation as the canonical
        // attempt entry. Charge it exactly once in `reserve_attempt_entry`.
        self.lease_for_bytes(0, "attempt map growth alias")
    }

    fn reserve_attempt_entry(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.attempt_entry_bytes, "attempt entry")
    }

    fn reserve_attempt_correlation(
        &self,
        attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(attempt.len(), "attempt correlation")
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
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        // Compatibility growth is the same allocation as the canonical relay
        // entry. Charge it exactly once in `reserve_relay_entry`.
        self.lease_for_bytes(0, "relay map growth alias")
    }

    fn reserve_relay_entry(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.lease_for_bytes(retention.relay_entry_bytes, "relay entry")
    }
}

/// Construct the exact provider adapter passed to the Nostr attempt store.
///
/// Kept crate-visible so the Nostr driver integration can pass the provider
/// without giving the signaling crate a core-resource constructor or a global
/// ledger.
pub(crate) fn nostr_delivery_provider(
    scope: LocalApplicationResourceScope,
    guard: Arc<CarrierInstanceGuard>,
) -> Arc<dyn DeliveryProvider> {
    Arc::new(CoreNostrDeliveryProvider {
        scope,
        guard,
        ledger: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
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
        SignalingOutbound::Announce
        | SignalingOutbound::RecoveryAnnounce { .. }
        | SignalingOutbound::Leave => None,
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
            let recovery = self
                .recovery_state
                .as_ref()
                .and_then(|_| match delivery.value() {
                    SignalingOutbound::RecoveryAnnounce { id } => Some(*id),
                    _ => None,
                })
                .and_then(|recovery_id| {
                    self.recovery_state
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .map(|state| (state, recovery_id))
                })
                .and_then(|(state, recovery_id)| {
                    self.recovery_instance.and_then(|instance| {
                        state
                            .begin_recovery_for_carrier(recovery_id, instance)
                            .map(|id| {
                                self.guard.track_recovery(id);
                                (state, instance, id)
                            })
                    })
                });
            if matches!(delivery.value(), SignalingOutbound::RecoveryAnnounce { .. })
                && recovery.is_none()
            {
                // A recovery envelope is admitted only against its carried
                // generation and exact attached carrier instance. Dropping a
                // stale envelope here prevents it from being translated as an
                // ordinary wire-level announce for a later generation.
                continue;
            }
            let attempt = outbound_attempt(delivery.value()).map(str::to_owned);
            let outbound_owner = match delivery.value() {
                SignalingOutbound::Offer { owner, .. }
                | SignalingOutbound::Answer { owner, .. }
                | SignalingOutbound::Candidate { owner, .. } => owner.clone(),
                _ => None,
            };
            let attempt_state = self.recovery_state.as_ref().and_then(Weak::upgrade);
            let mut preadmission = None;
            let emission = if let Some(attempt) = attempt.as_deref() {
                // Fan-out guards precreate one funded node per physical copy.
                // A missing node there is a stale/terminal delivery and must
                // not mint a fresh aggregate; direct single-carrier sources
                // retain their explicit untracked admission path.
                if let (Some(state), Some(instance), Some(owner)) = (
                    attempt_state.as_ref(),
                    self.recovery_instance,
                    outbound_owner.clone(),
                ) {
                    let Some((emission, (admission, fenced))) =
                        self.guard.claim_attempt_with(attempt, |emission| {
                            let admission = state.begin_carrier_emission_for_owner_result(
                                emission,
                                attempt,
                                owner,
                                [instance],
                            );
                            if admission.is_admitted() {
                                state.mark_carrier_emission_claimed(emission, attempt);
                            }
                            let fenced = state.carrier_emission_is_fenced(emission, attempt);
                            (admission, fenced)
                        })
                    else {
                        if let Some(fenced_emission) = self.guard.fenced_emission_for(attempt) {
                            self.guard.settle_attempt_and_acknowledge(
                                state,
                                fenced_emission,
                                attempt,
                                instance,
                            );
                        }
                        continue;
                    };
                    preadmission = Some((admission, fenced));
                    Some(emission)
                } else {
                    match self.guard.claim_attempt(attempt) {
                        Some(emission) => Some(emission),
                        None if self.allow_untracked_emission => Some(SignalingEmissionId::next()),
                        None => {
                            // Lifecycle settlement fences a queued physical
                            // copy but intentionally leaves its exact guard
                            // node until this carrier pull observes it.  Ack
                            // that token here; never recreate an aggregate by
                            // attempt name and never consume a successor.
                            if let (Some(state), Some(instance), Some(emission)) = (
                                attempt_state.as_ref(),
                                self.recovery_instance,
                                self.guard.fenced_emission_for(attempt),
                            ) {
                                self.guard.settle_attempt_and_acknowledge(
                                    state, emission, attempt, instance,
                                );
                            }
                            continue;
                        }
                    }
                }
            } else {
                None
            };
            if let (Some(state), Some(attempt), Some(emission), Some((admission, fenced))) = (
                attempt_state.as_ref(),
                attempt.as_deref(),
                emission,
                preadmission,
            ) {
                if admission == CarrierEmissionAdmission::Stale || fenced {
                    if let Some(instance) = self.recovery_instance {
                        self.guard
                            .settle_attempt_and_acknowledge(state, emission, attempt, instance);
                    } else {
                        self.guard.settle_attempt(emission);
                    }
                    continue;
                }
                if !admission.is_admitted() {
                    if let Some(instance) = self.recovery_instance {
                        self.guard
                            .settle_attempt_and_acknowledge(state, emission, attempt, instance);
                    } else {
                        self.guard.settle_attempt(emission);
                    }
                    continue;
                }
            }
            // Acquire before translating. A refusal here means nothing is built:
            // the delivery is dropped whole, its own funding goes back, and the
            // driver simply does not see this emission. That ordering is the fix
            // — the alternative is to build the copy and then discover nobody is
            // paying for it, which is exactly what "admitted before it is queued"
            // was asking to prevent.
            let derived = match self.scope.acquire(DERIVED_OUTBOUND_CLAIM) {
                Ok(lease) => lease,
                Err(error) => {
                    if let Some((state, instance, id)) = recovery {
                        state.record_recovery_carrier(id, instance, false);
                        self.guard.settle_recovery(id);
                    }
                    let final_refusal =
                        if let (Some(state), Some(attempt), Some(instance), Some(emission)) = (
                            attempt_state.as_ref(),
                            attempt.as_deref(),
                            self.recovery_instance,
                            emission,
                        ) {
                            let record =
                                state.record_carrier_emission(emission, attempt, instance, false);
                            self.guard
                                .settle_attempt_and_acknowledge(state, emission, attempt, instance);
                            record == CarrierEmissionRecord::FinalRefusal
                        } else {
                            if let Some(emission) = emission {
                                self.guard.settle_attempt(emission);
                            }
                            false
                        };
                    if let (true, true, Some(attempt), Some(state), Some(instance)) = (
                        final_refusal,
                        self.refusal_sink.is_some(),
                        attempt.clone(),
                        attempt_state.as_ref(),
                        self.recovery_instance,
                    ) {
                        CoreAttemptRefusalSink {
                            state: Arc::downgrade(state),
                            instance: Some(instance),
                            guard: Arc::clone(&self.guard),
                        }
                        .drop_unadmitted(
                            emission,
                            outbound_owner.clone(),
                            attempt,
                            error.to_string(),
                        );
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
            if let Some((state, instance, id)) = recovery {
                state.record_recovery_carrier(id, instance, true);
                self.guard.settle_recovery(id);
            }
            if !self.defer_attempt_acceptance {
                if let (Some(state), Some(attempt), Some(instance)) = (
                    attempt_state.as_ref(),
                    attempt.as_deref(),
                    self.recovery_instance,
                ) {
                    let emission = emission.expect("attempt emission");
                    state.record_carrier_emission(emission, attempt, instance, true);
                    self.guard
                        .settle_attempt_and_acknowledge(state, emission, attempt, instance);
                }
                if (attempt_state.is_none() || self.recovery_instance.is_none())
                    && emission.is_some()
                {
                    if let Some(emission) = emission {
                        self.guard.settle_attempt(emission);
                    }
                }
            }
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
    let recovery_instance = state.next_recovery_carrier_instance();
    let Some(attach) = SignalingRuntime::attach_for_state(
        &runtime,
        SignalingCarrier::Local,
        state,
        recovery_instance,
    ) else {
        warn!(network = %state.network_id, "local signaling not attached: guard index unfunded");
        return;
    };
    let guard = attach.guard();
    let Ok((local_tx, local_rx)) = crate::resource::resource_mailbox(scope.clone()) else {
        return;
    };
    let fanout = spawn_fanout(
        state.clone(),
        outbound_rx,
        vec![(recovery_instance, local_tx, Arc::clone(&guard))],
    );
    if state
        .with_local_signaling_forwarder(|| ((), fanout))
        .is_none()
    {
        return;
    }
    let device_id_for_out = device_id.clone();
    let outbound: Box<dyn OutboundSource<LocalOutbound, Owner = CoreOutboundOwner>> =
        Box::new(TranslatedOutbound {
            first: Some(first),
            rx: local_rx,
            scope,
            translate: Box::new(move |outbound| match outbound {
                SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. } => {
                    LocalOutbound::Announce {
                        device_id: device_id_for_out.clone(),
                    }
                }
                SignalingOutbound::Leave => LocalOutbound::Leave {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Offer {
                    device_id: to,
                    attempt,
                    sdp,
                    ..
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
                    ..
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
                    ..
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
            recovery_state: Some(Arc::downgrade(state)),
            recovery_instance,
            guard,
            allow_untracked_emission: false,
            defer_attempt_acceptance: false,
        });
    let _ = state.with_local_signaling_forwarder(|| {
        let forwarder = broker.join_with_sink(&room, &device_id, outbound, carrier_sink(attach));
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
    let (nostr_tx, nostr_rx) =
        crate::resource::resource_mailbox(state.local_application_resource_scope().ok()?).ok()?;
    let recovery_instance = state.next_recovery_carrier_instance();
    let attach = SignalingRuntime::attach_for_state(
        &runtime,
        SignalingCarrier::Nostr,
        state,
        recovery_instance,
    )?;
    let guard = attach.guard();
    let handle = attach_nostr_with(state, nostr_rx, attach, recovery_instance, false)?;
    let fanout = spawn_fanout(
        state.clone(),
        outbound_rx,
        vec![(recovery_instance, nostr_tx, guard)],
    );
    let handle = state.with_local_signaling_forwarder(|| (handle, fanout))?;
    Some(handle)
}

/// [`attach_nostr`] with an explicit outbound receiver + carrier
/// attach, so [`attach_signaling`]'s fan-out can feed several drivers
/// from the one engine receiver and one runtime.
fn attach_nostr_with(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
    recovery_instance: Option<RecoveryCarrierInstance>,
    allow_untracked_emission: bool,
) -> Option<NostrDriverHandle> {
    let guard = attach.guard();
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
    let provider = nostr_delivery_provider(scope.clone(), Arc::clone(&guard));
    let outbound: Box<dyn OutboundSource<NostrOutbound, Owner = CoreOutboundOwner>> =
        Box::new(TranslatedOutbound {
            first: None,
            rx: outbound_rx,
            scope,
            translate: Box::new(move |outbound| match outbound {
                SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. } => {
                    NostrOutbound::Announce
                }
                SignalingOutbound::Leave => NostrOutbound::Leave,
                SignalingOutbound::Offer {
                    device_id: to,
                    attempt,
                    sdp,
                    ..
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
                    ..
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
                    ..
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
                instance: recovery_instance,
                guard: Arc::clone(&guard),
            })),
            recovery_state: Some(Arc::downgrade(state)),
            recovery_instance,
            guard: Arc::clone(&guard),
            allow_untracked_emission,
            defer_attempt_acceptance: true,
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
            instance: recovery_instance,
            guard: Arc::clone(&guard),
        }),
        Arc::new(CoreAttemptOutcomeSink {
            state: Arc::downgrade(state),
            instance: recovery_instance,
            guard: Arc::clone(&guard),
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
    recovery_instance: Option<RecoveryCarrierInstance>,
    allow_untracked_emission: bool,
) -> Option<Arc<NostrDriverHandle>> {
    let handle = Arc::new(attach_nostr_with(
        state,
        outbound_rx,
        attach,
        recovery_instance,
        allow_untracked_emission,
    )?);
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
    let (mdns_tx, mdns_rx) =
        crate::resource::resource_mailbox(state.local_application_resource_scope().ok()?).ok()?;
    let recovery_instance = state.next_recovery_carrier_instance();
    let attach = SignalingRuntime::attach_for_state(
        &runtime,
        SignalingCarrier::Mdns,
        state,
        recovery_instance,
    )?;
    let guard = attach.guard();
    let handle = attach_mdns_with(state, mdns_rx, attach, recovery_instance, false)?;
    let fanout = spawn_fanout(
        state.clone(),
        outbound_rx,
        vec![(recovery_instance, mdns_tx, guard)],
    );
    let handle = state.with_local_signaling_forwarder(|| (handle, fanout))?;
    Some(handle)
}

/// [`attach_mdns`] with an explicit outbound receiver + carrier
/// attach — the fan-out building block. On driver-start failure the
/// receiver is dropped (a fan-out sender to it becomes a no-op) and
/// a warning names the network.
fn attach_mdns_with(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
    recovery_instance: Option<RecoveryCarrierInstance>,
    allow_untracked_emission: bool,
) -> Option<MdnsDriverHandle> {
    let guard = attach.guard();
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
                SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. } => {
                    MdnsOutbound::Announce
                }
                SignalingOutbound::Leave => MdnsOutbound::Leave,
                SignalingOutbound::Offer {
                    device_id: to,
                    attempt,
                    sdp,
                    ..
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
                    ..
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
                    ..
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
            refusal_sink: Some(Arc::new(CoreAttemptRefusalSink {
                state: Arc::downgrade(state),
                instance: recovery_instance,
                guard: Arc::clone(&guard),
            })),
            recovery_state: Some(Arc::downgrade(state)),
            recovery_instance,
            guard: Arc::clone(&guard),
            allow_untracked_emission,
            defer_attempt_acceptance: false,
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
            let nostr_instance = state.next_recovery_carrier_instance();
            let mdns_instance = state.next_recovery_carrier_instance();
            let Some(nostr_attach) = SignalingRuntime::attach_for_state(
                &runtime,
                SignalingCarrier::Nostr,
                state,
                nostr_instance,
            ) else {
                return Err(crate::Error::Network("nostr guard index unfunded".into()));
            };
            let Some(mdns_attach) = SignalingRuntime::attach_for_state(
                &runtime,
                SignalingCarrier::Mdns,
                state,
                mdns_instance,
            ) else {
                runtime.detach_guards();
                return Err(crate::Error::Network("mdns guard index unfunded".into()));
            };
            let fanout = spawn_fanout(
                state.clone(),
                outbound_rx,
                vec![
                    (nostr_instance, nostr_tx, nostr_attach.guard()),
                    (mdns_instance, mdns_tx, mdns_attach.guard()),
                ],
            );
            let nostr = attach_nostr_shared(state, nostr_rx, nostr_attach, nostr_instance, false);
            let mdns = attach_mdns_with(state, mdns_rx, mdns_attach, mdns_instance, false);
            SignalingDrivers {
                nostr,
                mdns,
                fanout: Some(fanout),
            }
        }
        (true, false) => {
            let (nostr_tx, nostr_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let recovery_instance = state.next_recovery_carrier_instance();
            let Some(attach) = SignalingRuntime::attach_for_state(
                &runtime,
                SignalingCarrier::Nostr,
                state,
                recovery_instance,
            ) else {
                return Err(crate::Error::Network("nostr guard index unfunded".into()));
            };
            let fanout = spawn_fanout(
                state.clone(),
                outbound_rx,
                vec![(recovery_instance, nostr_tx, attach.guard())],
            );
            SignalingDrivers {
                nostr: attach_nostr_shared(state, nostr_rx, attach, recovery_instance, false),
                mdns: None,
                fanout: Some(fanout),
            }
        }
        (false, true) => {
            let (mdns_tx, mdns_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let recovery_instance = state.next_recovery_carrier_instance();
            let Some(attach) = SignalingRuntime::attach_for_state(
                &runtime,
                SignalingCarrier::Mdns,
                state,
                recovery_instance,
            ) else {
                return Err(crate::Error::Network("mdns guard index unfunded".into()));
            };
            let fanout = spawn_fanout(
                state.clone(),
                outbound_rx,
                vec![(recovery_instance, mdns_tx, attach.guard())],
            );
            let mdns = attach_mdns_with(state, mdns_rx, attach, recovery_instance, false);
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
                fanout: Some(fanout),
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
    driver_txs: Vec<(
        Option<RecoveryCarrierInstance>,
        ResourceMailboxSender<SignalingOutbound>,
        Arc<CarrierInstanceGuard>,
    )>,
) -> tokio::task::JoinHandle<()> {
    // While stood-down (signed-evicted), announces are suppressed — but
    // not forever silenced: one probe per this interval still goes out, so
    // a device that gets RE-ADMITTED in place (a fresh signed grant, no
    // re-claim flow) isn't deaf to its own pardon. The probe costs one
    // handshake+deny per interval while still evicted; the moment the
    // members' verdict clears, that same probe is what revives the links.
    tokio::spawn(async move {
        while let Some(delivery) = outbound_rx.recv().await {
            // Read, never taken apart. Every driver copy below is separately
            // admitted through its own `ResourceMailboxSender`, so this pump
            // never owns a translated allocation of its own and has no reason
            // to hold the delivered value away from what funds it.
            let msg = delivery.value();
            let recovery_id = match msg {
                SignalingOutbound::RecoveryAnnounce { id } => Some(*id),
                _ => None,
            };
            if let Some(id) = recovery_id {
                let instances: Vec<_> = driver_txs
                    .iter()
                    .filter_map(|(instance, _, _)| *instance)
                    .collect();
                match state.begin_recovery_publication_result(id, instances) {
                    super::state::RecoveryPublicationStart::Started(_) => {}
                    super::state::RecoveryPublicationStart::Stale => {
                        // A stale fan-out copy cannot claim a later publication.
                        // Do not forward it to a carrier either: forwarding an old
                        // envelope would let a source observe a later generation.
                        continue;
                    }
                    super::state::RecoveryPublicationStart::Refused(error) => {
                        warn!(?error, "recovery publication refused before carrier fanout");
                        continue;
                    }
                }
                let all_tracked = driver_txs
                    .iter()
                    .all(|(_, _, guard)| guard.track_recovery(id));
                if !all_tracked {
                    for (instance, _, guard) in &driver_txs {
                        guard.settle_recovery(id);
                        if let Some(instance) = instance {
                            state.record_recovery_carrier(id, *instance, false);
                        }
                    }
                    state.refuse_empty_recovery_publication(id);
                    continue;
                }
            }
            // A stood-down engine stops advertising itself: an announce is
            // an invitation to dial us, and every member would answer it
            // with a denial. Directed signaling (offers/answers already in
            // flight) still passes — only the broadcast self-advertisement
            // is throttled, to the slow re-admit probe above.
            if matches!(
                msg,
                SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. }
            ) && state.self_evicted.load(std::sync::atomic::Ordering::SeqCst)
            {
                continue;
            }
            state.traffic.record_signaling_tx(matches!(
                msg,
                SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. }
            ));
            // The outbound half of the ingress boundary. Nothing routes on
            // it — every emission is transport control — but a dropped copy is
            // named by the signal kind it carried as well as its variant, and
            // the admission is exhaustive, so an emission that is not ephemeral
            // transport control cannot be added without deciding that here.
            let signal = outbound_signal(msg).name();
            let attempt = outbound_attempt(msg).map(str::to_owned);
            let outbound_owner = match msg {
                SignalingOutbound::Offer { owner, .. }
                | SignalingOutbound::Answer { owner, .. }
                | SignalingOutbound::Candidate { owner, .. } => owner.clone(),
                _ => None,
            };
            let emission = attempt.as_deref().map(|_| SignalingEmissionId::next());
            if let Some(attempt) = attempt.as_deref() {
                if let Some(emission) = emission {
                    // Register every physical copy before activating the
                    // state-side aggregate. A detached first guard must not
                    // leave a live state node for a later queued copy, and a
                    // partial registration is not a fan-out publication.
                    let all_tracked = driver_txs
                        .iter()
                        .all(|(_, _, guard)| guard.track_attempt(emission, attempt));
                    if !all_tracked {
                        for (_, _, guard) in &driver_txs {
                            guard.settle_attempt(emission);
                        }
                        CoreAttemptRefusalSink {
                            state: Arc::downgrade(&state),
                            instance: None,
                            guard: CarrierInstanceGuard::noop(None),
                        }
                        .drop_unadmitted(
                            None,
                            outbound_owner.clone(),
                            attempt.to_string(),
                            "carrier emission custody refused",
                        );
                        continue;
                    }
                    let instances = driver_txs.iter().filter_map(|(instance, _, _)| *instance);
                    let admission =
                        outbound_owner
                            .clone()
                            .map_or(CarrierEmissionAdmission::Refused, |owner| {
                                state.begin_carrier_emission_for_owner_result(
                                    emission,
                                    attempt,
                                    owner,
                                    instances.clone(),
                                )
                            });
                    if admission == CarrierEmissionAdmission::Stale {
                        for (_, _, guard) in &driver_txs {
                            guard.settle_attempt(emission);
                        }
                        continue;
                    }
                    if !admission.is_admitted() {
                        for (_, _, guard) in &driver_txs {
                            guard.settle_attempt(emission);
                        }
                        CoreAttemptRefusalSink {
                            state: Arc::downgrade(&state),
                            instance: None,
                            guard: CarrierInstanceGuard::noop(None),
                        }
                        .drop_unadmitted(
                            Some(emission),
                            outbound_owner.clone(),
                            attempt.to_string(),
                            "signaling emission cohort refused",
                        );
                        continue;
                    }
                }
            }
            #[cfg(test)]
            let fanout_gate = {
                FANOUT_AFTER_ADMISSION
                    .get_or_init(|| Mutex::new(None))
                    .lock()
                    .expect("fanout test hook mutex is not poisoned")
                    .clone()
            };
            #[cfg(test)]
            if let Some(gate) = fanout_gate {
                gate.entered.notify_waiters();
                gate.release.notified().await;
            }
            let mut final_refusal = false;
            let mut final_owner = None;
            let mut refusal_reason = None;
            for (instance, tx, guard) in &driver_txs {
                let kind = match msg {
                    SignalingOutbound::Announce | SignalingOutbound::RecoveryAnnounce { .. } => {
                        "announce"
                    }
                    SignalingOutbound::Leave => "leave",
                    SignalingOutbound::Offer { .. } => "offer",
                    SignalingOutbound::Answer { .. } => "answer",
                    SignalingOutbound::Candidate { .. } => "candidate",
                };
                match tx.send(msg.clone()) {
                    Ok(()) => {}
                    Err(ResourceMailboxSendError::Closed(_)) => {
                        refusal_reason = Some("signaling carrier unavailable".to_string());
                        if let (Some(attempt), Some(instance), Some(emission)) =
                            (attempt.as_deref(), instance, emission)
                        {
                            let settlement = state.record_carrier_emission_with_owner(
                                emission, attempt, *instance, false,
                            );
                            if settlement.record == CarrierEmissionRecord::FinalRefusal {
                                final_refusal = true;
                                final_owner = settlement.owner;
                            }
                            guard.settle_attempt_and_acknowledge(
                                &state, emission, attempt, *instance,
                            );
                        }
                        if let (Some(id), Some(instance)) = (recovery_id, instance) {
                            state.record_recovery_carrier(id, *instance, false);
                            guard.settle_recovery(id);
                        }
                    }
                    Err(ResourceMailboxSendError::Pressure { error, .. }) => {
                        refusal_reason = Some(error.to_string());
                        warn!(
                            kind,
                            signal,
                            ?error,
                            "signaling driver copy dropped under declared resource pressure"
                        );
                        if let (Some(attempt), Some(instance), Some(emission)) =
                            (attempt.as_deref(), instance, emission)
                        {
                            let settlement = state.record_carrier_emission_with_owner(
                                emission, attempt, *instance, false,
                            );
                            if settlement.record == CarrierEmissionRecord::FinalRefusal {
                                final_refusal = true;
                                final_owner = settlement.owner;
                            }
                            guard.settle_attempt_and_acknowledge(
                                &state, emission, attempt, *instance,
                            );
                        }
                        if let (Some(id), Some(instance)) = (recovery_id, instance) {
                            state.record_recovery_carrier(id, *instance, false);
                            guard.settle_recovery(id);
                        }
                    }
                    Err(ResourceMailboxSendError::Claim { error, .. }) => {
                        refusal_reason = Some(error.to_string());
                        warn!(kind, signal, %error, "unrepresentable signaling driver copy dropped");
                        if let (Some(attempt), Some(instance), Some(emission)) =
                            (attempt.as_deref(), instance, emission)
                        {
                            let settlement = state.record_carrier_emission_with_owner(
                                emission, attempt, *instance, false,
                            );
                            if settlement.record == CarrierEmissionRecord::FinalRefusal {
                                final_refusal = true;
                                final_owner = settlement.owner;
                            }
                            guard.settle_attempt_and_acknowledge(
                                &state, emission, attempt, *instance,
                            );
                        }
                        if let (Some(id), Some(instance)) = (recovery_id, instance) {
                            state.record_recovery_carrier(id, *instance, false);
                            guard.settle_recovery(id);
                        }
                    }
                }
            }
            if let Some(id) = recovery_id {
                state.refuse_empty_recovery_publication(id);
            }
            if final_refusal && !driver_txs.is_empty() {
                if let Some(reason) = refusal_reason {
                    if let Some(attempt) = attempt.clone() {
                        CoreAttemptRefusalSink {
                            state: Arc::downgrade(&state),
                            instance: None,
                            guard: CarrierInstanceGuard::noop(None),
                        }
                        .drop_unadmitted(
                            emission,
                            final_owner,
                            attempt,
                            reason,
                        );
                    }
                }
            }
        }
        trace!("signaling fan-out exiting");
    })
}

#[cfg(test)]
struct FanoutTestGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static FANOUT_AFTER_ADMISSION: OnceLock<Mutex<Option<Arc<FanoutTestGate>>>> = OnceLock::new();

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
            owner: None,
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
            recovery_state: None,
            recovery_instance: None,
            guard: CarrierInstanceGuard::noop(None),
            allow_untracked_emission: true,
            defer_attempt_acceptance: false,
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

    #[test]
    fn emissions_are_distinct_even_when_attempts_are_reused() {
        let first = SignalingEmissionId::next();
        let second = SignalingEmissionId::next();
        assert_ne!(first, second);
    }

    #[test]
    fn core_provider_accounts_each_retention_delta_once() {
        let (_root, scope, accountant) = scoped(|dimension| match dimension {
            crate::resource::ResourceClass::AccountedMemoryBytes => 1_000_000,
            _ => 10_000,
        });
        let provider = CoreNostrDeliveryProvider {
            scope,
            guard: CarrierInstanceGuard::noop(None),
            ledger: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        let before = accountant
            .in_use()
            .amount(crate::resource::ResourceClass::AccountedMemoryBytes);
        let lease = provider
            .lease_for_bytes(37, "ledger-control")
            .expect("the isolated provider admits the exact retention");
        let after = accountant
            .in_use()
            .amount(crate::resource::ResourceClass::AccountedMemoryBytes);
        assert_eq!(after - before, 37);
        assert_eq!(
            provider.ledger.load(std::sync::atomic::Ordering::SeqCst),
            37,
            "provider ledger tracks the exact live retention"
        );
        drop(lease);
        assert_eq!(
            accountant
                .in_use()
                .amount(crate::resource::ResourceClass::AccountedMemoryBytes),
            before
        );
        assert_eq!(
            provider.ledger.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "provider ledger returns to baseline after settlement"
        );
    }

    #[test]
    fn core_provider_delivery_store_session_and_admission_return_to_ledger_baseline() {
        let state = crate::engine::build_test_state("delivery-store-ledger");
        let instance = state
            .next_recovery_carrier_instance()
            .expect("the isolated state mints one carrier instance");
        let guard = CarrierInstanceGuard::for_state(&state, Some(instance));
        let emission = SignalingEmissionId::next();
        let duplicate_emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "ledger-attempt", [instance]));
        assert!(state.begin_carrier_emission(duplicate_emission, "ledger-attempt", [instance]));
        assert!(guard.track_attempt(emission, "ledger-attempt"));
        assert!(guard.track_attempt(duplicate_emission, "ledger-attempt"));
        assert_eq!(guard.claim_attempt("ledger-attempt"), Some(emission));
        assert_eq!(
            guard.claim_attempt("ledger-attempt"),
            Some(duplicate_emission)
        );
        let provider = Arc::new(CoreNostrDeliveryProvider {
            scope: state
                .local_application_resource_scope()
                .expect("the test state has a local application scope"),
            guard: Arc::clone(&guard),
            ledger: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let store = myownmesh_signaling::nostr::delivery::DeliveryStore::new(provider.clone());
        let baseline = provider.ledger.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            baseline, 0,
            "a fresh production provider starts at baseline"
        );
        let (session, session_refusals) = store.open_session();
        assert!(session_refusals.is_empty());
        let after_session = provider.ledger.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_session > baseline);
        let event = myownmesh_signaling::nostr::event::make_event(
            &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
            myownmesh_signaling::nostr::event::SIGNALING_EPHEMERAL_KIND,
            Vec::new(),
            "ledger-control".to_string(),
            1,
        );
        let retention = DeliveryRetention::for_attempt("ledger-attempt", &event);
        let attempt_custody = u64::try_from(retention.attempt_key_bytes)
            .expect("attempt key retention fits the provider ledger")
            .checked_add(
                u64::try_from(retention.attempt_entry_bytes)
                    .expect("attempt entry retention fits the provider ledger"),
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    u64::try_from("ledger-attempt".len())
                        .expect("attempt correlation retention fits the provider ledger"),
                )
            })
            .expect("attempt custody retention does not overflow the provider ledger");
        let relay_custody = u64::try_from(retention.encoded_event_bytes)
            .expect("encoded event retention fits the provider ledger")
            .checked_add(
                u64::try_from(retention.relay_entry_bytes)
                    .expect("relay entry retention fits the provider ledger"),
            )
            .expect("relay custody retention does not overflow the provider ledger");
        let event_id = event.id.clone();
        let report = store.admit(
            "ledger-attempt".to_string(),
            OwnedSignal::new(
                event.clone(),
                Box::new(()) as myownmesh_signaling::ErasedOwner,
            ),
        );
        assert_eq!(report.accepted_sessions, 1);
        let after_admission = provider.ledger.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            after_admission,
            after_session + attempt_custody + relay_custody,
            "CoreNostrDeliveryProvider charges each real session/attempt/relay allocation once"
        );
        assert_eq!(guard.emission_for_source(report.source), Some(emission));
        let duplicate = store.admit(
            "ledger-attempt".to_string(),
            OwnedSignal::new(event, Box::new(()) as myownmesh_signaling::ErasedOwner),
        );
        assert_eq!(duplicate.accepted_sessions, 0);
        assert!(matches!(
            duplicate.attempt_refusal,
            Some(myownmesh_signaling::nostr::delivery::AdmissionRefusal::DuplicateLiveEvent)
        ));
        assert_ne!(duplicate.source, report.source);
        assert_eq!(
            guard.emission_for_source(duplicate.source),
            Some(duplicate_emission)
        );
        assert_eq!(
            state.record_carrier_emission(emission, "ledger-attempt", instance, true),
            crate::engine::state::CarrierEmissionRecord::Accepted
        );
        assert_eq!(
            state.record_carrier_emission(duplicate_emission, "ledger-attempt", instance, false,),
            crate::engine::state::CarrierEmissionRecord::FinalRefusal
        );
        guard.settle_attempt(emission);
        guard.settle_attempt(duplicate_emission);
        assert_eq!(
            provider.ledger.load(std::sync::atomic::Ordering::SeqCst),
            after_admission,
            "carrier settlement does not release provider-owned delivery custody"
        );
        assert!(store.settle(&session, &event_id, DeliveryTerminal::Cancelled));
        assert_eq!(
            provider.ledger.load(std::sync::atomic::Ordering::SeqCst),
            after_session + attempt_custody,
            "cancelled relay custody remains while the attempt is reconnectable"
        );
        assert_eq!(
            store.finish_attempt("ledger-attempt", DeliveryTerminal::Cancelled),
            0,
            "the cancelled relay leaves attempt custody to its lifecycle terminal"
        );
        assert_eq!(
            provider.ledger.load(std::sync::atomic::Ordering::SeqCst),
            after_session,
            "attempt custody is released only at its lifecycle terminal"
        );
        store.close_session(session, DeliveryTerminal::Cancelled);
        assert_eq!(
            provider.ledger.load(std::sync::atomic::Ordering::SeqCst),
            baseline
        );
    }

    #[test]
    fn same_attempt_event_ids_settle_out_of_order() {
        let state = crate::engine::build_test_state("emission-events");
        let guard = CarrierInstanceGuard::for_state(&state, state.next_recovery_carrier_instance());
        let first = SignalingEmissionId::next();
        let second = SignalingEmissionId::next();
        assert!(guard.track_attempt(first, "same-attempt"));
        assert!(guard.track_attempt(second, "same-attempt"));
        assert_eq!(guard.claim_attempt("same-attempt"), Some(first));
        assert_eq!(guard.claim_attempt("same-attempt"), Some(second));
        let first_event = "0000000000000000000000000000000000000000000000000000000000000001";
        let second_event = "0000000000000000000000000000000000000000000000000000000000000002";
        assert_eq!(
            guard.bind_event_id("same-attempt", first_event),
            Some(first)
        );
        assert_eq!(
            guard.bind_event_id("same-attempt", second_event),
            Some(second)
        );
        assert_eq!(
            guard.emission_for_event("same-attempt", second_event),
            Some(second)
        );
        guard.settle_attempt(first);
        assert_eq!(guard.emission_for_event("same-attempt", first_event), None);
        assert_eq!(
            guard.emission_for_event("same-attempt", second_event),
            Some(second)
        );
    }

    #[test]
    fn duplicate_event_id_binds_the_next_emission_without_recreating_custody() {
        let state = crate::engine::build_test_state("duplicate-event-id");
        let instance = state.next_recovery_carrier_instance().unwrap();
        let guard = CarrierInstanceGuard::for_state(&state, Some(instance));
        let first = SignalingEmissionId::next();
        let second = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(first, "same-attempt", [instance]));
        assert!(state.begin_carrier_emission(second, "same-attempt", [instance]));
        assert!(guard.track_attempt(first, "same-attempt"));
        assert!(guard.track_attempt(second, "same-attempt"));
        assert_eq!(guard.claim_attempt("same-attempt"), Some(first));
        assert_eq!(guard.claim_attempt("same-attempt"), Some(second));
        let event = "000000000000000000000000000000000000000000000000000000000000000a";
        assert_eq!(guard.bind_event_id("same-attempt", event), Some(first));
        assert_eq!(guard.bind_event_id("same-attempt", event), Some(second));
        guard.settle_attempt(first);
        assert_eq!(
            guard.emission_for_event("same-attempt", event),
            Some(second)
        );
        assert_eq!(
            state.record_carrier_emission(second, "same-attempt", instance, false),
            crate::engine::state::CarrierEmissionRecord::FinalRefusal
        );
    }

    #[test]
    fn late_emission_callbacks_are_stale_without_recreation() {
        let state = crate::engine::build_test_state("emission-stale");
        let first = state
            .next_recovery_carrier_instance()
            .expect("test carrier instance");
        let second = state
            .next_recovery_carrier_instance()
            .expect("second test carrier instance");
        let emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "late-attempt", [first, second]));
        assert_eq!(
            state.record_carrier_emission(emission, "late-attempt", first, true),
            crate::engine::state::CarrierEmissionRecord::Accepted
        );
        assert!(!state.begin_carrier_emission(emission, "late-attempt", [second]));
        assert_eq!(
            state.record_carrier_emission(emission, "late-attempt", second, false),
            crate::engine::state::CarrierEmissionRecord::Stale
        );
        let successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(successor, "late-attempt", [second]));
        assert_eq!(
            state.record_carrier_emission(successor, "late-attempt", second, false),
            crate::engine::state::CarrierEmissionRecord::FinalRefusal
        );
    }

    #[test]
    fn one_carrier_terminal_and_cancellation_are_bounded_to_exact_copies() {
        let state = crate::engine::build_test_state("one-carrier-fence");
        let instance = state
            .next_recovery_carrier_instance()
            .expect("one carrier instance");
        let guard = CarrierInstanceGuard::for_state(&state, Some(instance));
        let first = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(first, "bounded-attempt", [instance]));
        assert!(guard.track_attempt(first, "bounded-attempt"));
        assert_eq!(guard.claim_attempt("bounded-attempt"), Some(first));
        assert_eq!(
            state.record_carrier_emission(first, "bounded-attempt", instance, true),
            crate::engine::state::CarrierEmissionRecord::Accepted
        );
        guard.settle_attempt(first);
        assert!(!state.begin_carrier_emission(first, "bounded-attempt", [instance]));

        let successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(successor, "bounded-attempt", [instance]));
        assert!(guard.track_attempt(successor, "bounded-attempt"));
        assert_eq!(
            guard.claim_attempt("bounded-attempt"),
            Some(successor),
            "the same-correlation successor owns a distinct one-carrier copy"
        );
        guard.detach();
        assert_eq!(
            state.record_carrier_emission(successor, "bounded-attempt", instance, false),
            crate::engine::state::CarrierEmissionRecord::Stale,
            "detachment terminally fences only its exact successor copy"
        );
        assert!(!guard.track_attempt(SignalingEmissionId::next(), "bounded-attempt"));
    }

    #[test]
    fn lifecycle_settlement_fences_queued_copy_before_state_clear() {
        let state = crate::engine::build_test_state("queued-copy-fence");
        let scope = state
            .local_application_resource_scope()
            .expect("test state local scope");
        let (tx, _rx) = crate::resource::resource_mailbox::<
            crate::engine::signaling_ingress::EphemeralIngress,
        >(scope.clone())
        .expect("test runtime mailbox");
        let runtime = SignalingRuntime::new(tx, scope);
        state.publish_signaling_runtime(&runtime);
        let instance = state
            .next_recovery_carrier_instance()
            .expect("queued carrier instance");
        let attach = SignalingRuntime::attach_for_state(
            &runtime,
            SignalingCarrier::Nostr,
            &state,
            Some(instance),
        )
        .expect("test guard index is funded");
        let guard = attach.guard();
        let emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "queued-attempt", [instance]));
        assert!(guard.track_attempt(emission, "queued-attempt"));
        assert_eq!(guard.claim_attempt("queued-attempt"), Some(emission));
        state.mark_carrier_emission_claimed(emission, "queued-attempt");

        state.settle_attempt("queued-attempt", DeliveryTerminal::Cancelled);

        assert!(!state.begin_carrier_emission(emission, "queued-attempt", [instance]));
        state.acknowledge_terminal_carrier_emission(emission, "queued-attempt", instance);
        let successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(successor, "queued-attempt", [instance]));
        assert_eq!(
            guard.claim_attempt("queued-attempt"),
            None,
            "a delayed pull cannot recreate custody after lifecycle settlement"
        );
    }

    #[tokio::test]
    #[ignore = "native connector fixture; exercises the production fanout and pull path"]
    async fn production_fanout_fence_waits_for_each_physical_copy_ack() {
        let (state, _signaling_in_rx, cmd_rx, provider, _grant) =
            super::super::build_test_state_parts_metered("fanout-copy-fence", None, 2, None);
        state.park_command_receiver_for_test(cmd_rx);
        let baseline = provider.in_use();
        let _fixture = super::super::insert_promoted_peer(&state, "fanout-peer").await;
        let owner = state.peers.owner("fanout-peer").expect("installed owner");
        let scope = state
            .local_application_resource_scope()
            .expect("test state local scope");
        let (out_tx, out_rx) =
            crate::resource::resource_mailbox(scope.clone()).expect("fanout source mailbox");
        let (first_tx, first_rx) =
            crate::resource::resource_mailbox(scope.clone()).expect("first carrier mailbox");
        let (second_tx, second_rx) =
            crate::resource::resource_mailbox(scope.clone()).expect("second carrier mailbox");
        let runtime = SignalingRuntime::new(state.signaling_inbound_tx.clone(), scope.clone());
        state.publish_signaling_runtime(&runtime);
        let first_instance = state
            .next_recovery_carrier_instance()
            .expect("first carrier instance");
        let second_instance = state
            .next_recovery_carrier_instance()
            .expect("second carrier instance");
        let first_attach = SignalingRuntime::attach_for_state(
            &runtime,
            SignalingCarrier::Nostr,
            &state,
            Some(first_instance),
        )
        .expect("first guard index is funded");
        let second_attach = SignalingRuntime::attach_for_state(
            &runtime,
            SignalingCarrier::Mdns,
            &state,
            Some(second_instance),
        )
        .expect("second guard index is funded");
        let first_guard = first_attach.guard();
        let second_guard = second_attach.guard();
        let fanout = spawn_fanout(
            state.clone(),
            out_rx,
            vec![
                (Some(first_instance), first_tx, first_guard.clone()),
                (Some(second_instance), second_tx, second_guard.clone()),
            ],
        );
        let gate = Arc::new(FanoutTestGate {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *FANOUT_AFTER_ADMISSION
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("fanout test hook mutex is not poisoned") = Some(gate.clone());
        let attempt = "fanout-copy-fence".to_string();
        let entered = gate.entered.notified();
        tokio::pin!(entered);
        entered.as_mut().enable();
        let release = gate.release.notified();
        tokio::pin!(release);
        release.as_mut().enable();
        out_tx
            .send(SignalingOutbound::Offer {
                device_id: "fanout-peer".to_string(),
                attempt: attempt.clone(),
                sdp: "sdp".to_string(),
                owner: Some(owner.clone()),
            })
            .expect("fanout source accepts the offer");
        drop(out_tx);
        entered.await;

        // The real fanout has registered both physical copies, but has not yet
        // handed either one to a carrier.  Lifecycle settlement in this window
        // is the interleave that used to erase the second copy's fence.
        state.settle_attempt(&attempt, DeliveryTerminal::Cancelled);
        gate.release.notify_waiters();
        release.await;
        let mut first_source = TranslatedOutbound {
            first: None,
            rx: first_rx,
            scope: scope.clone(),
            translate: Box::new(|_| "first".to_string()),
            refusal_sink: None,
            recovery_state: Some(Arc::downgrade(&state)),
            recovery_instance: Some(first_instance),
            guard: first_guard,
            allow_untracked_emission: false,
            defer_attempt_acceptance: false,
        };
        let mut second_source = TranslatedOutbound {
            first: None,
            rx: second_rx,
            scope,
            translate: Box::new(|_| "second".to_string()),
            refusal_sink: None,
            recovery_state: Some(Arc::downgrade(&state)),
            recovery_instance: Some(second_instance),
            guard: second_guard,
            allow_untracked_emission: false,
            defer_attempt_acceptance: false,
        };
        assert!(
            first_source.recv().await.is_none(),
            "first physical copy is stale"
        );
        let successor = SignalingEmissionId::next();
        assert!(
            state.begin_carrier_emission(successor, &attempt, [first_instance, second_instance]),
            "the first stale acknowledgment preserves the second-copy fence while allowing a fresh successor"
        );
        assert!(
            second_source.recv().await.is_none(),
            "second physical copy is stale"
        );
        state.settle_attempt(&attempt, DeliveryTerminal::Cancelled);
        state.acknowledge_terminal_carrier_emission(successor, &attempt, first_instance);
        state.acknowledge_terminal_carrier_emission(successor, &attempt, second_instance);
        // The translated sources own the two carrier mailbox roots.  Release
        // them before measuring the provider baseline; the exact carrier
        // acknowledgments above have already completed their stale-fence work.
        drop(first_source);
        drop(second_source);

        drop(first_attach);
        drop(second_attach);
        drop(runtime);
        fanout.abort();
        let _ = fanout.await;
        *FANOUT_AFTER_ADMISSION
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("fanout test hook mutex is not poisoned") = None;
        state.shutdown().await;
        drop(owner);
        drop(_fixture);
        assert_eq!(
            provider.in_use(),
            baseline,
            "physical fanout and both exact carrier nodes release to the provider baseline"
        );
    }

    #[tokio::test]
    #[ignore = "native connector fixture; exercises pressured command-mailbox cleanup"]
    async fn closed_command_mailbox_keeps_candidate_and_promoted_sink_cleanup_exact() {
        let (state, _signaling_in_rx, cmd_rx, provider, _grant) =
            super::super::build_test_state_parts_metered("sink-pressure", None, 5, None);
        state.park_command_receiver_for_test(cmd_rx);
        let baseline = provider.in_use();
        let broad_settlements = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let broad_settlements_clone = Arc::clone(&broad_settlements);
        state.set_attempt_settlement(Arc::new(move |_, _| {
            broad_settlements_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            0
        }));
        let fixture = super::super::insert_promoted_peer(&state, "sink-pressure-peer").await;
        let peer = Arc::clone(&fixture.peer);
        let base_owner = state
            .peers
            .owner("sink-pressure-peer")
            .expect("the promoted owner is current");
        let (candidate, _candidate_events) = state
            .transport
            .open_connector_peer(
                crate::transport::Role::Offerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("the fixture admits a speculative connector");
        let candidate = Arc::new(candidate);
        let candidate_attempt = "candidate-pressure".to_string();
        let candidate_lease = candidate
            .reserve_attempt_work(
                crate::engine::connection::PeerConnection::speculative_attempt_claim(
                    &candidate_attempt,
                ),
            )
            .expect("the candidate attempt is funded");
        assert!(peer.install_speculative(
            candidate_attempt.clone(),
            Arc::clone(&candidate),
            candidate_lease,
        ));
        let candidate_owner = base_owner.for_worker(Arc::clone(&candidate));
        let candidate_instance = state
            .next_recovery_carrier_instance()
            .expect("candidate carrier instance");
        let candidate_guard = CarrierInstanceGuard::for_state(&state, Some(candidate_instance));
        let candidate_emission = SignalingEmissionId::next();
        assert!(state
            .begin_carrier_emission_for_owner_result(
                candidate_emission,
                &candidate_attempt,
                candidate_owner,
                [candidate_instance],
            )
            .is_admitted());
        assert!(candidate_guard.track_attempt(candidate_emission, &candidate_attempt));
        assert_eq!(
            candidate_guard.claim_attempt(&candidate_attempt),
            Some(candidate_emission)
        );
        state.mark_carrier_emission_claimed(candidate_emission, &candidate_attempt);
        let candidate_source = AdmissionSource::fresh();
        assert!(candidate_guard.bind_admission_source(candidate_source, &candidate_attempt));

        // Script one real provider pressure before the command send.  This
        // exercises the same synchronous exact-owner fallback as a pressured
        // mailbox; each later command send scripts its own pressure as well.
        provider.script_pressure(crate::resource::ResourceClass::CallbackOrScheduledWork);
        CoreAttemptRefusalSink {
            state: Arc::downgrade(&state),
            instance: Some(candidate_instance),
            guard: candidate_guard,
        }
        .refused(AttemptRefusal {
            source: candidate_source,
            attempt: candidate_attempt.clone(),
            event_id: "candidate-pressure-event".to_string(),
            refusal: myownmesh_signaling::NegotiationRefusal::Provider(
                "mailbox pressure".to_string(),
            ),
        });
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert!(
            !peer.speculative_is_exact(&candidate_attempt, &candidate),
            "candidate-first refusal retires only W1 under command pressure"
        );
        assert!(
            state.peers.get_if_current(&base_owner).is_some(),
            "candidate cleanup leaves the promoted predecessor current"
        );
        assert_eq!(
            broad_settlements.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "carrier-local refusal never broad-settles the shared attempt"
        );

        let (drop_candidate, _drop_events) = state
            .transport
            .open_connector_peer(
                crate::transport::Role::Offerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("the fixture admits a second speculative connector");
        let drop_candidate = Arc::new(drop_candidate);
        let drop_attempt = "drop-peer-pressure".to_string();
        let drop_lease = drop_candidate
            .reserve_attempt_work(
                crate::engine::connection::PeerConnection::speculative_attempt_claim(&drop_attempt),
            )
            .expect("the second candidate attempt is funded");
        assert!(peer.install_speculative(
            drop_attempt.clone(),
            Arc::clone(&drop_candidate),
            drop_lease,
        ));
        let drop_owner = base_owner.for_worker(Arc::clone(&drop_candidate));
        provider.script_pressure(crate::resource::ResourceClass::CallbackOrScheduledWork);
        CoreAttemptRefusalSink {
            state: Arc::downgrade(&state),
            instance: None,
            guard: CarrierInstanceGuard::noop(None),
        }
        .drop_unadmitted(
            None,
            Some(drop_owner),
            drop_attempt.clone(),
            "DropPeerIfCurrent mailbox closed",
        );
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert!(
            !peer.speculative_is_exact(&drop_attempt, &drop_candidate),
            "closed DropPeerIfCurrent cleanup retires only the exact candidate"
        );
        assert!(
            state.peers.get_if_current(&base_owner).is_some(),
            "direct command-send refusal leaves W0 current"
        );
        assert_eq!(
            broad_settlements.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "direct command-send refusal does not broad-settle"
        );

        // Promotion-first uses a separately scripted pressure, but its exact
        // owner terminal removes the promoted installation rather than a
        // successor selected by device id or attempt name.
        peer.adopt_attempt("promoted-pressure");
        let promoted_instance = state
            .next_recovery_carrier_instance()
            .expect("promoted carrier instance");
        let promoted_guard = CarrierInstanceGuard::for_state(&state, Some(promoted_instance));
        let promoted_emission = SignalingEmissionId::next();
        assert!(state
            .begin_carrier_emission_for_owner_result(
                promoted_emission,
                "promoted-pressure",
                base_owner.clone(),
                [promoted_instance],
            )
            .is_admitted());
        assert!(promoted_guard.track_attempt(promoted_emission, "promoted-pressure"));
        assert_eq!(
            promoted_guard.claim_attempt("promoted-pressure"),
            Some(promoted_emission)
        );
        state.mark_carrier_emission_claimed(promoted_emission, "promoted-pressure");
        let promoted_source = AdmissionSource::fresh();
        assert!(promoted_guard.bind_admission_source(promoted_source, "promoted-pressure"));
        provider.script_pressure(crate::resource::ResourceClass::CallbackOrScheduledWork);
        CoreAttemptOutcomeSink {
            state: Arc::downgrade(&state),
            instance: Some(promoted_instance),
            guard: promoted_guard,
        }
        .outcome(AttemptOutcome {
            source: promoted_source,
            attempt: "promoted-pressure".to_string(),
            event_id: "promoted-pressure-event".to_string(),
            kind: myownmesh_signaling::AttemptOutcomeKind::TypedRefused(
                "mailbox pressure".to_string(),
            ),
        });
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert!(
            state.peers.get_if_current(&base_owner).is_none(),
            "promotion-first refusal retires the exact promoted owner"
        );
        assert_eq!(
            broad_settlements.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "promotion cleanup remains exact and does not broad-settle"
        );
        state.shutdown().await;
        drop(candidate);
        drop(drop_candidate);
        drop(_candidate_events);
        drop(_drop_events);
        drop(base_owner);
        drop(fixture);
        assert_eq!(
            provider.in_use(),
            baseline,
            "candidate/promoted command-pressure cleanup returns provider custody to baseline"
        );
    }

    #[test]
    fn carrier_refusal_is_pending_until_the_exact_last_copy() {
        let state = crate::engine::build_test_state("emission-aggregate");
        let first = state
            .next_recovery_carrier_instance()
            .expect("first carrier instance");
        let second = state
            .next_recovery_carrier_instance()
            .expect("second carrier instance");
        let emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "aggregate-attempt", [first, second]));
        assert!(state.begin_carrier_emission(emission, "aggregate-attempt", [first, second]));
        assert_eq!(
            state.record_carrier_emission(emission, "aggregate-attempt", first, false),
            crate::engine::state::CarrierEmissionRecord::Pending
        );
        assert_eq!(
            state.record_carrier_emission(emission, "aggregate-attempt", second, false),
            crate::engine::state::CarrierEmissionRecord::FinalRefusal
        );
        assert_eq!(
            state.record_carrier_emission(emission, "aggregate-attempt", second, false),
            crate::engine::state::CarrierEmissionRecord::Stale
        );
    }

    #[test]
    fn carrier_refusal_does_not_finish_same_attempt_emissions() {
        let state = crate::engine::build_test_state("emission-source-settlement");
        let first = state
            .next_recovery_carrier_instance()
            .expect("first carrier instance");
        let second = state
            .next_recovery_carrier_instance()
            .expect("second carrier instance");
        let guard = CarrierInstanceGuard::for_state(&state, Some(second));
        let broad_settlements = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let broad_settlements_clone = Arc::clone(&broad_settlements);
        state.set_attempt_settlement(Arc::new(move |_, _| {
            broad_settlements_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            0
        }));

        let first_emission = SignalingEmissionId::next();
        let second_emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(first_emission, "shared-attempt", [first, second]));
        assert!(state.begin_carrier_emission(second_emission, "shared-attempt", [second]));
        assert!(guard.track_attempt(first_emission, "shared-attempt"));
        assert!(guard.track_attempt(second_emission, "shared-attempt"));
        assert_eq!(guard.claim_attempt("shared-attempt"), Some(first_emission));
        assert_eq!(guard.claim_attempt("shared-attempt"), Some(second_emission));
        let first_source = AdmissionSource::fresh();
        let second_source = AdmissionSource::fresh();
        assert!(guard.bind_admission_source(first_source, "shared-attempt"));
        assert!(guard.bind_admission_source(second_source, "shared-attempt"));
        state.mark_carrier_emission_claimed(first_emission, "shared-attempt");
        state.mark_carrier_emission_claimed(second_emission, "shared-attempt");
        assert_eq!(
            state.record_carrier_emission(first_emission, "shared-attempt", first, false),
            CarrierEmissionRecord::Pending
        );
        assert_eq!(
            state.record_carrier_emission(second_emission, "shared-attempt", second, false),
            CarrierEmissionRecord::FinalRefusal
        );
        assert!(state.settle_final_refusal_carrier(second_emission, "shared-attempt"));
        guard.settle_attempt(second_emission);
        assert_eq!(
            guard.emission_for_source(first_source),
            Some(first_emission)
        );
        assert_eq!(guard.emission_for_source(second_source), None);
        assert_eq!(
            broad_settlements.load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        // The first source remains provider-live after the second source's
        // carrier refusal and can reach its own terminal independently.
        assert_eq!(
            state.record_carrier_emission(first_emission, "shared-attempt", second, false),
            CarrierEmissionRecord::FinalRefusal
        );
        assert!(state.settle_final_refusal_carrier(first_emission, "shared-attempt"));
        guard.settle_attempt(first_emission);
        assert_eq!(guard.emission_for_source(first_source), None);
        assert_eq!(
            broad_settlements.load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        // Native lifecycle settlement still owns the broad attempt terminal.
        state.settle_attempt(
            "shared-attempt",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        assert_eq!(
            broad_settlements.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn detached_carrier_guard_settles_its_exact_emission_once() {
        let state = crate::engine::build_test_state("emission-detach");
        let instance = state
            .next_recovery_carrier_instance()
            .expect("test carrier instance");
        let guard = CarrierInstanceGuard::for_state(&state, Some(instance));
        let emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "detach-attempt", [instance]));
        assert!(guard.track_attempt(emission, "detach-attempt"));
        guard.detach();
        guard.detach();
        assert!(!guard.track_attempt(SignalingEmissionId::next(), "stale-attempt"));
        assert_eq!(
            state.record_carrier_emission(emission, "detach-attempt", instance, false),
            crate::engine::state::CarrierEmissionRecord::Stale
        );

        // Detach released the one-copy FinalRefusal node, so a fresh
        // same-carrier emission can reacquire provider custody.
        let successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(successor, "detach-attempt", [instance]));
        assert_eq!(
            state.record_carrier_emission(successor, "detach-attempt", instance, false),
            crate::engine::state::CarrierEmissionRecord::FinalRefusal
        );
        assert!(state.settle_final_refusal_carrier(successor, "detach-attempt"));
    }

    #[test]
    fn detached_last_copy_releases_refusal_but_preserves_accepted_tombstone() {
        let state = crate::engine::build_test_state("emission-detach-last-copy");
        let first = state
            .next_recovery_carrier_instance()
            .expect("first carrier instance");
        let second = state
            .next_recovery_carrier_instance()
            .expect("second carrier instance");

        let refusal = SignalingEmissionId::next();
        let first_guard = CarrierInstanceGuard::for_state(&state, Some(first));
        let second_guard = CarrierInstanceGuard::for_state(&state, Some(second));
        assert!(state.begin_carrier_emission(refusal, "detach-last-copy", [first, second]));
        assert!(first_guard.track_attempt(refusal, "detach-last-copy"));
        assert!(second_guard.track_attempt(refusal, "detach-last-copy"));
        first_guard.detach();
        second_guard.detach();
        assert_eq!(
            state.record_carrier_emission(refusal, "detach-last-copy", second, false),
            crate::engine::state::CarrierEmissionRecord::Stale,
            "the last detach releases the exact FinalRefusal node"
        );

        let accepted = SignalingEmissionId::next();
        let accepted_guard = CarrierInstanceGuard::for_state(&state, Some(first));
        assert!(state.begin_carrier_emission(accepted, "detach-accepted", [first]));
        assert!(accepted_guard.track_attempt(accepted, "detach-accepted"));
        assert_eq!(
            state.record_carrier_emission(accepted, "detach-accepted", first, true),
            crate::engine::state::CarrierEmissionRecord::Accepted
        );
        accepted_guard.detach();
        assert!(!state.begin_carrier_emission(accepted, "detach-accepted", [first]));
        assert_eq!(
            state.record_carrier_emission(accepted, "detach-accepted", first, false),
            crate::engine::state::CarrierEmissionRecord::Stale,
            "Accepted remains a delayed-callback tombstone after detach"
        );
    }

    #[tokio::test]
    async fn accepted_terminal_releases_entry_custody_but_keeps_stale_fence() {
        let (state, _signaling_in_rx, cmd_rx, provider, _grant) =
            super::super::build_test_state_parts_metered(
                "accepted-tombstone-custody",
                None,
                5,
                None,
            );
        state.park_command_receiver_for_test(cmd_rx);
        let baseline = provider.in_use();
        let first = state
            .next_recovery_carrier_instance()
            .expect("first carrier instance");
        let second = state
            .next_recovery_carrier_instance()
            .expect("second carrier instance");

        let one_copy = SignalingEmissionId::next();
        let one_guard = CarrierInstanceGuard::for_state(&state, Some(first));
        assert!(state.begin_carrier_emission(one_copy, "accepted-one", [first]));
        assert!(one_guard.track_attempt(one_copy, "accepted-one"));
        assert_eq!(one_guard.claim_attempt("accepted-one"), Some(one_copy));
        state.mark_carrier_emission_claimed(one_copy, "accepted-one");
        assert_eq!(
            state.record_carrier_emission(one_copy, "accepted-one", first, true),
            CarrierEmissionRecord::Accepted
        );
        assert!(!state.begin_carrier_emission(one_copy, "accepted-one", [first]));
        state.settle_attempt(
            "accepted-one",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        one_guard.settle_attempt_and_acknowledge(&state, one_copy, "accepted-one", first);
        let one_successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(one_successor, "accepted-one", [first]));
        state.settle_attempt(
            "accepted-one",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        state.acknowledge_terminal_carrier_emission(one_successor, "accepted-one", first);

        let two_copy = SignalingEmissionId::next();
        let first_guard = CarrierInstanceGuard::for_state(&state, Some(first));
        let second_guard = CarrierInstanceGuard::for_state(&state, Some(second));
        assert!(state.begin_carrier_emission(two_copy, "accepted-two", [first, second]));
        assert!(first_guard.track_attempt(two_copy, "accepted-two"));
        assert!(second_guard.track_attempt(two_copy, "accepted-two"));
        assert_eq!(first_guard.claim_attempt("accepted-two"), Some(two_copy));
        assert_eq!(second_guard.claim_attempt("accepted-two"), Some(two_copy));
        state.mark_carrier_emission_claimed(two_copy, "accepted-two");
        assert_eq!(
            state.record_carrier_emission(two_copy, "accepted-two", first, false),
            CarrierEmissionRecord::Pending
        );
        assert_eq!(
            state.record_carrier_emission(two_copy, "accepted-two", first, true),
            CarrierEmissionRecord::Stale
        );
        assert_eq!(
            state.record_carrier_emission(two_copy, "accepted-two", second, true),
            CarrierEmissionRecord::Accepted
        );
        first_guard.settle_attempt_and_acknowledge(&state, two_copy, "accepted-two", first);
        second_guard.settle_attempt_and_acknowledge(&state, two_copy, "accepted-two", second);
        assert!(!state.begin_carrier_emission(two_copy, "accepted-two", [first, second]));
        state.settle_attempt(
            "accepted-two",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        let two_successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(two_successor, "accepted-two", [first, second]));
        state.settle_attempt(
            "accepted-two",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        state.acknowledge_terminal_carrier_emission(two_successor, "accepted-two", first);
        state.acknowledge_terminal_carrier_emission(two_successor, "accepted-two", second);
        assert_eq!(first_guard.claim_attempt("accepted-two"), None);
        assert_eq!(second_guard.claim_attempt("accepted-two"), None);
        drop(one_guard);
        drop(first_guard);
        drop(second_guard);
        state.shutdown().await;
        assert_eq!(
            provider.in_use(),
            baseline,
            "Accepted one-copy and Pending-to-Accepted two-copy custody return to baseline"
        );
    }

    #[tokio::test]
    async fn accepted_copy_late_sibling_failure_acknowledges_exact_carrier() {
        let (state, _signaling_in_rx, cmd_rx, provider, _grant) =
            super::super::build_test_state_parts_metered("accepted-late-sibling", None, 5, None);
        state.park_command_receiver_for_test(cmd_rx);
        let baseline = provider.in_use();
        let first = state
            .next_recovery_carrier_instance()
            .expect("first carrier instance");
        let second = state
            .next_recovery_carrier_instance()
            .expect("second carrier instance");
        let first_guard = CarrierInstanceGuard::for_state(&state, Some(first));
        let second_guard = CarrierInstanceGuard::for_state(&state, Some(second));
        let emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "accepted-late-sibling", [first, second]));
        assert!(first_guard.track_attempt(emission, "accepted-late-sibling"));
        assert!(second_guard.track_attempt(emission, "accepted-late-sibling"));
        assert_eq!(
            first_guard.claim_attempt("accepted-late-sibling"),
            Some(emission)
        );
        assert_eq!(
            second_guard.claim_attempt("accepted-late-sibling"),
            Some(emission)
        );
        state.mark_carrier_emission_claimed(emission, "accepted-late-sibling");
        assert_eq!(
            state.record_carrier_emission(emission, "accepted-late-sibling", first, true,),
            CarrierEmissionRecord::Accepted
        );
        assert_eq!(
            state.record_carrier_emission(emission, "accepted-late-sibling", second, false,),
            CarrierEmissionRecord::Stale
        );
        first_guard.settle_attempt_and_acknowledge(
            &state,
            emission,
            "accepted-late-sibling",
            first,
        );
        second_guard.settle_attempt_and_acknowledge(
            &state,
            emission,
            "accepted-late-sibling",
            second,
        );
        state.settle_attempt(
            "accepted-late-sibling",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        drop(first_guard);
        drop(second_guard);
        state.shutdown().await;
        assert_eq!(
            provider.in_use(),
            baseline,
            "late sibling failure releases exact Accepted carrier custody"
        );
    }

    #[tokio::test]
    async fn claimed_e0_queued_e1_uses_oldest_fenced_unclaimed_copy() {
        let (state, _signaling_in_rx, cmd_rx, provider, _grant) =
            super::super::build_test_state_parts_metered("claimed-queued-lane", None, 5, None);
        state.park_command_receiver_for_test(cmd_rx);
        let baseline = provider.in_use();
        let instance = state
            .next_recovery_carrier_instance()
            .expect("carrier instance");
        let guard = CarrierInstanceGuard::for_state(&state, Some(instance));
        let e0 = SignalingEmissionId::next();
        let e1 = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(e0, "same-lane", [instance]));
        assert!(state.begin_carrier_emission(e1, "same-lane", [instance]));
        assert!(guard.track_attempt(e0, "same-lane"));
        assert!(guard.track_attempt(e1, "same-lane"));
        assert_eq!(guard.claim_attempt("same-lane"), Some(e0));
        state.mark_carrier_emission_claimed(e0, "same-lane");

        // Lifecycle settlement fences both copies.  The claimed E0 remains
        // tied to its already-running physical pull; only queued E1 is an
        // eligible delayed lookup on this guard/lane.
        guard.fence_attempt("same-lane");
        state.settle_attempt(
            "same-lane",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        assert_eq!(
            guard.fenced_emission_for("same-lane"),
            Some(e1),
            "a delayed pull selects E1, never the already-claimed E0"
        );
        guard.settle_attempt(e1);
        state.acknowledge_terminal_carrier_emission(e1, "same-lane", instance);
        assert_eq!(guard.fenced_emission_for("same-lane"), None);
        guard.settle_attempt(e0);
        state.acknowledge_terminal_carrier_emission(e0, "same-lane", instance);

        // The exact old copies are gone, so a fresh same-correlation emission
        // can admit independently without being mistaken for a delayed E0/E1.
        let successor = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(successor, "same-lane", [instance]));
        state.settle_attempt(
            "same-lane",
            myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
        );
        state.acknowledge_terminal_carrier_emission(successor, "same-lane", instance);
        drop(guard);
        state.shutdown().await;
        assert_eq!(
            provider.in_use(),
            baseline,
            "claimed and queued lane custody returns to the metered baseline"
        );
    }

    #[test]
    fn claimed_copy_cannot_recreate_across_settlement_interleave() {
        let state = crate::engine::build_test_state("claim-settle-interleave");
        let instance = state
            .next_recovery_carrier_instance()
            .expect("carrier instance");
        let guard = CarrierInstanceGuard::for_state(&state, Some(instance));
        let emission = SignalingEmissionId::next();
        assert!(state.begin_carrier_emission(emission, "interleave", [instance]));
        assert!(guard.track_attempt(emission, "interleave"));

        let observed = guard.claim_attempt_with("interleave", |claimed| {
            assert_eq!(claimed, emission);
            state.settle_attempt(
                "interleave",
                myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
            );
            assert!(!state.begin_carrier_emission(claimed, "interleave", [instance]));
            claimed
        });
        assert_eq!(observed, Some((emission, emission)));
    }

    #[test]
    fn outcome_routing_matrix_requires_matching_terminal_record() {
        use crate::engine::state::CarrierEmissionRecord;
        use myownmesh_signaling::AttemptOutcomeKind;

        let kinds = [
            AttemptOutcomeKind::Accepted { session: None },
            AttemptOutcomeKind::TypedRefused("pressure".to_string()),
            AttemptOutcomeKind::CarrierUnavailable,
            AttemptOutcomeKind::Cancelled,
            AttemptOutcomeKind::Replaced,
        ];
        let records = [
            CarrierEmissionRecord::Stale,
            CarrierEmissionRecord::Pending,
            CarrierEmissionRecord::Accepted,
            CarrierEmissionRecord::FinalRefusal,
        ];
        for kind in &kinds {
            for record in records {
                let expected = match kind {
                    AttemptOutcomeKind::Accepted { .. } => {
                        record == CarrierEmissionRecord::Accepted
                    }
                    AttemptOutcomeKind::TypedRefused(_)
                    | AttemptOutcomeKind::CarrierUnavailable => {
                        record == CarrierEmissionRecord::FinalRefusal
                    }
                    AttemptOutcomeKind::Cancelled | AttemptOutcomeKind::Replaced => false,
                };
                assert_eq!(
                    outcome_record_is_routable(kind, record),
                    expected,
                    "unexpected routing for {kind:?} and {record:?}"
                );
            }
        }
    }
}
