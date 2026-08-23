//! Attempt-owned Nostr delivery custody.
//!
//! A negotiation event is retained by its source owner until the exact live
//! attempt finishes.  The attempt record itself has provider custody before
//! it enters the map, and every relay connection gets its own provider-backed
//! entry; a reconnect is a new session and can receive the still-live event.
//! This module deliberately has no count cap, elapsed TTL, retry timer, or
//! route authority.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

use super::event::NostrEvent;
use crate::{
    AttemptOutcome, AttemptOutcomeKind, AttemptOutcomeSink, AttemptRefusal, ErasedOwner,
    NegotiationRefusal, OwnedSignal,
};

/// An opaque identity for one concrete relay WebSocket session.
///
/// Pointer identity is intentional: a reconnect can never reuse an old
/// numeric generation and therefore cannot settle an old entry by ABA.
#[derive(Clone)]
pub struct RelaySessionId(Arc<()>);

impl RelaySessionId {
    pub(crate) fn fresh() -> Self {
        Self(Arc::new(()))
    }
}

impl std::fmt::Debug for RelaySessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RelaySessionId")
            .field(&(Arc::as_ptr(&self.0) as usize))
            .finish()
    }
}

impl PartialEq for RelaySessionId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RelaySessionId {}

impl std::hash::Hash for RelaySessionId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&(Arc::as_ptr(&self.0) as usize), state);
    }
}

/// Exact provider input computed before the encoded EVENT frame is allocated.
///
/// The fields deliberately distinguish the event frame from the attempt,
/// key/map, and session structures.  An attached provider can therefore
/// charge the record that owns a refusal independently from each relay copy;
/// folding all of these into one per-relay number would double-charge an
/// attempt when it has multiple relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRetention {
    pub encoded_event_bytes: usize,
    pub structural_entry_bytes: usize,
    /// Exact bytes for the relay-map node that points at the delivery entry.
    pub relay_map_growth_bytes: usize,
    /// Exact bytes for the attempt record allocation.
    pub attempt_record_bytes: usize,
    /// Exact bytes for the event-id key allocation.
    pub attempt_key_bytes: usize,
    /// Exact bytes for the attempt-map growth allocation.
    pub attempt_map_growth_bytes: usize,
}

/// Exact provider inputs for one relay-session registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRetention {
    pub session_record_bytes: usize,
    pub session_set_node_bytes: usize,
    pub session_set_growth_bytes: usize,
}

/// Why a provider refused a per-relay delivery entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryRefusal {
    Provider(String),
}

/// One-shot terminal outcome for a per-relay entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTerminal {
    Accepted,
    TypedRefused(String),
    AttemptCompleted,
    AttemptReplaced,
    Cancelled,
    Shutdown,
}

/// Provider-owned lease for one exact attempt or (event, relay-session)
/// delivery.
pub trait DeliveryLease: Send {
    fn finish(self: Box<Self>, terminal: DeliveryTerminal);
}

/// Narrow seam for the core resource provider.
///
/// The event is borrowed so the provider can compute its exact reservation
/// before the encoded frame is allocated.  The returned lease remains with
/// that relay-session entry until one terminal outcome consumes it.
pub trait DeliveryProvider: Send + Sync {
    /// Fund the session record before it is inserted into the live session set.
    fn reserve_session_record(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact session-set node before insertion.
    fn reserve_session_set_node(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact session-set growth before insertion.
    fn reserve_session_set_growth(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact attempt record before it is inserted into the live map.
    fn reserve_attempt_record(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact event-id key allocation.
    fn reserve_attempt_key(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact attempt-map growth allocation.
    fn reserve_attempt_map_growth(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    fn reserve(
        &self,
        attempt: &str,
        session: RelaySessionId,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the relay-map growth separately from the relay delivery entry.
    fn reserve_relay_map_growth(
        &self,
        attempt: &str,
        session: RelaySessionId,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;
}

/// Standalone compatibility provider. Production core attachment should pass
/// its provider through [`super::driver::start_with_delivery_provider`].
pub struct UnmeteredDeliveryProvider;

struct UnmeteredLease;

struct UnmeteredAttemptOutcomeSink;

impl AttemptOutcomeSink for UnmeteredAttemptOutcomeSink {
    fn outcome(&self, _outcome: AttemptOutcome) {}
}

impl DeliveryLease for UnmeteredLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {}
}

impl DeliveryProvider for UnmeteredDeliveryProvider {
    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_session_set_growth(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_map_growth(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_relay_map_growth(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }
}

struct RelayEntry {
    lease: Box<dyn DeliveryLease>,
    map_lease: Box<dyn DeliveryLease>,
    in_flight: bool,
}

impl DeliveryRetention {
    pub fn for_event(event: &NostrEvent) -> Self {
        let mut counter = CountingWriter(0);
        counter.write_all(b"[\"EVENT\",").expect("counting writer");
        serde_json::to_writer(&mut counter, event).expect("event serializes");
        counter.write_all(b"]").expect("counting writer");
        Self {
            encoded_event_bytes: counter.0,
            structural_entry_bytes: std::mem::size_of::<RelayEntry>(),
            relay_map_growth_bytes: std::mem::size_of::<(RelaySessionId, RelayEntry)>(),
            attempt_record_bytes: std::mem::size_of::<AttemptEntry>(),
            attempt_key_bytes: event.id.len(),
            attempt_map_growth_bytes: std::mem::size_of::<(String, AttemptEntry)>(),
        }
    }
}

impl SessionRetention {
    fn exact() -> Self {
        Self {
            session_record_bytes: std::mem::size_of::<SessionEntry>(),
            session_set_node_bytes: std::mem::size_of::<RelaySessionId>(),
            session_set_growth_bytes: std::mem::size_of::<(RelaySessionId, SessionEntry)>(),
        }
    }
}

struct CountingWriter(usize);

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Successful admissions and typed per-relay refusals are both retained in
/// the attempt record; one refused relay never rolls back healthy relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefusal {
    DuplicateLiveEvent,
    /// The exact attempt owner was refused before its record was admitted.
    Provider(DeliveryRefusal),
}

impl AdmissionRefusal {
    pub(crate) fn into_negotiation(self) -> NegotiationRefusal {
        match self {
            Self::DuplicateLiveEvent => NegotiationRefusal::DuplicateLiveEvent,
            Self::Provider(DeliveryRefusal::Provider(reason)) => {
                NegotiationRefusal::Provider(reason)
            }
        }
    }
}

#[derive(Debug)]
pub struct AdmissionReport {
    pub event_id: String,
    pub accepted_sessions: usize,
    pub refused: Vec<(RelaySessionId, DeliveryRefusal)>,
    pub attempt_refusal: Option<AdmissionRefusal>,
}

struct AttemptEntry {
    attempt: String,
    owned: OwnedSignal<NostrEvent, ErasedOwner>,
    record_lease: Box<dyn DeliveryLease>,
    key_lease: Box<dyn DeliveryLease>,
    map_lease: Box<dyn DeliveryLease>,
    relays: HashMap<RelaySessionId, RelayEntry>,
    provider_refused: bool,
}

struct SessionEntry {
    record_lease: Box<dyn DeliveryLease>,
    node_lease: Box<dyn DeliveryLease>,
    growth_lease: Box<dyn DeliveryLease>,
}

struct DeliveryState {
    sessions: HashMap<RelaySessionId, SessionEntry>,
    attempts: HashMap<String, AttemptEntry>,
}

/// The live attempt owner and its per-relay delivery entries.
pub struct DeliveryStore {
    provider: Arc<dyn DeliveryProvider>,
    outcome_sink: Arc<dyn AttemptOutcomeSink>,
    state: Mutex<DeliveryState>,
    notify: Notify,
}

impl DeliveryStore {
    pub fn new(provider: Arc<dyn DeliveryProvider>) -> Arc<Self> {
        Self::new_with_outcome_sink(provider, Arc::new(UnmeteredAttemptOutcomeSink))
    }

    pub fn new_with_outcome_sink(
        provider: Arc<dyn DeliveryProvider>,
        outcome_sink: Arc<dyn AttemptOutcomeSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            outcome_sink,
            state: Mutex::new(DeliveryState {
                sessions: HashMap::new(),
                attempts: HashMap::new(),
            }),
            notify: Notify::new(),
        })
    }

    pub fn notification(&self) -> &Notify {
        &self.notify
    }

    /// Register a fresh relay connection and fund one entry for each live
    /// attempt before any frame is encoded for that connection.
    pub fn open_session(&self) -> (RelaySessionId, Vec<(String, DeliveryRefusal)>) {
        let (session, session_refusal, refused) = self.open_session_with_refusals();
        let mut legacy = Vec::new();
        if let Some(error) = session_refusal {
            legacy.push(("<session>".to_string(), error));
        }
        legacy.extend(refused.into_iter().map(|refusal| {
            (
                refusal.event_id,
                DeliveryRefusal::Provider(match refusal.refusal {
                    NegotiationRefusal::Provider(reason) => reason,
                    NegotiationRefusal::DuplicateLiveEvent => "duplicate live event".to_string(),
                }),
            )
        }));
        (session, legacy)
    }

    /// Register a session and return only refusals that left the exact
    /// attempt with no funded relay.  Partial relay refusal is observable in
    /// the per-relay report but is not an attempt terminal.
    pub fn open_session_with_refusals(
        &self,
    ) -> (RelaySessionId, Option<DeliveryRefusal>, Vec<AttemptRefusal>) {
        let mut state = self.state.lock();
        let session = RelaySessionId::fresh();
        let retention = SessionRetention::exact();
        let record_lease = match self
            .provider
            .reserve_session_record(session.clone(), retention)
        {
            Ok(lease) => lease,
            Err(error) => return (session, Some(error), Vec::new()),
        };
        let node_lease = match self
            .provider
            .reserve_session_set_node(session.clone(), retention)
        {
            Ok(lease) => lease,
            Err(error) => {
                record_lease.finish(DeliveryTerminal::Cancelled);
                return (session, Some(error), Vec::new());
            }
        };
        let growth_lease = match self
            .provider
            .reserve_session_set_growth(session.clone(), retention)
        {
            Ok(lease) => lease,
            Err(error) => {
                node_lease.finish(DeliveryTerminal::Cancelled);
                record_lease.finish(DeliveryTerminal::Cancelled);
                return (session, Some(error), Vec::new());
            }
        };
        state.sessions.insert(
            session.clone(),
            SessionEntry {
                record_lease,
                node_lease,
                growth_lease,
            },
        );
        let mut refused = Vec::new();
        for entry in state.attempts.values_mut() {
            let retention = DeliveryRetention::for_event(entry.owned.value());
            match self.provider.reserve(
                &entry.attempt,
                session.clone(),
                entry.owned.value(),
                retention,
            ) {
                Ok(lease) => {
                    match self.provider.reserve_relay_map_growth(
                        &entry.attempt,
                        session.clone(),
                        entry.owned.value(),
                        retention,
                    ) {
                        Ok(map_lease) => {
                            entry.provider_refused = false;
                            entry.relays.insert(
                                session.clone(),
                                RelayEntry {
                                    lease,
                                    map_lease,
                                    in_flight: false,
                                },
                            );
                        }
                        Err(error) => {
                            lease.finish(DeliveryTerminal::Cancelled);
                            if entry.relays.is_empty() {
                                entry.provider_refused = true;
                                refused.push(AttemptRefusal {
                                    attempt: entry.attempt.clone(),
                                    event_id: entry.owned.value().id.clone(),
                                    refusal: NegotiationRefusal::Provider(match &error {
                                        DeliveryRefusal::Provider(reason) => reason.clone(),
                                    }),
                                });
                            }
                        }
                    }
                }
                Err(error) => {
                    // A refused reconnect does not invalidate an already
                    // funded relay.  Mark the attempt retryable only when
                    // this leaves it with no live relay entry; otherwise the
                    // healthy relay's authoritative ACK may retire it.
                    if entry.relays.is_empty() {
                        entry.provider_refused = true;
                        refused.push(AttemptRefusal {
                            attempt: entry.attempt.clone(),
                            event_id: entry.owned.value().id.clone(),
                            refusal: NegotiationRefusal::Provider(match &error {
                                DeliveryRefusal::Provider(reason) => reason.clone(),
                            }),
                        });
                    }
                }
            }
        }
        (session, None, refused)
    }

    /// Admit a translated negotiation. Existing sessions are funded before
    /// this value can be encoded or queued for any relay.
    pub fn admit(
        &self,
        attempt: String,
        owned: OwnedSignal<NostrEvent, ErasedOwner>,
    ) -> AdmissionReport {
        let event_id = owned.value().id.clone();
        let mut state = self.state.lock();
        if state.attempts.contains_key(&event_id) {
            return AdmissionReport {
                event_id,
                accepted_sessions: 0,
                refused: Vec::new(),
                attempt_refusal: Some(AdmissionRefusal::DuplicateLiveEvent),
            };
        }
        let retention = DeliveryRetention::for_event(owned.value());
        let record_lease =
            match self
                .provider
                .reserve_attempt_record(&attempt, owned.value(), retention)
            {
                Ok(lease) => lease,
                Err(error) => {
                    return AdmissionReport {
                        event_id,
                        accepted_sessions: 0,
                        refused: Vec::new(),
                        attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                    };
                }
            };
        let key_lease = match self
            .provider
            .reserve_attempt_key(&attempt, owned.value(), retention)
        {
            Ok(lease) => lease,
            Err(error) => {
                record_lease.finish(DeliveryTerminal::Cancelled);
                return AdmissionReport {
                    event_id,
                    accepted_sessions: 0,
                    refused: Vec::new(),
                    attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                };
            }
        };
        let map_lease =
            match self
                .provider
                .reserve_attempt_map_growth(&attempt, owned.value(), retention)
            {
                Ok(lease) => lease,
                Err(error) => {
                    key_lease.finish(DeliveryTerminal::Cancelled);
                    record_lease.finish(DeliveryTerminal::Cancelled);
                    return AdmissionReport {
                        event_id,
                        accepted_sessions: 0,
                        refused: Vec::new(),
                        attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                    };
                }
            };
        let mut relays = HashMap::new();
        let mut refused = Vec::new();
        for session in state.sessions.keys().cloned() {
            match self
                .provider
                .reserve(&attempt, session.clone(), owned.value(), retention)
            {
                Ok(lease) => match self.provider.reserve_relay_map_growth(
                    &attempt,
                    session.clone(),
                    owned.value(),
                    retention,
                ) {
                    Ok(map_lease) => {
                        relays.insert(
                            session,
                            RelayEntry {
                                lease,
                                map_lease,
                                in_flight: false,
                            },
                        );
                    }
                    Err(error) => {
                        lease.finish(DeliveryTerminal::Cancelled);
                        refused.push((session, error));
                    }
                },
                Err(error) => refused.push((session, error)),
            }
        }
        let accepted_sessions = relays.len();
        let provider_refused = !refused.is_empty() && relays.is_empty();
        let attempt_refusal = if relays.is_empty() {
            refused
                .first()
                .map(|(_, error)| AdmissionRefusal::Provider(error.clone()))
        } else {
            None
        };
        state.attempts.insert(
            event_id.clone(),
            AttemptEntry {
                attempt,
                owned,
                record_lease,
                key_lease,
                map_lease,
                relays,
                // A partial refusal still has a funded live relay and may
                // settle authoritatively there.  Only an all-refused active
                // set needs to remain marked for a later reconnect retry.
                provider_refused,
            },
        );
        drop(state);
        self.notify.notify_waiters();
        AdmissionReport {
            event_id,
            accepted_sessions,
            refused,
            attempt_refusal,
        }
    }

    /// Mark all pending entries for a session in flight and return event ids.
    pub fn pending(&self, session: &RelaySessionId) -> Vec<String> {
        let mut state = self.state.lock();
        let mut ids = Vec::new();
        for (event_id, entry) in &mut state.attempts {
            if let Some(relay) = entry.relays.get_mut(session) {
                if !relay.in_flight {
                    relay.in_flight = true;
                    ids.push(event_id.clone());
                }
            }
        }
        ids
    }

    /// Borrow an event only after its relay entry has been provider-funded.
    pub fn with_event<R>(&self, event_id: &str, f: impl FnOnce(&NostrEvent) -> R) -> Option<R> {
        let state = self.state.lock();
        state
            .attempts
            .get(event_id)
            .map(|entry| f(entry.owned.value()))
    }

    /// Settle exactly one event/session pair. A stale session cannot settle a
    /// fresh reconnect because its entry was removed when the old session died.
    pub fn settle(
        &self,
        session: &RelaySessionId,
        event_id: &str,
        terminal: DeliveryTerminal,
    ) -> bool {
        let (leases, outcome) = {
            let mut state = self.state.lock();
            let (lease, remove_attempt, attempt) = {
                let Some(entry) = state.attempts.get_mut(event_id) else {
                    return false;
                };
                let Some(relay) = entry.relays.remove(session) else {
                    return false;
                };
                let remove_attempt = matches!(
                    &terminal,
                    DeliveryTerminal::Accepted | DeliveryTerminal::TypedRefused(_)
                ) && entry.relays.is_empty()
                    && !entry.provider_refused;
                (relay, remove_attempt, entry.attempt.clone())
            };
            let outcome = match &terminal {
                DeliveryTerminal::Accepted => Some(AttemptOutcome {
                    attempt,
                    event_id: event_id.to_string(),
                    kind: AttemptOutcomeKind::Accepted {
                        session: Some(session.clone()),
                    },
                }),
                DeliveryTerminal::TypedRefused(reason) => Some(AttemptOutcome {
                    attempt,
                    event_id: event_id.to_string(),
                    kind: AttemptOutcomeKind::TypedRefused(reason.clone()),
                }),
                _ => None,
            };
            if remove_attempt {
                // Remove the source owner atomically with the final relay
                // entry.  A reconnect may otherwise acquire this mutex after
                // the lease is detached but before the old implementation
                // removed the attempt, fund a fresh entry, and then have
                // that entry erased by the stale removal.
                let entry = state
                    .attempts
                    .remove(event_id)
                    .expect("attempt exists while settling its relay");
                (
                    vec![
                        lease.lease,
                        lease.map_lease,
                        entry.record_lease,
                        entry.key_lease,
                        entry.map_lease,
                    ],
                    outcome,
                )
            } else {
                (vec![lease.lease, lease.map_lease], outcome)
            }
        };
        for lease in leases {
            lease.finish(terminal.clone());
        }
        if let Some(outcome) = outcome {
            self.outcome_sink.outcome(outcome);
        }
        true
    }

    /// Release every entry for an exact attempt lifecycle terminal.
    pub fn finish_attempt(&self, attempt: &str, terminal: DeliveryTerminal) -> usize {
        let mut leases = Vec::new();
        let mut outcomes = Vec::new();
        let mut count = 0;
        {
            let mut state = self.state.lock();
            let ids: Vec<String> = state
                .attempts
                .iter()
                .filter(|(_, entry)| entry.attempt == attempt)
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(entry) = state.attempts.remove(&id) {
                    count += entry.relays.len();
                    let kind = match &terminal {
                        DeliveryTerminal::Accepted | DeliveryTerminal::AttemptCompleted => {
                            AttemptOutcomeKind::Accepted { session: None }
                        }
                        DeliveryTerminal::TypedRefused(reason) => {
                            AttemptOutcomeKind::TypedRefused(reason.clone())
                        }
                        DeliveryTerminal::AttemptReplaced => AttemptOutcomeKind::Replaced,
                        DeliveryTerminal::Cancelled | DeliveryTerminal::Shutdown => {
                            AttemptOutcomeKind::Cancelled
                        }
                    };
                    outcomes.push(AttemptOutcome {
                        attempt: entry.attempt.clone(),
                        event_id: entry.owned.value().id.clone(),
                        kind,
                    });
                    leases.push(entry.record_lease);
                    leases.push(entry.key_lease);
                    leases.push(entry.map_lease);
                    leases.extend(
                        entry
                            .relays
                            .into_values()
                            .flat_map(|relay| [relay.lease, relay.map_lease]),
                    );
                }
            }
        }
        for lease in leases {
            lease.finish(terminal.clone());
        }
        for outcome in outcomes {
            self.outcome_sink.outcome(outcome);
        }
        count
    }

    /// Retire one relay session while preserving live attempts for a fresh
    /// reconnect.
    pub fn close_session(&self, session: RelaySessionId, terminal: DeliveryTerminal) -> usize {
        let mut leases = Vec::new();
        let mut outcomes = Vec::new();
        let mut count = 0;
        {
            let mut state = self.state.lock();
            if let Some(session_entry) = state.sessions.remove(&session) {
                leases.push(session_entry.record_lease);
                leases.push(session_entry.node_lease);
                leases.push(session_entry.growth_lease);
            }
            for entry in state.attempts.values_mut() {
                if let Some(relay) = entry.relays.remove(&session) {
                    count += 1;
                    outcomes.push(AttemptOutcome {
                        attempt: entry.attempt.clone(),
                        event_id: entry.owned.value().id.clone(),
                        kind: AttemptOutcomeKind::CarrierUnavailable,
                    });
                    leases.push(relay.lease);
                    leases.push(relay.map_lease);
                }
            }
        }
        for lease in leases {
            lease.finish(terminal.clone());
        }
        for outcome in outcomes {
            self.outcome_sink.outcome(outcome);
        }
        count
    }

    /// Release all per-relay custody and every live source owner.
    pub fn shutdown(&self) -> usize {
        let mut leases = Vec::new();
        let mut outcomes = Vec::new();
        let mut count = 0;
        {
            let mut state = self.state.lock();
            for session_entry in state.sessions.drain().map(|(_, entry)| entry) {
                leases.push(session_entry.record_lease);
                leases.push(session_entry.node_lease);
                leases.push(session_entry.growth_lease);
            }
            for entry in state.attempts.drain().map(|(_, entry)| entry) {
                count += entry.relays.len();
                outcomes.push(AttemptOutcome {
                    attempt: entry.attempt.clone(),
                    event_id: entry.owned.value().id.clone(),
                    kind: AttemptOutcomeKind::Cancelled,
                });
                leases.push(entry.record_lease);
                leases.push(entry.key_lease);
                leases.push(entry.map_lease);
                leases.extend(
                    entry
                        .relays
                        .into_values()
                        .flat_map(|relay| [relay.lease, relay.map_lease]),
                );
            }
        }
        for lease in leases {
            lease.finish(DeliveryTerminal::Shutdown);
        }
        for outcome in outcomes {
            self.outcome_sink.outcome(outcome);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::event::{make_event, NostrIdentity, SIGNALING_EPHEMERAL_KIND};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{OnceLock, Weak};

    struct CountingProvider {
        live: Arc<AtomicUsize>,
    }

    struct CountingLease {
        live: Arc<AtomicUsize>,
    }

    impl DeliveryLease for CountingLease {
        fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    macro_rules! unmetered_reservations {
        () => {
            fn reserve_session_record(
                &self,
                _session: RelaySessionId,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_session_set_node(
                &self,
                _session: RelaySessionId,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_session_set_growth(
                &self,
                _session: RelaySessionId,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_attempt_record(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_attempt_key(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_attempt_map_growth(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_relay_map_growth(
                &self,
                _attempt: &str,
                _session: RelaySessionId,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }
        };
    }

    impl DeliveryProvider for CountingProvider {
        unmetered_reservations!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: self.live.clone(),
            }))
        }
    }

    struct OpenOnFinishProvider {
        store: Arc<OnceLock<Weak<DeliveryStore>>>,
        fresh: Arc<Mutex<Option<RelaySessionId>>>,
    }

    struct OpenOnFinishLease {
        store: Arc<OnceLock<Weak<DeliveryStore>>>,
        fresh: Arc<Mutex<Option<RelaySessionId>>>,
    }

    impl DeliveryLease for OpenOnFinishLease {
        fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
            let store = self
                .store
                .get()
                .expect("store weak reference is initialized")
                .upgrade()
                .expect("delivery store remains live during settlement");
            let (session, _) = store.open_session();
            *self.fresh.lock() = Some(session);
        }
    }

    impl DeliveryProvider for OpenOnFinishProvider {
        unmetered_reservations!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(Box::new(OpenOnFinishLease {
                store: Arc::clone(&self.store),
                fresh: Arc::clone(&self.fresh),
            }))
        }
    }

    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct RecordingOutcomeSink {
        outcomes: Arc<Mutex<Vec<AttemptOutcome>>>,
    }

    impl AttemptOutcomeSink for RecordingOutcomeSink {
        fn outcome(&self, outcome: AttemptOutcome) {
            self.outcomes.lock().push(outcome);
        }
    }

    fn recording_store(
        provider: Arc<dyn DeliveryProvider>,
    ) -> (Arc<DeliveryStore>, Arc<Mutex<Vec<AttemptOutcome>>>) {
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let store = DeliveryStore::new_with_outcome_sink(
            provider,
            Arc::new(RecordingOutcomeSink {
                outcomes: Arc::clone(&outcomes),
            }),
        );
        (store, outcomes)
    }

    struct RejectOnceProvider {
        live: Arc<AtomicUsize>,
        refused: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for RejectOnceProvider {
        unmetered_reservations!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            if self.refused.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(DeliveryRefusal::Provider("test refusal".into()));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: self.live.clone(),
            }))
        }
    }

    fn event() -> NostrEvent {
        make_event(
            &NostrIdentity::generate(),
            SIGNALING_EPHEMERAL_KIND,
            vec![],
            "attempt".into(),
            1,
        )
    }

    #[test]
    fn outcome_sink_records_exact_accepted_relay_custody() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (session, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("accepted-attempt".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert!(store.settle(&session, &event_id, DeliveryTerminal::Accepted));

        let records = outcomes.lock();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attempt, "accepted-attempt");
        assert_eq!(records[0].event_id, event_id);
        assert_eq!(
            records[0].kind,
            AttemptOutcomeKind::Accepted {
                session: Some(session)
            }
        );
    }

    #[test]
    fn outcome_sink_records_carrier_unavailable_for_every_closed_relay() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (first, _) = store.open_session();
        let (second, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("carrier-attempt".into(), owned);
        assert_eq!(report.accepted_sessions, 2);
        store.close_session(first, DeliveryTerminal::Cancelled);
        store.close_session(second, DeliveryTerminal::Cancelled);

        let records = outcomes.lock();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record.attempt == "carrier-attempt"
                && record.event_id == event_id
                && record.kind == AttemptOutcomeKind::CarrierUnavailable
        }));
    }

    #[test]
    fn outcome_sink_records_typed_refusal_for_exact_attempt() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (session, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("refused-attempt".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert!(store.settle(
            &session,
            &event_id,
            DeliveryTerminal::TypedRefused("negotiation rejected".into()),
        ));

        let records = outcomes.lock();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attempt, "refused-attempt");
        assert_eq!(records[0].event_id, event_id);
        assert_eq!(
            records[0].kind,
            AttemptOutcomeKind::TypedRefused("negotiation rejected".into())
        );
    }

    #[test]
    fn outcome_sink_records_replaced_and_cancelled_attempt_terminals() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (session, _) = store.open_session();
        let replaced = event();
        let replaced_id = replaced.id.clone();
        store.admit(
            "replaced-attempt".into(),
            OwnedSignal::new(replaced, Box::new(()) as ErasedOwner),
        );
        assert!(store.finish_attempt("replaced-attempt", DeliveryTerminal::AttemptReplaced) > 0);
        let cancelled = event();
        let cancelled_id = cancelled.id.clone();
        store.admit(
            "cancelled-attempt".into(),
            OwnedSignal::new(cancelled, Box::new(()) as ErasedOwner),
        );
        assert!(store.finish_attempt("cancelled-attempt", DeliveryTerminal::Cancelled) > 0);
        store.close_session(session, DeliveryTerminal::Cancelled);

        let records = outcomes.lock();
        assert!(records.iter().any(|record| {
            record.attempt == "replaced-attempt"
                && record.event_id == replaced_id
                && record.kind == AttemptOutcomeKind::Replaced
        }));
        assert!(records.iter().any(|record| {
            record.attempt == "cancelled-attempt"
                && record.event_id == cancelled_id
                && record.kind == AttemptOutcomeKind::Cancelled
        }));
    }

    #[test]
    fn stale_session_terminal_cannot_settle_fresh_attempt_outcome() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (stale, _) = store.open_session();
        let old = event();
        store.admit(
            "old-attempt".into(),
            OwnedSignal::new(old, Box::new(()) as ErasedOwner),
        );
        store.close_session(stale.clone(), DeliveryTerminal::Cancelled);

        let (fresh, _) = store.open_session();
        let current = event();
        let current_id = current.id.clone();
        store.admit(
            "fresh-attempt".into(),
            OwnedSignal::new(current, Box::new(()) as ErasedOwner),
        );
        assert!(!store.settle(&stale, &current_id, DeliveryTerminal::Accepted));
        assert!(store.settle(&fresh, &current_id, DeliveryTerminal::Accepted));

        let records = outcomes.lock();
        assert!(records.iter().any(|record| {
            record.attempt == "old-attempt" && record.kind == AttemptOutcomeKind::CarrierUnavailable
        }));
        assert!(records.iter().any(|record| {
            record.attempt == "fresh-attempt"
                && record.event_id == current_id
                && matches!(record.kind, AttemptOutcomeKind::Accepted { .. })
        }));
    }

    #[test]
    fn relay_entries_settle_independently_and_reconnect_is_fresh() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(CountingProvider { live: live.clone() }));
        let (a, _) = store.open_session();
        let (b, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let id = owned.value().id.clone();
        let report = store.admit("attempt-1".into(), owned);
        assert_eq!(report.accepted_sessions, 2);
        assert!(report.refused.is_empty());
        assert_eq!(live.load(Ordering::SeqCst), 2);
        assert!(store.settle(&a, &id, DeliveryTerminal::Accepted));
        assert_eq!(live.load(Ordering::SeqCst), 1);
        assert!(store.settle(&b, &id, DeliveryTerminal::TypedRefused("no".into())));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.finish_attempt("attempt-1", DeliveryTerminal::AttemptCompleted),
            0
        );
        store.close_session(a, DeliveryTerminal::Cancelled);
        store.close_session(b, DeliveryTerminal::Cancelled);
        let (c, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let id = owned.value().id.clone();
        let report = store.admit("attempt-2".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert_eq!(store.pending(&c), vec![id.clone()]);
        store.close_session(c.clone(), DeliveryTerminal::Cancelled);
        let (d, _) = store.open_session();
        assert_eq!(store.pending(&d), vec![id.clone()]);
        assert!(!store.settle(&c, &id, DeliveryTerminal::Accepted));
        store.close_session(d, DeliveryTerminal::Cancelled);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn final_settlement_removes_attempt_before_reentrant_reconnect() {
        let store_ref = Arc::new(OnceLock::new());
        let fresh_session = Arc::new(Mutex::new(None));
        let store = DeliveryStore::new(Arc::new(OpenOnFinishProvider {
            store: Arc::clone(&store_ref),
            fresh: Arc::clone(&fresh_session),
        }));
        assert!(store_ref.set(Arc::downgrade(&store)).is_ok());

        let (old_session, _) = store.open_session();
        let owner_dropped = Arc::new(AtomicBool::new(false));
        let event = event();
        let event_id = event.id.clone();
        let report = store.admit(
            "attempt-reentrant-reconnect".into(),
            OwnedSignal::new(
                event,
                Box::new(DropMarker(Arc::clone(&owner_dropped))) as ErasedOwner,
            ),
        );
        assert_eq!(report.accepted_sessions, 1);

        assert!(store.settle(&old_session, &event_id, DeliveryTerminal::Accepted));
        assert!(owner_dropped.load(Ordering::SeqCst));
        let fresh = fresh_session
            .lock()
            .clone()
            .expect("lease finish opens a fresh session");
        assert!(store.pending(&fresh).is_empty());
        assert!(!store.settle(&fresh, &event_id, DeliveryTerminal::Accepted));
    }

    #[test]
    fn duplicate_live_event_refusal_preserves_original_custody() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(CountingProvider { live: live.clone() }));
        let (session, _) = store.open_session();
        let event = event();
        let event_id = event.id.clone();
        let original_dropped = Arc::new(AtomicBool::new(false));
        let first = store.admit(
            "attempt-original".into(),
            OwnedSignal::new(
                event.clone(),
                Box::new(DropMarker(Arc::clone(&original_dropped))) as ErasedOwner,
            ),
        );
        assert_eq!(first.accepted_sessions, 1);
        assert_eq!(first.attempt_refusal, None);
        assert_eq!(live.load(Ordering::SeqCst), 1);

        let duplicate_dropped = Arc::new(AtomicBool::new(false));
        let duplicate = store.admit(
            "attempt-duplicate".into(),
            OwnedSignal::new(
                event,
                Box::new(DropMarker(Arc::clone(&duplicate_dropped))) as ErasedOwner,
            ),
        );
        assert_eq!(duplicate.accepted_sessions, 0);
        assert!(duplicate.refused.is_empty());
        assert_eq!(
            duplicate.attempt_refusal,
            Some(AdmissionRefusal::DuplicateLiveEvent)
        );
        assert!(duplicate_dropped.load(Ordering::SeqCst));
        assert!(!original_dropped.load(Ordering::SeqCst));
        assert_eq!(store.pending(&session), vec![event_id.clone()]);
        assert_eq!(live.load(Ordering::SeqCst), 1);

        assert_eq!(
            store.finish_attempt("attempt-duplicate", DeliveryTerminal::Cancelled),
            0
        );
        assert_eq!(
            store.finish_attempt("attempt-original", DeliveryTerminal::AttemptCompleted),
            1
        );
        assert!(original_dropped.load(Ordering::SeqCst));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(!store.settle(&session, &event_id, DeliveryTerminal::Accepted));
    }

    #[test]
    fn one_provider_refusal_keeps_healthy_relay_entry() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(RejectOnceProvider {
            live: live.clone(),
            refused: Arc::new(AtomicUsize::new(0)),
        }));
        let (a, _) = store.open_session();
        let (b, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let report = store.admit("partial".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(live.load(Ordering::SeqCst), 1);
        let id = report.event_id;
        assert!(store.pending(&a).is_empty() || store.pending(&b).is_empty());
        assert_eq!(
            store.finish_attempt("partial", DeliveryTerminal::AttemptReplaced),
            1
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(!store.settle(&a, &id, DeliveryTerminal::Accepted));
    }
}
