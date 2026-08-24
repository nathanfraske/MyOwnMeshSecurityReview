//! Attempt-owned Nostr delivery custody.
//!
//! A negotiation event is retained by its source owner until the exact live
//! attempt finishes.  The attempt record itself has provider custody before
//! it enters the map, and every relay connection gets its own provider-backed
//! entry; a reconnect is a new session and can receive the still-live event.
//! This module deliberately has no count cap, elapsed TTL, retry timer, or
//! route authority.

use std::borrow::Borrow;
use std::io::Write;
use std::mem;
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
    /// Exact allocation size of `Box<DeliveryMapNode<RelaySessionId,
    /// RelayEntry>>`, reserved before the relay node is inserted.
    pub relay_map_growth_bytes: usize,
    /// Exact bytes for the attempt record allocation.
    pub attempt_record_bytes: usize,
    /// Exact bytes for the event-id key allocation.
    pub attempt_key_bytes: usize,
    /// Exact allocation size of `Box<DeliveryMapNode<String, AttemptEntry>>`,
    /// reserved before the attempt node is inserted.
    pub attempt_map_growth_bytes: usize,
}

/// Exact provider inputs for one relay-session registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRetention {
    pub session_record_bytes: usize,
    pub session_set_node_bytes: usize,
    /// Exact allocation size of `Box<DeliveryMapNode<RelaySessionId,
    /// SessionEntry>>`, reserved before the session node is inserted.
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

    /// Fund the exact one-allocation session-map entry.
    fn reserve_session_entry(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_session_set_growth(session, retention)
    }

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

    /// Fund the exact attempt-map entry owned by the provider.
    ///
    /// New providers should override this seam. The default preserves the
    /// older byte-hint adapter while callers migrate; the store never treats
    /// the HashMap tuple layout as its own custody claim.
    fn reserve_attempt_entry(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_attempt_map_growth(attempt, event, retention)
    }

    /// Fund the exact relay-map entry owned by the provider.
    fn reserve_relay_entry(
        &self,
        attempt: &str,
        session: RelaySessionId,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_relay_map_growth(attempt, session, event, retention)
    }

    /// Fund the owned attempt-correlation string separately from the event-id
    /// key. The compatibility default reuses the old key seam with an exact
    /// correlation-length hint, so existing providers remain source-stable.
    fn reserve_attempt_correlation(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        let mut correlation = retention;
        correlation.attempt_key_bytes = attempt.len();
        self.reserve_attempt_key(attempt, event, correlation)
    }
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
        Self::for_attempt("", event)
    }

    /// Compute the frame and owned-record shape before any frame or map node
    /// is allocated. The map-node sizes are the exact boxed allocation types
    /// used by this module, and their provider leases are acquired before
    /// insertion.
    pub fn for_attempt(_attempt: &str, event: &NostrEvent) -> Self {
        let mut counter = CountingWriter(0);
        counter.write_all(b"[\"EVENT\",").expect("counting writer");
        serde_json::to_writer(&mut counter, event).expect("event serializes");
        counter.write_all(b"]").expect("counting writer");
        Self {
            encoded_event_bytes: counter.0,
            structural_entry_bytes: std::mem::size_of::<RelayEntry>(),
            relay_map_growth_bytes: std::mem::size_of::<DeliveryMapNode<RelaySessionId, RelayEntry>>(
            ),
            attempt_record_bytes: std::mem::size_of::<AttemptEntry>(),
            attempt_key_bytes: event.id.len(),
            attempt_map_growth_bytes: std::mem::size_of::<DeliveryMapNode<String, AttemptEntry>>(),
        }
    }
}

impl SessionRetention {
    fn exact() -> Self {
        Self {
            session_record_bytes: std::mem::size_of::<SessionEntry>(),
            session_set_node_bytes: std::mem::size_of::<RelaySessionId>(),
            session_set_growth_bytes: std::mem::size_of::<
                DeliveryMapNode<RelaySessionId, SessionEntry>,
            >(),
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
    correlation_lease: Option<Box<dyn DeliveryLease>>,
    map_lease: Box<dyn DeliveryLease>,
    relays: DeliveryMap<RelaySessionId, RelayEntry>,
    carrier: CarrierAggregate,
    provider_refused: bool,
}

/// Order-independent carrier observations for one live event.
///
/// The first accepted relay wins the event-level outcome, while duplicate ACKs
/// still release their own custody. A refusal from one relay is only a
/// candidate terminal until every live relay has either refused or
/// disappeared. The selected refusal is the lexicographically smallest
/// observed reason, so relay completion order cannot change the result.
/// `unavailable_reported` is scoped to the current carrier epoch and is reset
/// when a reconnect admits a relay.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CarrierAggregate {
    accepted_session: Option<RelaySessionId>,
    typed_refusal: Option<String>,
    terminal_emitted: bool,
    unavailable_reported: bool,
}

impl CarrierAggregate {
    /// Record the first accepted relay. Later duplicate ACKs remain valid
    /// custody releases but cannot emit a second event-level outcome.
    pub fn observe_accepted(&mut self, session: RelaySessionId) -> bool {
        if self.terminal_emitted {
            return false;
        }
        self.accepted_session = Some(session);
        self.terminal_emitted = true;
        true
    }

    /// Record a typed relay refusal without making it terminal while another
    /// carrier remains viable. Reasons are normalized by deterministic
    /// ordering so relay arrival order cannot choose the result.
    pub fn observe_typed_refusal(&mut self, reason: &str) {
        if self.terminal_emitted {
            return;
        }
        let replace = match self.typed_refusal.as_deref() {
            None => true,
            Some(current) => reason < current,
        };
        if replace {
            self.typed_refusal = Some(reason.to_string());
        }
    }

    /// Start a fresh carrier epoch after a relay reconnects.
    pub fn observe_reconnect(&mut self) {
        if !self.terminal_emitted {
            self.unavailable_reported = false;
            self.typed_refusal = None;
        }
    }

    /// Claim the one all-carrier refusal notification for this epoch.
    ///
    /// Individual relay sessions may fail concurrently after the last funded
    /// relay has gone away.  Only the first failure owns the provider/core
    /// refusal; a successful reconnect starts a new epoch through
    /// [`Self::observe_reconnect`].
    pub fn observe_all_carrier_refusal(&mut self) -> bool {
        if self.terminal_emitted || self.unavailable_reported {
            return false;
        }
        self.unavailable_reported = true;
        true
    }

    /// Return the one aggregate outcome for this unavailable carrier epoch.
    pub fn unavailable_outcome(&mut self) -> Option<AttemptOutcomeKind> {
        if self.terminal_emitted || self.unavailable_reported {
            return None;
        }
        self.unavailable_reported = true;
        Some(match &self.typed_refusal {
            Some(reason) => AttemptOutcomeKind::TypedRefused(reason.clone()),
            None => AttemptOutcomeKind::CarrierUnavailable,
        })
    }
}

struct SessionEntry {
    record_lease: Box<dyn DeliveryLease>,
    node_lease: Box<dyn DeliveryLease>,
    growth_lease: Box<dyn DeliveryLease>,
}

/// A provider-funded, one-allocation-per-entry map.
///
/// HashMap bucket arrays are process allocations whose geometric growth is
/// impossible to price from a tuple `size_of`. This intrusive map allocates
/// exactly one boxed node per insertion; the caller acquires that node's
/// provider lease before calling `insert`. It has no spare capacity, bucket
/// control bytes, or reallocation path.
struct DeliveryMap<K, V> {
    head: Option<Box<DeliveryMapNode<K, V>>>,
    len: usize,
}

struct DeliveryMapNode<K, V> {
    key: K,
    value: V,
    next: Option<Box<DeliveryMapNode<K, V>>>,
}

impl<K, V> Default for DeliveryMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Drop for DeliveryMap<K, V> {
    fn drop(&mut self) {
        let mut next = self.head.take();
        while let Some(mut node) = next {
            // Break the ownership chain before this node drops. Its own
            // fields then drop normally, while the loop owns the remainder.
            next = node.next.take();
        }
    }
}

impl<K, V> DeliveryMap<K, V> {
    fn new() -> Self {
        Self { head: None, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn iter(&self) -> DeliveryMapIter<'_, K, V> {
        DeliveryMapIter {
            next: self.head.as_deref(),
        }
    }

    fn iter_mut(&mut self) -> DeliveryMapIterMut<'_, K, V> {
        DeliveryMapIterMut {
            next: self.head.as_deref_mut(),
        }
    }

    fn into_values(self) -> impl Iterator<Item = V> {
        self.into_iter().map(|(_, value)| value)
    }
}

impl<K, V> DeliveryMap<K, V> {
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.iter()
            .find_map(|(candidate, value)| (candidate.borrow() == key).then_some(value))
    }

    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.iter_mut()
            .find_map(|(candidate, value)| (candidate.borrow() == key).then_some(value))
    }

    fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.get(key).is_some()
    }

    fn insert(&mut self, key: K, value: V) -> Option<V>
    where
        K: PartialEq,
    {
        let mut link = &mut self.head;
        loop {
            match link {
                Some(node) if node.key == key => {
                    return Some(mem::replace(&mut node.value, value));
                }
                Some(node) => link = &mut node.next,
                None => {
                    *link = Some(Box::new(DeliveryMapNode {
                        key,
                        value,
                        next: None,
                    }));
                    self.len += 1;
                    return None;
                }
            }
        }
    }

    fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let mut link = &mut self.head;
        loop {
            let matches = match link.as_ref() {
                Some(node) => node.key.borrow() == key,
                None => return None,
            };
            if matches {
                let mut removed = link.take().expect("the node was borrowed above");
                *link = removed.next.take();
                self.len -= 1;
                return Some(removed.value);
            }
            link = &mut link
                .as_mut()
                .expect("a nonmatching node exists while advancing")
                .next;
        }
    }
}

impl<K, V> IntoIterator for DeliveryMap<K, V> {
    type Item = (K, V);
    type IntoIter = DeliveryMapIntoIter<K, V>;

    fn into_iter(mut self) -> Self::IntoIter {
        DeliveryMapIntoIter {
            next: self.head.take(),
        }
    }
}

struct DeliveryMapIter<'a, K, V> {
    next: Option<&'a DeliveryMapNode<K, V>>,
}

impl<'a, K, V> Iterator for DeliveryMapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next?;
        self.next = node.next.as_deref();
        Some((&node.key, &node.value))
    }
}

struct DeliveryMapIterMut<'a, K, V> {
    next: Option<&'a mut DeliveryMapNode<K, V>>,
}

impl<'a, K, V> Iterator for DeliveryMapIterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next.take()?;
        self.next = node.next.as_deref_mut();
        Some((&node.key, &mut node.value))
    }
}

struct DeliveryMapIntoIter<K, V> {
    next: Option<Box<DeliveryMapNode<K, V>>>,
}

impl<K, V> Drop for DeliveryMapIntoIter<K, V> {
    fn drop(&mut self) {
        let mut next = self.next.take();
        while let Some(mut node) = next {
            next = node.next.take();
        }
    }
}

impl<K, V> Iterator for DeliveryMapIntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let mut node = self.next.take()?;
        self.next = node.next.take();
        Some((node.key, node.value))
    }
}

struct DeliveryState {
    sessions: DeliveryMap<RelaySessionId, SessionEntry>,
    attempts: DeliveryMap<String, AttemptEntry>,
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
                sessions: DeliveryMap::new(),
                attempts: DeliveryMap::new(),
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
            .reserve_session_entry(session.clone(), retention)
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
        for (_, entry) in state.attempts.iter_mut() {
            let retention = DeliveryRetention::for_attempt(&entry.attempt, entry.owned.value());
            match self.provider.reserve(
                &entry.attempt,
                session.clone(),
                entry.owned.value(),
                retention,
            ) {
                Ok(lease) => {
                    match self.provider.reserve_relay_entry(
                        &entry.attempt,
                        session.clone(),
                        entry.owned.value(),
                        retention,
                    ) {
                        Ok(map_lease) => {
                            entry.provider_refused = false;
                            entry.carrier.observe_reconnect();
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
                                if entry.carrier.observe_all_carrier_refusal() {
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
                }
                Err(error) => {
                    // A refused reconnect does not invalidate an already
                    // funded relay.  Mark the attempt retryable only when
                    // this leaves it with no live relay entry; otherwise the
                    // healthy relay's authoritative ACK may retire it.
                    if entry.relays.is_empty() {
                        entry.provider_refused = true;
                        if entry.carrier.observe_all_carrier_refusal() {
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
        let retention = DeliveryRetention::for_attempt(&attempt, owned.value());
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
        let correlation_lease = if attempt.is_empty() {
            None
        } else {
            match self
                .provider
                .reserve_attempt_correlation(&attempt, owned.value(), retention)
            {
                Ok(lease) => Some(lease),
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
            }
        };
        let map_lease =
            match self
                .provider
                .reserve_attempt_entry(&attempt, owned.value(), retention)
            {
                Ok(lease) => lease,
                Err(error) => {
                    if let Some(lease) = correlation_lease {
                        lease.finish(DeliveryTerminal::Cancelled);
                    }
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
        let mut relays = DeliveryMap::new();
        let mut refused = Vec::new();
        for (session, _) in state.sessions.iter() {
            let session = session.clone();
            match self
                .provider
                .reserve(&attempt, session.clone(), owned.value(), retention)
            {
                Ok(lease) => match self.provider.reserve_relay_entry(
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
                correlation_lease,
                map_lease,
                relays,
                carrier: CarrierAggregate::default(),
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
        for (event_id, entry) in state.attempts.iter_mut() {
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
            let (lease, remove_attempt, attempt, has_remaining, typed_refusal, accepted_outcome) = {
                let Some(entry) = state.attempts.get_mut(event_id) else {
                    return false;
                };
                let Some(relay) = entry.relays.remove(session) else {
                    return false;
                };
                if let DeliveryTerminal::TypedRefused(reason) = &terminal {
                    entry.carrier.observe_typed_refusal(reason);
                }
                let accepted_outcome = matches!(&terminal, DeliveryTerminal::Accepted)
                    && entry.carrier.observe_accepted(session.clone());
                let has_remaining = !entry.relays.is_empty();
                let remove_attempt = matches!(
                    &terminal,
                    DeliveryTerminal::Accepted | DeliveryTerminal::TypedRefused(_)
                ) && !has_remaining
                    && !entry.provider_refused;
                let typed_refusal = entry.carrier.typed_refusal.clone();
                (
                    relay,
                    remove_attempt,
                    entry.attempt.clone(),
                    has_remaining,
                    typed_refusal,
                    accepted_outcome,
                )
            };
            let outcome = match &terminal {
                DeliveryTerminal::Accepted if accepted_outcome => Some(AttemptOutcome {
                    attempt,
                    event_id: event_id.to_string(),
                    kind: AttemptOutcomeKind::Accepted {
                        session: Some(session.clone()),
                    },
                }),
                DeliveryTerminal::Accepted => None,
                DeliveryTerminal::TypedRefused(_) if !has_remaining => {
                    typed_refusal.map(|reason| AttemptOutcome {
                        attempt,
                        event_id: event_id.to_string(),
                        kind: AttemptOutcomeKind::TypedRefused(reason),
                    })
                }
                DeliveryTerminal::TypedRefused(_) => None,
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
                let mut leases = vec![
                    lease.lease,
                    lease.map_lease,
                    entry.record_lease,
                    entry.key_lease,
                ];
                if let Some(correlation_lease) = entry.correlation_lease {
                    leases.push(correlation_lease);
                }
                leases.push(entry.map_lease);
                (leases, outcome)
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
                    if !entry.carrier.terminal_emitted {
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
                    }
                    leases.push(entry.record_lease);
                    leases.push(entry.key_lease);
                    leases.extend(entry.correlation_lease);
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
            for (_, entry) in state.attempts.iter_mut() {
                if let Some(relay) = entry.relays.remove(&session) {
                    count += 1;
                    if entry.relays.is_empty() {
                        if let Some(kind) = entry.carrier.unavailable_outcome() {
                            outcomes.push(AttemptOutcome {
                                attempt: entry.attempt.clone(),
                                event_id: entry.owned.value().id.clone(),
                                kind,
                            });
                        }
                    }
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
            for (_, session_entry) in mem::take(&mut state.sessions).into_iter() {
                leases.push(session_entry.record_lease);
                leases.push(session_entry.node_lease);
                leases.push(session_entry.growth_lease);
            }
            for (_, entry) in mem::take(&mut state.attempts).into_iter() {
                count += entry.relays.len();
                if !entry.carrier.terminal_emitted {
                    outcomes.push(AttemptOutcome {
                        attempt: entry.attempt.clone(),
                        event_id: entry.owned.value().id.clone(),
                        kind: AttemptOutcomeKind::Cancelled,
                    });
                }
                leases.push(entry.record_lease);
                leases.push(entry.key_lease);
                leases.extend(entry.correlation_lease);
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

    struct ExactCustodyProvider {
        live: Arc<AtomicUsize>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl ExactCustodyProvider {
        fn lease(&self, label: &str) -> Box<dyn DeliveryLease> {
            self.calls.lock().push(label.to_string());
            self.live.fetch_add(1, Ordering::SeqCst);
            Box::new(CountingLease {
                live: Arc::clone(&self.live),
            })
        }
    }

    impl DeliveryProvider for ExactCustodyProvider {
        unmetered_reservations!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(self.lease("relay"))
        }

        fn reserve_attempt_correlation(
            &self,
            attempt: &str,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            assert!(!attempt.is_empty());
            assert!(retention.relay_map_growth_bytes > 0);
            assert!(retention.attempt_map_growth_bytes > 0);
            Ok(self.lease("attempt-correlation"))
        }

        fn reserve_attempt_entry(
            &self,
            _attempt: &str,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            assert!(retention.attempt_map_growth_bytes > 0);
            Ok(self.lease("attempt-entry"))
        }

        fn reserve_relay_entry(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            assert!(retention.relay_map_growth_bytes > 0);
            Ok(self.lease("relay-entry"))
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

    struct ToggleProvider {
        allow: Arc<AtomicBool>,
        live: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for ToggleProvider {
        unmetered_reservations!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            if !self.allow.load(Ordering::SeqCst) {
                return Err(DeliveryRefusal::Provider("carrier unavailable".into()));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: Arc::clone(&self.live),
            }))
        }
    }

    struct RefuseSpecificProvider {
        target: Arc<Mutex<Option<RelaySessionId>>>,
        live: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for RefuseSpecificProvider {
        unmetered_reservations!();

        fn reserve(
            &self,
            _attempt: &str,
            session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            if self.target.lock().as_ref() == Some(&session) {
                return Err(DeliveryRefusal::Provider("selected relay refusal".into()));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: Arc::clone(&self.live),
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
    fn large_delivery_map_chain_unlinks_iteratively() {
        const CHAIN: usize = 100_000;
        fn chain(size: usize) -> DeliveryMap<usize, usize> {
            let mut map = DeliveryMap::new();
            for key in 0..size {
                let next = map.head.take();
                map.head = Some(Box::new(DeliveryMapNode {
                    key,
                    value: key,
                    next,
                }));
                map.len += 1;
            }
            map
        }

        let mut map = chain(CHAIN);
        assert_eq!(map.len(), CHAIN);
        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.remove(&(CHAIN / 2)), Some(CHAIN / 2));
        assert_eq!(map.remove(&(CHAIN - 1)), Some(CHAIN - 1));
        assert_eq!(map.len(), CHAIN - 3);
        drop(map);

        let mut remainder = chain(CHAIN).into_iter();
        assert_eq!(remainder.next(), Some((CHAIN - 1, CHAIN - 1)));
        assert_eq!(remainder.next(), Some((CHAIN - 2, CHAIN - 2)));
        drop(remainder);
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
    fn outcome_sink_aggregates_carrier_unavailable_after_all_relays_close() {
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
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attempt, "carrier-attempt");
        assert_eq!(records[0].event_id, event_id);
        assert_eq!(records[0].kind, AttemptOutcomeKind::CarrierUnavailable);
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

    #[test]
    fn admission_refusal_permutation_preserves_the_other_relay() {
        fn exercise(refuse_first: bool) {
            let target = Arc::new(Mutex::new(None));
            let live = Arc::new(AtomicUsize::new(0));
            let store = DeliveryStore::new(Arc::new(RefuseSpecificProvider {
                target: Arc::clone(&target),
                live: Arc::clone(&live),
            }));
            let (first, _) = store.open_session();
            let (second, _) = store.open_session();
            let refused = if refuse_first {
                first.clone()
            } else {
                second.clone()
            };
            let healthy = if refuse_first { second } else { first };
            *target.lock() = Some(refused);

            let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
            let id = owned.value().id.clone();
            let report = store.admit("admission-permutation".into(), owned);
            assert_eq!(report.accepted_sessions, 1);
            assert_eq!(report.refused.len(), 1);
            assert!(report.attempt_refusal.is_none());
            assert_eq!(store.pending(&healthy), vec![id.clone()]);
            assert_eq!(live.load(Ordering::SeqCst), 1);
            assert_eq!(
                store.finish_attempt("admission-permutation", DeliveryTerminal::Accepted),
                1
            );
            assert_eq!(live.load(Ordering::SeqCst), 0);
        }

        exercise(true);
        exercise(false);
    }

    #[test]
    fn relay_refusal_outcome_is_order_independent_while_peer_remains_viable() {
        fn exercise(reverse: bool) {
            let live = Arc::new(AtomicUsize::new(0));
            let (store, outcomes) = recording_store(Arc::new(CountingProvider {
                live: Arc::clone(&live),
            }));
            let (first_session, _) = store.open_session();
            let (second_session, _) = store.open_session();
            let (first, second) = if reverse {
                (second_session, first_session)
            } else {
                (first_session, second_session)
            };
            let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
            let id = owned.value().id.clone();
            let report = store.admit("refusal-order".into(), owned);
            assert_eq!(report.accepted_sessions, 2);

            assert!(store.settle(
                &first,
                &id,
                DeliveryTerminal::TypedRefused("first relay refused".into()),
            ));
            assert!(outcomes.lock().is_empty());
            assert_eq!(store.pending(&second), vec![id.clone()]);
            assert_eq!(live.load(Ordering::SeqCst), 1);

            assert!(store.settle(&second, &id, DeliveryTerminal::Accepted));
            let records = outcomes.lock();
            assert_eq!(records.len(), 1);
            assert!(matches!(
                records[0].kind,
                AttemptOutcomeKind::Accepted { .. }
            ));
            assert_eq!(live.load(Ordering::SeqCst), 0);
        }

        exercise(false);
        exercise(true);
    }

    #[test]
    fn carrier_aggregate_is_deterministic_and_reconnect_scoped() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (first, _) = store.open_session();
        let (second, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("aggregate-accepted".into(), owned);
        assert_eq!(report.accepted_sessions, 2);
        assert!(store.settle(&first, &event_id, DeliveryTerminal::Accepted));
        assert!(store.settle(&second, &event_id, DeliveryTerminal::Accepted));
        assert_eq!(outcomes.lock().len(), 1);

        fn refusal_order(reverse: bool) -> String {
            let live = Arc::new(AtomicUsize::new(0));
            let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
            let (first, _) = store.open_session();
            let (second, _) = store.open_session();
            let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
            let event_id = owned.value().id.clone();
            let report = store.admit("aggregate-refusal".into(), owned);
            assert_eq!(report.accepted_sessions, 2);
            let (earlier, later) = if reverse {
                (second, first)
            } else {
                (first, second)
            };
            assert!(store.settle(
                &earlier,
                &event_id,
                DeliveryTerminal::TypedRefused("z-last".into()),
            ));
            assert!(outcomes.lock().is_empty());
            assert!(store.settle(
                &later,
                &event_id,
                DeliveryTerminal::TypedRefused("a-first".into()),
            ));
            let records = outcomes.lock();
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].kind,
                AttemptOutcomeKind::TypedRefused("a-first".into())
            );
            records[0].attempt.clone()
        }

        assert_eq!(refusal_order(false), refusal_order(true));

        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (first, _) = store.open_session();
        let (second, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        store.admit("aggregate-reconnect".into(), owned);
        store.close_session(first, DeliveryTerminal::Cancelled);
        assert!(outcomes.lock().is_empty());
        store.close_session(second, DeliveryTerminal::Cancelled);
        assert_eq!(outcomes.lock().len(), 1);
        let (fresh, _) = store.open_session();
        assert_eq!(store.pending(&fresh).len(), 1);
        store.close_session(fresh, DeliveryTerminal::Cancelled);
        assert_eq!(outcomes.lock().len(), 2);
    }

    #[test]
    fn all_carrier_refusal_is_once_only_and_rearms_after_eligible_reconnect() {
        let allow = Arc::new(AtomicBool::new(true));
        let live = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(ToggleProvider {
            allow: Arc::clone(&allow),
            live: Arc::clone(&live),
        });
        let store = DeliveryStore::new(provider);
        let (initial, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("all-carrier-once".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert!(store.settle(&initial, &event_id, DeliveryTerminal::Cancelled,));
        assert_eq!(live.load(Ordering::SeqCst), 0);

        allow.store(false, Ordering::SeqCst);
        let (_, first_session_refusal, first_refusals) = store.open_session_with_refusals();
        assert!(first_session_refusal.is_none());
        assert_eq!(first_refusals.len(), 1);
        assert_eq!(first_refusals[0].attempt, "all-carrier-once");
        assert_eq!(first_refusals[0].event_id, event_id);
        let (_, second_session_refusal, second_refusals) = store.open_session_with_refusals();
        assert!(second_session_refusal.is_none());
        assert!(second_refusals.is_empty());

        allow.store(true, Ordering::SeqCst);
        let (fresh, fresh_session_refusal, fresh_refusals) = store.open_session_with_refusals();
        assert!(fresh_session_refusal.is_none());
        assert!(fresh_refusals.is_empty());
        assert_eq!(store.pending(&fresh), vec![event_id.clone()]);
        assert!(store.settle(&fresh, &event_id, DeliveryTerminal::Cancelled));
        assert_eq!(live.load(Ordering::SeqCst), 0);

        allow.store(false, Ordering::SeqCst);
        let (_, third_session_refusal, third_refusals) = store.open_session_with_refusals();
        assert!(third_session_refusal.is_none());
        assert_eq!(third_refusals.len(), 1);
        assert_eq!(third_refusals[0].attempt, "all-carrier-once");
        assert_eq!(third_refusals[0].event_id, event_id);
    }

    #[test]
    fn provider_delta_covers_correlation_and_each_exact_entry() {
        let live = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let retention = DeliveryRetention::for_attempt("exact-correlation", &event());
        assert_eq!(
            retention.attempt_map_growth_bytes,
            std::mem::size_of::<DeliveryMapNode<String, AttemptEntry>>()
        );
        assert_eq!(
            retention.relay_map_growth_bytes,
            std::mem::size_of::<DeliveryMapNode<RelaySessionId, RelayEntry>>()
        );
        assert!(SessionRetention::exact().session_set_growth_bytes > 0);
        let store = DeliveryStore::new(Arc::new(ExactCustodyProvider {
            live: Arc::clone(&live),
            calls: Arc::clone(&calls),
        }));
        let (session, _) = store.open_session();
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("exact-correlation".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert_eq!(
            *calls.lock(),
            vec![
                "attempt-correlation".to_string(),
                "attempt-entry".to_string(),
                "relay".to_string(),
                "relay-entry".to_string(),
            ]
        );
        assert_eq!(live.load(Ordering::SeqCst), 4);
        assert_eq!(
            store.finish_attempt("exact-correlation", DeliveryTerminal::Accepted),
            1
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(!store.settle(&session, &event_id, DeliveryTerminal::Accepted));
    }
}
