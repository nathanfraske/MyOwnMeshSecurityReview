//! Attempt-owned Nostr delivery custody.
//!
//! A negotiation event is retained by its source owner until the exact live
//! attempt finishes.  Every relay connection gets its own provider-backed
//! entry; a reconnect is a new session and can receive the still-live event.
//! This module deliberately has no count cap, elapsed TTL, retry timer, or
//! route authority.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

use super::event::NostrEvent;
use crate::{ErasedOwner, OwnedSignal};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRetention {
    pub encoded_event_bytes: usize,
    pub structural_entry_bytes: usize,
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

/// Provider-owned lease for one exact (event, relay-session) delivery.
pub trait DeliveryLease: Send {
    fn finish(self: Box<Self>, terminal: DeliveryTerminal);
}

/// Narrow seam for the core resource provider.
///
/// The event is borrowed so the provider can compute its exact reservation
/// before the encoded frame is allocated.  The returned lease remains with
/// that relay-session entry until one terminal outcome consumes it.
pub trait DeliveryProvider: Send + Sync {
    fn reserve(
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

impl DeliveryLease for UnmeteredLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {}
}

impl DeliveryProvider for UnmeteredDeliveryProvider {
    fn reserve(
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefusal {
    DuplicateLiveEvent,
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
    relays: HashMap<RelaySessionId, RelayEntry>,
    provider_refused: bool,
}

struct DeliveryState {
    sessions: HashSet<RelaySessionId>,
    attempts: HashMap<String, AttemptEntry>,
}

/// The live attempt owner and its per-relay delivery entries.
pub struct DeliveryStore {
    provider: Arc<dyn DeliveryProvider>,
    state: Mutex<DeliveryState>,
    notify: Notify,
}

impl DeliveryStore {
    pub fn new(provider: Arc<dyn DeliveryProvider>) -> Arc<Self> {
        Arc::new(Self {
            provider,
            state: Mutex::new(DeliveryState {
                sessions: HashSet::new(),
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
        let mut state = self.state.lock();
        let session = RelaySessionId::fresh();
        state.sessions.insert(session.clone());
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
                    entry.relays.insert(
                        session.clone(),
                        RelayEntry {
                            lease,
                            in_flight: false,
                        },
                    );
                }
                Err(error) => {
                    entry.provider_refused = true;
                    refused.push((entry.owned.value().id.clone(), error));
                }
            }
        }
        (session, refused)
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
        let mut relays = HashMap::new();
        let mut refused = Vec::new();
        for session in state.sessions.iter().cloned() {
            match self
                .provider
                .reserve(&attempt, session.clone(), owned.value(), retention)
            {
                Ok(lease) => {
                    relays.insert(
                        session,
                        RelayEntry {
                            lease,
                            in_flight: false,
                        },
                    );
                }
                Err(error) => refused.push((session, error)),
            }
        }
        let accepted_sessions = relays.len();
        let provider_refused = !refused.is_empty();
        state.attempts.insert(
            event_id.clone(),
            AttemptEntry {
                attempt,
                owned,
                relays,
                provider_refused,
            },
        );
        drop(state);
        self.notify.notify_waiters();
        AdmissionReport {
            event_id,
            accepted_sessions,
            refused,
            attempt_refusal: None,
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
        let lease = {
            let mut state = self.state.lock();
            let (lease, remove_attempt) = {
                let Some(entry) = state.attempts.get_mut(event_id) else {
                    return false;
                };
                let Some(relay) = entry.relays.remove(session) else {
                    return false;
                };
                let remove_attempt = matches!(terminal, DeliveryTerminal::Accepted)
                    && entry.relays.is_empty()
                    && !entry.provider_refused;
                (relay.lease, remove_attempt)
            };
            if remove_attempt {
                // Remove the source owner atomically with the final relay
                // entry.  A reconnect may otherwise acquire this mutex after
                // the lease is detached but before the old implementation
                // removed the attempt, fund a fresh entry, and then have
                // that entry erased by the stale removal.
                state.attempts.remove(event_id);
            }
            lease
        };
        lease.finish(terminal);
        true
    }

    /// Release every entry for an exact attempt lifecycle terminal.
    pub fn finish_attempt(&self, attempt: &str, terminal: DeliveryTerminal) -> usize {
        let mut leases = Vec::new();
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
                    leases.extend(entry.relays.into_values().map(|relay| relay.lease));
                }
            }
        }
        let count = leases.len();
        for lease in leases {
            lease.finish(terminal.clone());
        }
        count
    }

    /// Retire one relay session while preserving live attempts for a fresh
    /// reconnect.
    pub fn close_session(&self, session: RelaySessionId, terminal: DeliveryTerminal) -> usize {
        let mut leases = Vec::new();
        {
            let mut state = self.state.lock();
            state.sessions.remove(&session);
            for entry in state.attempts.values_mut() {
                if let Some(relay) = entry.relays.remove(&session) {
                    leases.push(relay.lease);
                }
            }
        }
        let count = leases.len();
        for lease in leases {
            lease.finish(terminal.clone());
        }
        count
    }

    /// Release all per-relay custody and every live source owner.
    pub fn shutdown(&self) -> usize {
        let mut leases = Vec::new();
        {
            let mut state = self.state.lock();
            state.sessions.clear();
            for entry in state.attempts.drain().map(|(_, entry)| entry) {
                leases.extend(entry.relays.into_values().map(|relay| relay.lease));
            }
        }
        let count = leases.len();
        for lease in leases {
            lease.finish(DeliveryTerminal::Shutdown);
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

    impl DeliveryProvider for CountingProvider {
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

    struct RejectOnceProvider {
        live: Arc<AtomicUsize>,
        refused: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for RejectOnceProvider {
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
