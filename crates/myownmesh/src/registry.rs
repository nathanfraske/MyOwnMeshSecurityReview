//! Per-daemon registry of joined networks, keyed by both the user-chosen
//! config id and the wire-level network id. The control socket uses
//! this to address per-network operations (peers list, roster mutations,
//! topology changes, add/remove) without `serve.rs` having to thread a
//! handle through every dispatch arm.
//!
//! Each entry pairs a `JoinedNetwork` with its `SignalingDrivers` — the
//! signaling driver set (Nostr and/or mDNS, per the network's
//! strategy) is per-network, and dropping the handle stops it.
//!
//! # One lifecycle owner
//!
//! This registry is the only owner of a joined runtime's lifecycle, and
//! [`RuntimeState`] is the only place the answer lives.
//!
//! It used to be inferred after the fact from an `Arc` refcount: removal
//! unlinked the aliases, dropped the signaling drivers, and then asked
//! `Arc::try_unwrap` whether anyone still held a clone. A refcount answers "is
//! this value shared", which is a different question — a runtime with one
//! in-flight control request and a runtime that has finished tearing down are
//! both "not solely owned". The caller was told `StillBorrowed` either way, on
//! the stated theory that the engine would exit when its command sender dropped.
//! It could not: `NetworkState` holds that sender itself. So the engine kept
//! running with live sessions while no key in this map could reach it, and
//! `network_update` would then join a replacement under the same configuration,
//! leaving a hidden runtime beside the visible one.
//!
//! Four properties replace that, and each is structural rather than observed:
//!
//! * a runtime is claimed for teardown, unlinked, and moved to the closing set
//!   in **one** acquisition of the registry's state lock, so there is no
//!   instant in which it is unreachable, unowned, or invisible to the check a
//!   concurrent insert makes;
//! * a `Closing` entry stays owned here until teardown completes, so no live
//!   runtime is ever ownerless;
//! * a replacement under either id is refused while **any** runtime holding
//!   either id is not yet `Stopped` — `Running` as well as `Closing`. A
//!   `Running` collision used to fall straight through to the map, where
//!   `insert` overwrote one alias and `or_insert` left the other pointing at
//!   the predecessor: two live runtimes, one half-reachable, neither being
//!   torn down. That is the same defect through a different door;
//! * every caller that loses the race to claim a teardown **waits for the
//!   winner** and observes `Stopped` before returning. Answering "already
//!   closing" and returning immediately let `shutdown_all` finish while a
//!   concurrent removal was still awaiting an engine driver, and the daemon
//!   then exited with that engine live — which is the review's own failure
//!   mode arriving through the shutdown door.
//!
//! Teardown itself needs no unwrapping: [`JoinedNetwork::shutdown`] takes
//! `&self` and is idempotent, so the supervisor drives it through the shared
//! handle rather than requiring unique ownership of every outstanding facade.
//! A loser calls it too — that is what makes "wait for the winner" go through
//! the runtime's own seam rather than through a second mechanism — and then
//! waits on [`Lifecycle::await_stopped`], because `shutdown` returning proves
//! the driver is retired and not yet that this registry has finished
//! bookkeeping the fact.
//!
//! Concurrency: one [`parking_lot::Mutex`] guards the aliases and the closing
//! set together, because every decision here is about both. Callers pull an
//! `Arc<JoinedNetwork>` out and drop the guard before awaiting any per-network
//! method — holding a `parking_lot` guard across `.await` is forbidden, and no
//! path here does.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::engine::SignalingDrivers;
use myownmesh_core::JoinedNetwork;
use parking_lot::Mutex;

/// How long [`NetworkRegistry::announce_all_departures`] waits after queuing
/// the per-network `leave` broadcasts before returning, so they reach the
/// already-connected relay sockets before the registry is drained on
/// shutdown. Mirrors core's per-network `JoinedNetwork::announce_leave`
/// flush window.
const DEPARTURE_FLUSH: Duration = Duration::from_millis(250);

/// Where one joined runtime is in its life. The single owner of that answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeState {
    /// Registered and authoritative. Operations are admitted.
    Running,
    /// Teardown has begun. The aliases are gone and no new operation is
    /// admitted, but the runtime is still owned here. An outstanding facade
    /// observes this instead of keeping an unregistered runtime authoritative.
    Closing,
    /// Teardown finished: signaling drivers dropped, engine driver retired. A
    /// replacement may install under the same ids.
    Stopped,
}

/// Snapshot view of one joined network for ctl / GUI consumers.
/// Cheap to compute — every field is already cached on the
/// `JoinedNetwork`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkSummary {
    /// User-chosen config record id (unique per device). Auto-generated
    /// (`net_<rand>_<stamp>`) at create time and used as a stable
    /// key for control-protocol ops — not the friendly display name.
    pub config_id: String,
    /// Wire-level network rendezvous handle. Human-typed at create
    /// time (e.g. `cpjeeves-home`); the GUI falls back to this when
    /// no cosmetic `label` is set.
    pub network_id: String,
    /// Cosmetic display name picked at create time. Empty falls
    /// back to `network_id`.
    pub label: String,
    /// Coarse-grained phase: joining / alone / discovering / active / degraded / stopped.
    pub phase: myownmesh_core::MeshPhase,
    /// Current topology mode. Serialised with serde-internal tagging so
    /// `Star { hub }` keeps its hub field on the wire.
    pub topology: myownmesh_core::TopologyMode,
    /// Per-network traffic accounting since join — frames/bytes by
    /// class, signaling publish/receive split into presence vs
    /// negotiation, forwarding duty, acked-delivery backlog. The
    /// numbers a topology experiment compares.
    pub traffic: myownmesh_core::engine::traffic::TrafficSnapshot,
}

/// Where one runtime is in its life, and the signal that it has finished.
///
/// Separated from [`Entry`] because it is the whole of the lifecycle rule and
/// none of it needs a runtime to be true. Claiming, waiting and finishing are
/// the three things that have to be right, and keeping them in one small type
/// is what lets them be exercised directly rather than only through a joined
/// network.
pub(crate) struct Lifecycle {
    state: Mutex<RuntimeState>,
    /// Fired once, when [`Self::finish`] lands. Waiters re-read the state
    /// rather than trusting the wake, so a notify that arrives before a waiter
    /// registers cannot be lost.
    stopped: tokio::sync::Notify,
}

impl Lifecycle {
    /// A runtime begins `Running`. Deliberately not `Default`: which state a
    /// lifecycle starts in is a decision, and a derived one would read as the
    /// state a runtime is in when nobody said.
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeState::Running),
            stopped: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn state(&self) -> RuntimeState {
        *self.state.lock()
    }

    /// Claim this runtime for teardown, exactly once.
    ///
    /// `true` to the caller that moved it `Running` -> `Closing`, and `false`
    /// to every other — which is what makes "exactly one teardown" a property
    /// of the transition rather than of caller discipline.
    pub(crate) fn begin_closing(&self) -> bool {
        let mut state = self.state.lock();
        if *state != RuntimeState::Running {
            return false;
        }
        *state = RuntimeState::Closing;
        true
    }

    /// Record that teardown is complete and release every waiter.
    ///
    /// The state moves first and the wake follows, which is the order
    /// [`Self::await_stopped`]'s double check depends on: a waiter that reads
    /// the state after registering its `Notified` cannot miss a `finish` that
    /// happened in between.
    pub(crate) fn finish(&self) {
        *self.state.lock() = RuntimeState::Stopped;
        self.stopped.notify_waiters();
    }

    /// Wait until this runtime has actually stopped.
    ///
    /// Returns `Stopped` and nothing else — the return exists so a caller can
    /// state what it observed rather than assert it. The double check around
    /// registration is the standard race-free `Notify` shape: read, register,
    /// read again, then await. Without the second read a `finish` landing
    /// between the first read and the registration would be lost and the
    /// waiter would park forever.
    pub(crate) async fn await_stopped(&self) -> RuntimeState {
        loop {
            if self.state() == RuntimeState::Stopped {
                return RuntimeState::Stopped;
            }
            let notified = self.stopped.notified();
            if self.state() == RuntimeState::Stopped {
                return RuntimeState::Stopped;
            }
            notified.await;
        }
    }
}

/// One row of the registry: the `JoinedNetwork` handle, the
/// `SignalingDrivers` that keep signaling alive, and where that runtime is in
/// its life. `drivers` is `Mutex<Option<...>>` so teardown can `take()` it
/// through the shared `Arc` without `&mut self`.
struct Entry {
    joined: Arc<JoinedNetwork>,
    drivers: Mutex<Option<SignalingDrivers>>,
    lifecycle: Lifecycle,
}

impl Entry {
    /// Whether this runtime answers to `id` under either of its two names.
    fn holds(&self, id: &str) -> bool {
        self.joined.config_id() == id || self.joined.network_id() == id
    }
}

/// Registry shared between `serve.rs` (which owns initial population
/// + final shutdown) and the control socket dispatcher (which clones
///   `Arc<JoinedNetwork>`s out to perform per-network work, and may
///   add/remove networks via the NetworkAdd / NetworkRemove ops).
#[derive(Default)]
pub struct NetworkRegistry {
    state: Mutex<RegistryState>,
    #[cfg(test)]
    claim_pause: Mutex<Option<Arc<ClaimPause>>>,
}

#[cfg(test)]
struct ClaimPause {
    reached: tokio::sync::Barrier,
    release: tokio::sync::Barrier,
}

#[cfg(test)]
impl ClaimPause {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reached: tokio::sync::Barrier::new(2),
            release: tokio::sync::Barrier::new(2),
        })
    }
}

/// The aliases and the closing set, behind **one** lock.
///
/// They are one lock because every decision this registry makes reads both. An
/// insert has to know whether either id is held by a visible runtime *or* by
/// one draining; a removal has to move an entry from the first to the second
/// without a moment in between. Two locks made those two-step operations, and
/// each step was a window: an insert that checked the closing set, released it,
/// and then took the map could be interleaved by the removal it was checking
/// for.
#[derive(Default)]
struct RegistryState {
    /// Both ids of every visible runtime, two keys to one `Arc<Entry>`.
    aliases: HashMap<String, Arc<Entry>>,
    /// Runtimes past their aliases and not yet `Stopped`.
    ///
    /// This is what makes "no unreachable live runtime" structural rather than
    /// hoped for. Removal unlinks the aliases before teardown can finish, and
    /// in that window the entry must be owned by something or it is running
    /// with nobody able to name it. It is owned here, and a replacement under
    /// either of its ids is refused until it drains.
    closing: Vec<Arc<Entry>>,
}

impl RegistryState {
    /// The runtime answering to `key`, visible or draining.
    ///
    /// The closing set is searched too, and that is the correction to a
    /// removal that used to start at the alias map alone: once the first
    /// removal unlinked the aliases, a second one missed and reported
    /// `NotFound` about a network that was very much still there.
    fn find(&self, key: &str) -> Option<Arc<Entry>> {
        if let Some(entry) = self.aliases.get(key) {
            return Some(entry.clone());
        }
        self.closing.iter().find(|entry| entry.holds(key)).cloned()
    }

    /// Any runtime holding either id that has not reached `Stopped`.
    ///
    /// Both sets and both states. `Running` is included deliberately: a live
    /// runtime under one of these ids is a collision, not a free slot, and
    /// admitting past it is what left two runtimes for one network with only
    /// one of them reachable.
    fn holder(&self, config_id: &str, network_id: &str) -> Option<Arc<Entry>> {
        self.aliases
            .values()
            .chain(self.closing.iter())
            .find(|entry| {
                (entry.holds(config_id) || entry.holds(network_id))
                    && entry.lifecycle.state() != RuntimeState::Stopped
            })
            .cloned()
    }

    /// Unlink every alias pointing at this exact entry.
    ///
    /// By pointer identity rather than by id string: the two aliases are two
    /// keys for one `Arc`, and a network whose config id happens to equal
    /// another's network id must not have its neighbour's key removed.
    fn unlink(&mut self, entry: &Arc<Entry>) {
        let target = Arc::as_ptr(entry);
        self.aliases.retain(|_, held| Arc::as_ptr(held) != target);
    }

    /// Claim `entry` for teardown and move it out of the aliases in one step.
    ///
    /// `true` to the one caller that won the claim. Everything the winner has
    /// to do before it can release the lock happens here, so no other caller
    /// can observe the entry half-moved.
    fn claim(&mut self, entry: &Arc<Entry>) -> bool {
        if !entry.lifecycle.begin_closing() {
            return false;
        }
        self.unlink(entry);
        if !self.closing.iter().any(|held| Arc::ptr_eq(held, entry)) {
            self.closing.push(entry.clone());
        }
        true
    }
}

impl NetworkRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a freshly-joined network together with its signaling
    /// driver handles. Indexed by both the config record id and the
    /// wire-level network id so callers can use either as the lookup
    /// key (the CLI / GUI both have a habit of passing whichever
    /// happens to be in scope).
    ///
    /// Refused while **any** runtime holding either id has not reached
    /// `Stopped` — whether it is `Running` or still tearing down.
    ///
    /// Both refusals matter and they are different defects. `Closing` is the
    /// ordering rule of finding 13: `network_update` removes and re-joins under
    /// the same configuration, and admitting the replacement before the
    /// predecessor stopped is what produced two runtimes for one network.
    /// `Running` is the same outcome by a shorter route — without this check
    /// the two writes below would overwrite one alias and leave the other
    /// pointing at the live predecessor, which is then unreachable under half
    /// its names and owned by nothing that will ever tear it down.
    ///
    /// The check and the two writes are one acquisition of the state lock, so a
    /// removal cannot interleave between them.
    ///
    /// The caller is handed its `JoinedNetwork` back rather than having it
    /// dropped, so refusing costs it nothing it cannot retry.
    pub fn insert(
        &self,
        joined: JoinedNetwork,
        drivers: Option<SignalingDrivers>,
    ) -> InsertOutcome {
        let config_id = joined.config_id().to_string();
        let network_id = joined.network_id().to_string();
        let mut state = self.state.lock();
        let held = state.holder(&config_id, &network_id);
        if let Some(holder) = held {
            return InsertOutcome::refused(InsertRefused {
                joined,
                drivers,
                state: holder.lifecycle.state(),
            });
        }
        let entry = Arc::new(Entry {
            joined: Arc::new(joined),
            drivers: Mutex::new(drivers),
            lifecycle: Lifecycle::new(),
        });
        state.aliases.insert(config_id, entry.clone());
        state.aliases.entry(network_id).or_insert(entry);
        InsertOutcome::inserted()
    }

    /// Resolve a network's `JoinedNetwork` by either its config id or
    /// wire-level network id. Returns a cloned `Arc` so callers can
    /// release the internal lock before awaiting.
    ///
    /// Answers only for a `Running` runtime. A handle taken before removal may
    /// still be held by an in-flight request — that is unavoidable and
    /// harmless, because the runtime it names is being torn down by its owner
    /// and the operations that matter refuse on their own fences. What must not
    /// happen is this registry *issuing* a fresh authoritative handle to a
    /// runtime it has already begun closing.
    pub fn get(&self, key: &str) -> Option<Arc<JoinedNetwork>> {
        let entry = self.state.lock().aliases.get(key).cloned()?;
        (entry.lifecycle.state() == RuntimeState::Running).then(|| entry.joined.clone())
    }

    /// The lifecycle state of the runtime under `key`, for a caller that needs
    /// to distinguish "never existed" from "on its way out".
    pub fn state(&self, key: &str) -> Option<RuntimeState> {
        self.state
            .lock()
            .find(key)
            .map(|entry| entry.lifecycle.state())
    }

    /// True when a runtime holding that id exists and has not stopped.
    ///
    /// A draining runtime counts. It still holds both ids as far as a
    /// replacement is concerned, so reporting it absent would invite a caller
    /// to attempt an insert this registry is about to refuse.
    pub fn contains(&self, key: &str) -> bool {
        self.state
            .lock()
            .find(key)
            .is_some_and(|entry| entry.lifecycle.state() != RuntimeState::Stopped)
    }

    /// Snapshot every distinct network. Each network appears once
    /// even though the map stores aliases.
    pub fn summaries(&self) -> Vec<NetworkSummary> {
        let state = self.state.lock();
        let map = &state.aliases;
        // Dedup by entry pointer — both the config-id and
        // network-id aliases point at the same `Arc<Entry>`, so
        // pointer identity is the cheapest dedup key.
        let mut seen: Vec<*const Entry> = Vec::new();
        let mut out = Vec::new();
        for entry in map.values() {
            let ptr = Arc::as_ptr(entry);
            if seen.contains(&ptr) {
                continue;
            }
            seen.push(ptr);
            let j = &entry.joined;
            out.push(NetworkSummary {
                config_id: j.config_id().to_string(),
                network_id: j.network_id().to_string(),
                label: j.label().to_string(),
                phase: j.current_phase(),
                topology: j.current_topology(),
                traffic: j.traffic(),
            });
        }
        // Stable order across calls: alphabetical by config id.
        out.sort_by(|a, b| a.config_id.cmp(&b.config_id));
        out
    }

    /// Tear one network down: mark it `Closing`, unlink every alias, drop the
    /// signaling drivers, await the engine driver, and mark it `Stopped`.
    ///
    /// The order is the correction. Marking precedes unlinking, so the runtime
    /// is never both unreachable and admitting work; ownership stays here
    /// across the await, so it is never live and ownerless; and the entry is
    /// only released once `shutdown` has returned, so the next `insert` under
    /// either id sees a finished teardown rather than a racing one.
    ///
    /// A caller that loses the claim does **not** return early. It waits for
    /// the winner through the runtime's own idempotent `shutdown` and then for
    /// this registry to record `Stopped`, and answers
    /// [`RemoveResult::AlreadyClosing`] carrying what it observed. Returning
    /// immediately is what let a concurrent `shutdown_all` finish while an
    /// engine driver was still being awaited.
    ///
    /// A runtime already past its aliases is still found: the closing set is
    /// searched too, so a second removal answers about the teardown in progress
    /// rather than reporting `NotFound` about a network that is still there.
    ///
    /// There is deliberately no "removed but still borrowed" answer: an
    /// outstanding facade is not a lifecycle state, and reporting it as one is
    /// what let a live runtime escape.
    pub async fn remove(&self, key: &str) -> RemoveResult {
        let claim = {
            let mut state = self.state.lock();
            let Some(entry) = state.find(key) else {
                return RemoveResult::NotFound;
            };
            let won = state.claim(&entry);
            (entry, won)
        };
        match claim {
            (entry, true) => {
                #[cfg(test)]
                self.pause_after_claim_for_test().await;
                RemoveResult::Removed(self.teardown(entry).await)
            }
            (entry, false) => RemoveResult::AlreadyClosing(Self::await_winner(&entry).await),
        }
    }

    #[cfg(test)]
    async fn pause_after_claim_for_test(&self) {
        let pause = self.claim_pause.lock().take();
        if let Some(pause) = pause {
            pause.reached.wait().await;
            pause.release.wait().await;
        }
    }

    #[cfg(test)]
    fn install_claim_pause_for_test(&self) -> Arc<ClaimPause> {
        let pause = ClaimPause::new();
        *self.claim_pause.lock() = Some(Arc::clone(&pause));
        pause
    }

    /// Wait for whoever won the claim on `entry` to finish.
    ///
    /// Two waits, and both are needed. `shutdown` is the runtime's own seam and
    /// is idempotent — its internal driver mutex is what makes a second caller
    /// observe the same retirement rather than an empty slot — so going through
    /// it means the loser waits on the same thing the winner waited on, not on
    /// a parallel mechanism that could drift from it. `await_stopped` then
    /// covers the remainder: `shutdown` returning proves the driver is retired,
    /// and not yet that this registry has recorded the fact and released the
    /// entry. A caller told `Stopped` can rely on both.
    async fn await_winner(entry: &Arc<Entry>) -> RuntimeState {
        let _ = entry.joined.shutdown().await;
        entry.lifecycle.await_stopped().await
    }

    /// Drivers down, engine driver awaited, state advanced to `Stopped`, entry
    /// released. The one teardown path; `remove` and `shutdown_all` share it so
    /// there is a single ordering to get right.
    async fn teardown(&self, entry: Arc<Entry>) -> Result<(), String> {
        // Signaling first: their `Drop` signals every spawned task to exit, and
        // doing it before the engine wait means those tasks are not still
        // publishing on behalf of a network that is going away.
        drop(entry.drivers.lock().take());
        let outcome = entry
            .joined
            .shutdown()
            .await
            .map_err(|error| error.to_string());
        // Ownership is released before the state moves, so a waiter released by
        // `finish` cannot find the entry still held here and conclude the
        // teardown is unfinished.
        let target = Arc::as_ptr(&entry);
        {
            let mut state = self.state.lock();
            state.closing.retain(|held| Arc::as_ptr(held) != target);
            // Publish `Stopped` before releasing the same guard insert/remove
            // acquire. No caller can observe an absent-but-still-Closing gap.
            entry.lifecycle.finish();
        }
        outcome
    }

    /// Broadcast a graceful `leave` on every joined network, then wait
    /// briefly for the publishes to reach the relays, before the caller
    /// drains the registry on daemon shutdown. Peers drop our sessions
    /// immediately on the `leave` instead of waiting out their ~90 s
    /// heartbeat timeout — the same courtesy `network_remove` extends for a
    /// single network. The read lock is held only for the synchronous emit
    /// (dropped before the flush wait), so this never holds a `parking_lot`
    /// guard across `.await`.
    pub async fn announce_all_departures(&self) {
        let mut emitted = false;
        {
            let state = self.state.lock();
            let map = &state.aliases;
            // Dedup by entry pointer — both id aliases point at the same Arc.
            let mut seen: Vec<*const Entry> = Vec::new();
            for entry in map.values() {
                let ptr = Arc::as_ptr(entry);
                if seen.contains(&ptr) {
                    continue;
                }
                seen.push(ptr);
                entry.joined.request_departure();
                emitted = true;
            }
        }
        if emitted {
            tokio::time::sleep(DEPARTURE_FLUSH).await;
        }
    }

    /// Tear down every distinct network, in the same order and through the same
    /// path as a single removal.
    ///
    /// Nothing is skipped and nothing is left running. The previous drain
    /// silently dropped any entry it could not `try_unwrap`, so a network held
    /// by one in-flight request at shutdown was neither left nor reported, and
    /// the daemon exited leaving peers to time it out.
    ///
    /// A network a concurrent control request is already tearing down is **not**
    /// skipped either: this waits for that teardown before returning. Skipping
    /// it let the daemon exit with an engine driver still being awaited, which
    /// is the same live-runtime-after-removal shape one layer up. Its outcome
    /// belongs to the caller that claimed it, so it is not repeated in the
    /// returned vector — what comes back is one result per teardown this call
    /// performed.
    pub async fn shutdown_all(&self) -> Vec<Result<(), String>> {
        let (winners, losers) = {
            let mut state = self.state.lock();
            // Every distinct runtime, visible or already draining. Dedup by
            // pointer: both aliases of one network are the same `Arc`.
            let mut distinct: Vec<Arc<Entry>> = Vec::new();
            for entry in state.aliases.values().chain(state.closing.iter()) {
                if !distinct.iter().any(|held| Arc::ptr_eq(held, entry)) {
                    distinct.push(entry.clone());
                }
            }
            let mut winners = Vec::new();
            let mut losers = Vec::new();
            for entry in distinct {
                if state.claim(&entry) {
                    winners.push(entry);
                } else {
                    losers.push(entry);
                }
            }
            (winners, losers)
        };
        let mut outcomes = Vec::new();
        for entry in winners {
            outcomes.push(self.teardown(entry).await);
        }
        for entry in losers {
            Self::await_winner(&entry).await;
        }
        outcomes
    }
}

/// Outcome of a [`NetworkRegistry::remove`] call.
pub enum RemoveResult {
    /// The runtime was torn down: drivers dropped, engine driver retired,
    /// state `Stopped`. Carries the shutdown outcome so a failed teardown is
    /// reported rather than assumed clean.
    Removed(Result<(), String>),
    /// No entry under that key.
    NotFound,
    /// A teardown for this runtime was already in progress, so this call
    /// started nothing — and **waited for it**. Carries the state observed
    /// once that teardown finished, which is `Stopped`: the variant reports
    /// who did the work, not that the caller gave up early.
    AlreadyClosing(RuntimeState),
}

/// A rejected [`NetworkRegistry::insert`], handing the caller back exactly what
/// it passed in.
///
/// The values come back rather than being dropped: a refusal is an ordering
/// answer ("the previous runtime under this id has not stopped"), not a
/// decision to destroy a network the caller just joined.
pub struct InsertRefused {
    pub joined: JoinedNetwork,
    pub drivers: Option<SignalingDrivers>,
    /// The state of the runtime still holding one of these ids.
    pub state: RuntimeState,
}

/// Allocation-free answer from [`NetworkRegistry::insert`].
///
/// A refused insert must return the caller's joined runtime and signaling
/// drivers intact so the caller can shut them down. That payload is large
/// enough to trip `clippy::result_large_err`; boxing it would add an allocation
/// that no resource owner reserved. This wrapper retains the same inline
/// ownership and drop behavior without treating the refusal as a boxed error.
#[must_use = "a refused insert returns a live runtime that its caller must shut down"]
pub struct InsertOutcome {
    refusal: Option<InsertRefused>,
}

impl InsertOutcome {
    fn inserted() -> Self {
        Self { refusal: None }
    }

    fn refused(refusal: InsertRefused) -> Self {
        Self {
            refusal: Some(refusal),
        }
    }

    /// Return the refused runtime and drivers, or `None` when insertion won.
    pub fn into_refusal(self) -> Option<InsertRefused> {
        self.refusal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    // The two controls that stand up a real `Mesh` serialize on
    // `crate::exclusive_connector_fixture`, shared with every other
    // connector-consuming family in this binary. A mutex private to this module
    // would stop these two racing each other and not stop either of them racing
    // `ipc::bridge`, which is what actually exhausted the process-global
    // connector budget. The four `Lifecycle` controls take nothing: they drive
    // the state machine directly and open no runtime.

    fn connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        let capacity = NonZeroUsize::new(4).expect("fixture capacity is nonzero");
        let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
            myownmesh_core::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
            myownmesh_core::ConnectorCallbackServiceWeights::data_only(capacity, capacity),
            myownmesh_core::RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture callback policy is consistent");
        let profile = myownmesh_core::WebRtcConnectorProfile::new(
            callbacks,
            myownmesh_core::PendingRemoteCandidatePolicy::elastic(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), profile)
    }

    async fn mesh() -> myownmesh_core::MeshHandle {
        myownmesh_core::Mesh::open_connector_capable_with_identity(
            myownmesh_core::MeshConfig::default(),
            Arc::new(myownmesh_core::Identity::ephemeral()),
            connector_policy(),
        )
        .await
        .expect("registry fixture opens a connector-capable Mesh")
    }

    fn network(config_id: &str, network_id: &str) -> myownmesh_core::NetworkConfig {
        myownmesh_core::NetworkConfig {
            id: config_id.to_string(),
            network_id: network_id.to_string(),
            label: config_id.to_string(),
            kind: Default::default(),
            topology: myownmesh_core::TopologyMode::FullMesh,
            signaling: myownmesh_core::config::SignalingConfig::default(),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            roster_path: None,
            pinned_peers: Vec::new(),
            auto_approve: true,
        }
    }

    /// Exactly one caller may claim a runtime for teardown.
    ///
    /// This is the property every other one rests on. If two callers could
    /// claim, two teardowns would run against one runtime and the second would
    /// await a driver the first had already retired — and, worse, the second
    /// would report a successful removal it did not perform.
    ///
    /// Non-vacuous in both directions: the losers must be told `false`, and the
    /// state must actually have moved, so a `begin_closing` that always
    /// answered `true` and a `begin_closing` that never transitioned would each
    /// fail here.
    #[test]
    fn exactly_one_caller_claims_a_teardown() {
        let lifecycle = Lifecycle::new();
        assert_eq!(
            lifecycle.state(),
            RuntimeState::Running,
            "non-vacuity: a fresh runtime is claimable"
        );

        let claims: Vec<bool> = (0..8).map(|_| lifecycle.begin_closing()).collect();
        assert_eq!(
            claims.iter().filter(|won| **won).count(),
            1,
            "one winner, and the other seven are told they lost"
        );
        assert!(claims[0], "and the winner is the first to ask");
        assert_eq!(
            lifecycle.state(),
            RuntimeState::Closing,
            "the claim moved the state rather than merely answering about it"
        );

        lifecycle.finish();
        assert!(
            !lifecycle.begin_closing(),
            "a stopped runtime is not claimable either — `Running` is the only \
             state a teardown may start from, so a late caller cannot restart \
             one that has already finished"
        );
    }

    /// A loser waits for the winner and observes `Stopped`.
    ///
    /// The defect this closes: the loser used to return the moment it saw it
    /// had lost, so `shutdown_all` could finish while a concurrent removal was
    /// still awaiting an engine driver, and the daemon exited with that engine
    /// live.
    ///
    /// Deterministic and sleepless. The runtime is single-threaded, so a
    /// `yield_now` is enough to run the waiter up to its park, and
    /// `is_finished` after that yield is what makes the assertion
    /// discriminating: without it, a `await_stopped` that returned immediately
    /// would pass this test.
    #[tokio::test]
    async fn a_losing_caller_waits_for_the_winner_to_finish() {
        let lifecycle = Arc::new(Lifecycle::new());
        assert!(lifecycle.begin_closing(), "the winner claims it");

        let waiter = tokio::spawn({
            let lifecycle = Arc::clone(&lifecycle);
            async move { lifecycle.await_stopped().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "non-vacuity: the loser is genuinely parked while the runtime is \
             still `Closing`"
        );

        lifecycle.finish();
        assert_eq!(
            waiter.await.expect("the waiter task does not panic"),
            RuntimeState::Stopped,
            "and it wakes only once teardown finished, reporting what it saw"
        );
    }

    /// A wait that begins after the winner has already finished returns at
    /// once, rather than parking for a notification that will never come again.
    ///
    /// `Notify::notify_waiters` wakes only those already registered, so a
    /// caller that trusted the wake alone would hang here. The state is
    /// re-read, which is what makes the wake an optimisation rather than the
    /// mechanism.
    #[tokio::test]
    async fn a_wait_after_the_finish_returns_immediately() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.begin_closing());
        lifecycle.finish();

        assert_eq!(
            lifecycle.await_stopped().await,
            RuntimeState::Stopped,
            "the already-finished case is answered by the state, not by a \
             notification that has already been delivered to nobody"
        );
    }

    /// Several losers all wake, not just one.
    ///
    /// `notify_waiters` is the right primitive precisely because it releases
    /// every registered waiter; `notify_one` would leave a second concurrent
    /// removal parked forever behind a teardown that had already completed.
    #[tokio::test]
    async fn every_waiting_caller_is_released() {
        let lifecycle = Arc::new(Lifecycle::new());
        assert!(lifecycle.begin_closing());

        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let lifecycle = Arc::clone(&lifecycle);
                tokio::spawn(async move { lifecycle.await_stopped().await })
            })
            .collect();
        tokio::task::yield_now().await;
        assert!(
            waiters.iter().all(|waiter| !waiter.is_finished()),
            "non-vacuity: all four are parked before the finish"
        );

        lifecycle.finish();
        for waiter in waiters {
            assert_eq!(
                waiter.await.expect("no waiter panics"),
                RuntimeState::Stopped
            );
        }
    }

    #[tokio::test]
    async fn running_collision_refuses_newcomer_and_preserves_both_incumbent_aliases() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let incumbent = mesh
            .join(network("f13-running-config", "f13-running-wire"))
            .await
            .expect("incumbent joins");
        let same_config = mesh
            .join(network("f13-running-config", "f13-other-wire"))
            .await
            .expect("same-config newcomer joins independently");
        let same_network = mesh
            .join(network("f13-other-config", "f13-running-wire"))
            .await
            .expect("same-network newcomer joins independently");
        assert!(
            registry.insert(incumbent, None).into_refusal().is_none(),
            "the first runtime installs"
        );

        let refused_config = registry
            .insert(same_config, None)
            .into_refusal()
            .expect("a Running collision must not overwrite either alias");
        assert_eq!(refused_config.state, RuntimeState::Running);
        let refused_network = registry
            .insert(same_network, None)
            .into_refusal()
            .expect("a Running network-id collision must not overwrite either alias");
        assert_eq!(refused_network.state, RuntimeState::Running);
        let by_config = registry
            .get("f13-running-config")
            .expect("the incumbent config alias remains");
        let by_network = registry
            .get("f13-running-wire")
            .expect("the incumbent network alias remains");
        assert!(
            Arc::ptr_eq(&by_config, &by_network),
            "both incumbent aliases still name the same exact runtime"
        );
        assert_eq!(by_network.network_id(), "f13-running-wire");
        assert!(
            registry.get("f13-other-wire").is_none(),
            "the same-config newcomer did not install its distinct network alias"
        );
        assert!(
            registry.get("f13-other-config").is_none(),
            "the same-network newcomer did not install its distinct config alias"
        );
        let by_config_after = registry
            .get("f13-running-config")
            .expect("the incumbent config alias remains after both refusals");
        let by_network_after = registry
            .get("f13-running-wire")
            .expect("the incumbent network alias remains after both refusals");
        assert!(Arc::ptr_eq(&by_config_after, &by_network_after));
        assert!(Arc::ptr_eq(&by_config, &by_config_after));

        refused_config
            .joined
            .shutdown()
            .await
            .expect("the refused same-config runtime is explicitly retired");
        refused_network
            .joined
            .shutdown()
            .await
            .expect("the refused same-network runtime is explicitly retired");
        let _ = registry.shutdown_all().await;
    }

    #[tokio::test]
    async fn insert_racing_remove_waits_until_predecessor_is_stopped() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let incumbent = mesh
            .join(network("f13-race-config", "f13-race-wire"))
            .await
            .expect("incumbent joins");
        let replacement = mesh
            .join(network("f13-race-config", "f13-race-wire"))
            .await
            .expect("replacement joins independently");
        assert!(
            registry.insert(incumbent, None).into_refusal().is_none(),
            "the predecessor installs"
        );
        let predecessor = registry
            .state
            .lock()
            .find("f13-race-config")
            .expect("the predecessor is visible");
        let pause = registry.install_claim_pause_for_test();
        let remover = tokio::spawn({
            let registry = Arc::clone(&registry);
            async move { registry.remove("f13-race-config").await }
        });
        pause.reached.wait().await;

        assert_eq!(predecessor.lifecycle.state(), RuntimeState::Closing);
        assert!(registry.get("f13-race-config").is_none());
        assert!(registry.contains("f13-race-config"));
        let refused = registry
            .insert(replacement, None)
            .into_refusal()
            .expect("replacement installed before predecessor stopped");
        assert_eq!(refused.state, RuntimeState::Closing);

        pause.release.wait().await;
        assert!(matches!(
            remover.await.expect("remove task does not panic"),
            RemoveResult::Removed(Ok(()))
        ));
        assert_eq!(predecessor.lifecycle.state(), RuntimeState::Stopped);
        assert!(
            registry
                .insert(refused.joined, refused.drivers)
                .into_refusal()
                .is_none(),
            "the same replacement installs only after Stopped"
        );
        let installed = registry
            .get("f13-race-config")
            .expect("the replacement is now authoritative");
        assert_eq!(installed.network_id(), "f13-race-wire");
        let _ = registry.shutdown_all().await;
    }
}
