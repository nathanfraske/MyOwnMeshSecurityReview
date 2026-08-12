//! Every operation the registry performs on its tables.
//!
//! A descendant of the module that declares the state, which is what lets this
//! file hold the whole of `impl ClientRegistry` without a single field being
//! widened: a child sees its parent's private items, while a sibling or an
//! outside caller still sees only what the parent chose to publish. The tables,
//! the handle's own maps and the pending records stay exactly as private as they
//! were.
//!
//! The declarations stayed behind deliberately. What a `RegistryTables` *is* —
//! five leased maps under one lock — is a fact a reader needs before any of
//! this makes sense, and it belongs beside the claims that fund them. What the
//! registry *does* with them is this file, and it was two thirds of a file
//! nobody could hold in their head.
//!
//! Three helpers open the file rather than sitting in the parent, because all
//! three take `&mut RegistryTables` and have no meaning without it: they are
//! parts of these operations that happen to be shared between them.

use super::*;

/// Drop one client out of one channel's subscriber set, and drop the set itself
/// once it empties. Answers whether the channel now has no subscribers.
///
/// Removing the empty set is not tidiness: the previous shape left one behind
/// for every channel any client had ever subscribed to, so the table only ever
/// grew, and it grew on names local clients chose.
fn remove_channel_member(tables: &mut RegistryTables, key: &ClaimKey, client: ClientId) -> bool {
    let empty = match tables.channel_subs.get_mut(key) {
        Some(members) => {
            members.remove(&client);
            !members.any_value(|_| true)
        }
        None => return true,
    };
    if empty {
        tables.channel_subs.remove(key);
    }
    empty
}

/// Take every pending operation the predicate names, cancelling each as it comes
/// out of the table.
///
/// The records are returned rather than settled here, and the callers settle
/// them only after releasing the tables. Settling wakes the task waiting on the
/// operation, and waking it under this lock invites it straight back into a
/// method that takes the same lock — which this mutex, being unfair to no one
/// and reentrant for no one, would answer with a deadlock.
fn take_pending(
    tables: &mut RegistryTables,
    mut names: impl FnMut(&PendingKey, &PendingRecord) -> bool,
) -> Vec<PendingRecord> {
    let mut keys = Vec::new();
    tables.exact_pending_inbound.for_each(|key, pending| {
        if names(key, pending) {
            keys.push(key.clone());
        }
    });
    let mut taken = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(pending) = tables.exact_pending_inbound.remove(&key) {
            pending.cancelled.cancel();
            taken.push(pending);
        }
    }
    taken
}

/// Settle every taken operation truthfully, after the tables have been released.
///
/// A single-shot awaiter is told why in words that reach the calling peer. A
/// stream sender is dropped without a terminal item, which core reports to the
/// peer as a failed stream — correct, because it is one: the client that was
/// producing the stream is no longer entitled to finish it.
fn settle_taken(taken: Vec<PendingRecord>, reason: &str) {
    for pending in taken {
        match pending.effect {
            PendingInbound::Single(tx) => {
                let _ = tx.send(Err(reason.to_string()));
            }
            PendingInbound::Stream(tx) => drop(tx),
        }
    }
}

impl ClientRegistry {
    /// One registry over one acquisition port.
    ///
    /// It used to be `with_stream_capacity`, and took a mandatory item count for
    /// the inbound RPC stream queue. That queue is a resource mailbox now and
    /// has no item count to select, so there was nothing left for the argument
    /// to mean.
    pub fn new(resources: LocalApplicationResourceScope) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                resources,
                next_id: AtomicU64::new(0),
                next_call_stream_id: AtomicU64::new(0),
                next_operation_id: AtomicU64::new(0),
                tables: Mutex::new(RegistryTables {
                    clients: LeasedMap::new(),
                    handler_claims: LeasedMap::new(),
                    channel_subs: LeasedMap::new(),
                    exact_pending_inbound: LeasedMap::new(),
                    installed_handlers: LeasedMap::new(),
                }),
            }),
        }
    }

    /// Issue one acquisition subtree under this registry's own port.
    ///
    /// For things with a lifetime of their own — an inbound stream's queue is
    /// the one caller today — so that everything the thing holds is released as
    /// a unit when it ends, rather than lingering in the registry's scope until
    /// the daemon stops.
    pub fn child_resources(&self) -> Result<LocalApplicationResourceScope, IpcAdmissionError> {
        self.inner
            .resources
            .child()
            .map_err(IpcAdmissionError::Resources)
    }

    /// Fund one task this registry keeps alive, before it is spawned.
    ///
    /// The lease must be **moved into the task's own future**, so that it is
    /// released exactly when the task stops running — including when the task
    /// is dropped mid-await rather than returning. A lease held anywhere else
    /// would report the task as funded for a lifetime that is not the task's.
    ///
    /// Acquired before `tokio::spawn` rather than inside the future, because a
    /// task that started and then discovered it was unfunded would already be
    /// consuming a runtime worker — the refusal has to happen while there is
    /// still nothing to clean up.
    ///
    /// One owner for all four IPC task kinds — the accepted connection, the
    /// channel pump, the inbound stream watchdog, and the outbound
    /// stream-forwarding task — so the process owner sees one number for daemon
    /// IPC concurrency instead of four that have to be added up.
    pub fn lease_task(&self) -> Result<ResourceLease, IpcAdmissionError> {
        self.inner
            .resources
            .acquire(task_claim().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)
    }

    /// Allocate a fresh `ClientId` and register the client's outbound writer.
    /// Returns the handle the read loop should keep alongside its socket.
    ///
    /// Registration is an admission and can be refused. Both of the things this
    /// installs — the handle's own record and the registry's index node for it —
    /// are funded before the id is consumed, so a refusal leaves no gap in the
    /// id space and nothing partially installed: the caller sees the provider's
    /// own reason and the registry is exactly as it was.
    ///
    /// Two claims rather than one because they are released at two different
    /// moments. The record's lease lives in the handle and goes when the last
    /// reference to it does; the index node's lease lives in the table and goes
    /// when the client is unregistered, which can be earlier.
    ///
    /// The refusal reaches an IPC client as a failed `EventsSubscribe`, which
    /// is the truthful answer — the daemon cannot carry this connection's
    /// outbound stream, and a client told it had subscribed would wait forever
    /// for frames nothing was funded to send it.
    pub fn register(
        &self,
        writer_tx: ResourceMailboxSender<ServerOut>,
    ) -> Result<Arc<ClientHandle>, IpcAdmissionError> {
        let record = self
            .inner
            .resources
            .acquire(client_record_claim().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)?;
        let entry = self.inner.lease_entry::<ClientId, Arc<ClientHandle>>()?;
        let id = ClientId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let handle = Arc::new(ClientHandle {
            id,
            capability: ClientCapability::mint(),
            connected: AtomicBool::new(true),
            disconnected: tokio::sync::Notify::new(),
            writer_tx,
            method_claims: HeldNames::default(),
            channel_subs: HeldNames::default(),
            _record: record,
            realtime_flows: Mutex::new(LeasedMap::new()),
        });
        self.inner
            .tables
            .lock()
            .clients
            .insert(id, handle.clone(), entry)
            // The counter above is monotonic and never reset, so the id in hand
            // has never been issued before and cannot already be in the table.
            .expect("client ids are issued once and never reused");
        Ok(handle)
    }

    pub fn capability<'a>(&self, client: &'a ClientHandle) -> &'a str {
        client.capability.expose()
    }

    pub fn authenticate(&self, id: ClientId, presented: &str) -> Option<Arc<ClientHandle>> {
        let client = self.client(id)?;
        client.capability.matches(presented).then_some(client)
    }

    /// Install a completed realtime open only while its event-stream owner is
    /// still registered. This shares the registry table seam with
    /// [`Self::unregister`]: install-first means the disconnect drain observes
    /// and closes the flow; disconnect-first returns the move-only handle to
    /// the caller, which must close it directly.
    ///
    /// The flow's table entry is funded before the flow is filed, and the
    /// refusal hands the handle back exactly as the disconnect race does. Both
    /// mean the same thing to the caller — this flow was never installed, and
    /// closing it is yours — which is why one `Err` shape carries both.
    pub fn install_realtime_flow(
        &self,
        owner: &Arc<ClientHandle>,
        network: String,
        flow: myownmesh_core::realtime::RealtimeFlowHandle,
    ) -> Result<RealtimeFlowCapability, RealtimeFlowRejected> {
        self.install_if_live(
            owner,
            LeasedMap::<String, OwnedRealtimeFlow>::entry_claim(),
            flow,
            |flow, entry| owner.register_realtime_flow(network, flow, entry),
        )
        .map_err(|(flow, reason)| RealtimeFlowRejected { flow, reason })
    }

    /// Run `install` only while `owner` is still a registered, connected client
    /// of this registry — under one acquisition of the tables, so a disconnect
    /// cannot land between the check and the install.
    ///
    /// `install` receives the funding for the one table entry it files. The
    /// lease is acquired inside the seam rather than before it, so a value that
    /// is never installed is never funded either.
    ///
    /// Both failures hand `value` straight back, because the caller's obligation
    /// is the same in both: nothing was installed, and whatever `value` holds is
    /// now the caller's alone to release. They differ only in what there is to
    /// say about it.
    ///
    /// Generic over the value rather than written out for the one production
    /// caller, because a real `RealtimeFlowHandle` is `pub(crate)` to core and
    /// cannot be minted from this crate. The ordering that matters lives here,
    /// so the controls drive it with a stand-in value.
    ///
    /// `pub(super)` for exactly that reason and no other: the controls are a
    /// sibling module, and a sibling sees only what this one publishes. It
    /// reaches no further than the module tree that owns the registry, so
    /// nothing outside can install past the disconnect seam.
    pub(super) fn install_if_live<T, R>(
        &self,
        owner: &Arc<ClientHandle>,
        entry_claim: Result<ResourceClaim, ResourceClaimArithmeticError>,
        value: T,
        install: impl FnOnce(T, ResourceLease) -> R,
    ) -> Result<R, (T, RegistrationError)> {
        let tables = self.inner.tables.lock();
        let live = match tables.client(owner.id) {
            Some(current) => {
                Arc::ptr_eq(&current, owner) && owner.connected.load(Ordering::Acquire)
            }
            None => false,
        };
        if !live {
            return Err((value, RegistrationError::ClientGone));
        }
        let entry = match entry_claim
            .map_err(IpcAdmissionError::Claim)
            .and_then(|claim| {
                self.inner
                    .resources
                    .acquire(claim)
                    .map_err(IpcAdmissionError::Resources)
            }) {
            Ok(entry) => entry,
            Err(refusal) => return Err((value, refusal.into())),
        };
        // Still holding the tables, which is the whole point of taking them.
        Ok(install(value, entry))
    }

    /// Remove one exact connection owner, all its claims and subscriptions,
    /// and every pending operation it owns. A stream sender disappearing
    /// without an explicit terminal item is a peer-visible failure in core.
    ///
    /// Answers which methods it was the last claimant of. Those synthetic
    /// handlers used to be left installed on the engine forever, on the reasoning
    /// that a future claimant might re-take the method and save the install. That
    /// traded a bounded, once-per-claim cost for an unbounded one: a client could
    /// claim a thousand methods, disconnect, and leave a thousand handlers — each
    /// holding its own retention in the network's gateway scope — installed for a
    /// method nobody serves. What the engine kept is not free, and it is not this
    /// registry's to spend.
    pub fn unregister(&self, id: ClientId) -> Option<UnregisteredClient> {
        let mut tables = self.inner.tables.lock();
        let handle = tables.clients.remove(&id)?;
        handle.connected.store(false, Ordering::Release);
        handle.disconnected.notify_waiters();
        // Method claims this client owned, dropped only where it still owns
        // them: a displacing client may already have taken one over, and that
        // claimant's handler is not ours to forget.
        let mut forget = Vec::new();
        for key in handle.method_claims.snapshot() {
            handle.method_claims.release(&key);
            if tables.handler_claims.get(&key) != Some(&id) {
                continue;
            }
            tables.handler_claims.remove(&key);
            if tables.installed_handlers.remove(&key).is_some() {
                forget.push(key);
            }
        }
        // Channel subscriptions. The fan-out task running for this
        // (network, channel) notices the empty subscriber set and exits on its
        // next iteration; an emptied set is removed with its last member.
        for key in handle.channel_subs.snapshot() {
            handle.channel_subs.release(&key);
            remove_channel_member(&mut tables, &key, id);
        }
        let taken = take_pending(&mut tables, |_, pending| pending.owner == id);
        drop(tables);
        settle_taken(taken, "local IPC handler disconnected");
        Some(UnregisteredClient { handle, forget })
    }

    pub fn client(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        self.inner.tables.lock().client(id)
    }

    /// Unregister every client and answer what each one left behind.
    ///
    /// Returned rather than dropped because some of what a client owns cannot be
    /// released by dropping it: realtime flows, whose handles are non-owning and
    /// whose closes have to run through a joined network and await, and the
    /// synthetic handlers it was the last claimant of, which live on the engine
    /// rather than here. This module has neither a network nor an await, so it
    /// hands both back to the caller that does.
    #[must_use = "a shut-down client's realtime flows and orphaned handlers still have to be released through their networks"]
    pub fn shutdown(&self) -> Vec<UnregisteredClient> {
        let ids = {
            let tables = self.inner.tables.lock();
            let mut ids = Vec::new();
            tables.clients.for_each(|id, _| ids.push(*id));
            ids
        };
        let removed: Vec<UnregisteredClient> = ids
            .into_iter()
            .filter_map(|client| self.unregister(client))
            .collect();
        // Defensive: handler futures can race shutdown after the client
        // snapshot. Dropping a stream entry without End is explicitly failed
        // by core; dropping a single sender wakes its waiter with cancellation.
        let mut tables = self.inner.tables.lock();
        let stranded = take_pending(&mut tables, |_, _| true);
        drop(tables);
        drop(stranded);
        removed
    }

    /// Claim a method on a network. Answers the previously claiming client if
    /// any, so the caller can notify them with `HandlerDisplaced`.
    ///
    /// Three tables are written and each one's entry is funded first, before any
    /// of them is touched. A refusal therefore leaves the registry exactly as it
    /// was rather than half-claimed — a method routed to a client its own
    /// disconnect path would never clean up.
    ///
    /// Funding is skipped where the entry already exists, because a re-claim
    /// writes over a value and writing over a value allocates no node. That
    /// check and the write that follows it happen under one acquisition of the
    /// tables, so nothing can slip in between and make the skip wrong.
    pub fn claim_method(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
    ) -> Result<Option<ClientId>, RegistrationError> {
        let mut tables = self.inner.tables.lock();
        let Some(client) = tables.client(new_owner) else {
            return Err(RegistrationError::ClientGone);
        };
        let claim_entry = match tables.handler_claims.contains_key(&key) {
            true => None,
            false => Some(self.inner.lease_entry::<ClaimKey, ClientId>()?),
        };
        let installed_entry = match tables.installed_handlers.contains_key(&key) {
            true => None,
            false => Some(self.inner.lease_entry::<ClaimKey, HandlerMode>()?),
        };
        let held_entry = match client.method_claims.holds(&key) {
            true => None,
            false => Some(self.inner.lease_entry::<ClaimKey, ()>()?),
        };
        // Nothing below can fail, so from here the claim is installed whole.
        // The per-client cache goes first so on-disconnect cleanup sees the new
        // claim even if it runs the instant this lock is released.
        if let Some(entry) = held_entry {
            client.method_claims.hold(key.clone(), entry);
        }
        let prev = match claim_entry {
            Some(entry) => {
                tables
                    .handler_claims
                    .insert(key.clone(), new_owner, entry)
                    .expect("absence was established while these tables were held");
                None
            }
            None => tables
                .handler_claims
                .get_mut(&key)
                .map(|owner| std::mem::replace(owner, new_owner)),
        };
        match installed_entry {
            Some(entry) => {
                tables
                    .installed_handlers
                    .insert(key.clone(), mode, entry)
                    .expect("absence was established while these tables were held");
            }
            None => {
                if let Some(installed) = tables.installed_handlers.get_mut(&key) {
                    *installed = mode;
                }
            }
        }
        let Some(prev_owner) = prev else {
            return Ok(None);
        };
        if prev_owner == new_owner {
            return Ok(None);
        }
        if let Some(prev_client) = tables.client(prev_owner) {
            prev_client.method_claims.release(&key);
        }
        // Everything the displaced owner had in flight on this exact method.
        // Taken under the same acquisition that moved the claim, so no call can
        // be admitted to an owner that has just stopped being one.
        let displaced = take_pending(&mut tables, |pending_key, pending| {
            pending.owner == prev_owner
                && pending_key.network == key.0
                && pending_key.method == key.1
        });
        drop(tables);
        settle_taken(displaced, "local IPC handler displaced");
        Ok(Some(prev_owner))
    }

    /// Release a method claim, and say whether the engine's synthetic handler
    /// for it is now owned by nobody.
    pub fn release_method(&self, key: &ClaimKey, owner: ClientId) -> MethodRelease {
        let mut tables = self.inner.tables.lock();
        if let Some(client) = tables.client(owner) {
            client.method_claims.release(key);
        }
        if tables.handler_claims.get(key) != Some(&owner) {
            return MethodRelease {
                released: false,
                forget: false,
            };
        }
        tables.handler_claims.remove(key);
        // This was the claim, and a claim is the only thing an installed
        // handler serves, so removing the record and reporting the handler
        // forgettable are the same event.
        let forget = tables.installed_handlers.remove(key).is_some();
        MethodRelease {
            released: true,
            forget,
        }
    }

    pub fn handler_owner(&self, key: &ClaimKey) -> Option<ClientId> {
        self.inner.tables.lock().handler_claims.get(key).copied()
    }

    #[allow(dead_code)]
    pub fn handler_mode(&self, key: &ClaimKey) -> Option<HandlerMode> {
        self.inner
            .tables
            .lock()
            .installed_handlers
            .get(key)
            .copied()
    }

    /// Subscribe one client to one channel. Answers `true` on the FIRST
    /// subscriber for this (network, channel) — the caller uses that signal to
    /// spawn a new pump task.
    ///
    /// Up to three entries, funded before any is installed, for the same reason
    /// [`Self::claim_method`] funds first: a half-installed subscription is a
    /// client that receives channel traffic its disconnect will not stop.
    pub fn subscribe_channel(
        &self,
        key: ClaimKey,
        client: ClientId,
    ) -> Result<bool, RegistrationError> {
        let mut tables = self.inner.tables.lock();
        let Some(c) = tables.client(client) else {
            return Err(RegistrationError::ClientGone);
        };
        let already_member = match tables.channel_subs.get(&key) {
            Some(members) => members.contains_key(&client),
            None => false,
        };
        let held_entry = match c.channel_subs.holds(&key) {
            true => None,
            false => Some(self.inner.lease_entry::<ClaimKey, ()>()?),
        };
        let set_entry = match tables.channel_subs.contains_key(&key) {
            true => None,
            false => Some(
                self.inner
                    .lease_entry::<ClaimKey, LeasedMap<ClientId, ()>>()?,
            ),
        };
        let member_entry = match already_member {
            true => None,
            false => Some(self.inner.lease_entry::<ClientId, ()>()?),
        };
        // Nothing below can fail.
        if let Some(entry) = held_entry {
            c.channel_subs.hold(key.clone(), entry);
        }
        if let Some(entry) = set_entry {
            tables
                .channel_subs
                .insert(key.clone(), LeasedMap::new(), entry)
                .expect("absence was established while these tables were held");
        }
        let members = tables
            .channel_subs
            .get_mut(&key)
            .expect("the subscriber set exists or was just inserted");
        // Read before the insert: the answer is whether this client is the one
        // that made the channel live, not whether it ended up in the set.
        let was_empty = !members.any_value(|_| true);
        if let Some(entry) = member_entry {
            members
                .insert(client, (), entry)
                .expect("absence was established while these tables were held");
        }
        Ok(was_empty)
    }

    /// Release a subscription. Answers `true` if no clients remain on this
    /// channel — the caller uses that signal to tear down the pump task.
    pub fn unsubscribe_channel(&self, key: &ClaimKey, client: ClientId) -> bool {
        let mut tables = self.inner.tables.lock();
        if let Some(c) = tables.client(client) {
            c.channel_subs.release(key);
        }
        remove_channel_member(&mut tables, key, client)
    }

    /// Snapshot the current set of subscribers — used by the
    /// channel pump task each iteration.
    pub fn channel_subscribers(&self, key: &ClaimKey) -> Vec<ClientId> {
        let tables = self.inner.tables.lock();
        let Some(members) = tables.channel_subs.get(key) else {
            return Vec::new();
        };
        let mut subscribers = Vec::new();
        members.for_each(|client, _| subscribers.push(*client));
        subscribers
    }

    /// Monotonic counter used to tag outbound stream calls.
    /// The lib's `Rpc::call_stream` allocates its own request
    /// id internally but doesn't expose it; the IPC layer
    /// generates its own correlation id so clients can match
    /// chunks back to their originating call.
    pub fn next_call_stream_id(&self) -> u64 {
        self.inner
            .next_call_stream_id
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Track one inbound call so a later `RpcRespond` or stream frame can settle
    /// it, and answer the ticket that owns its removal.
    ///
    /// The refusal says which of the three things went wrong and hands the
    /// engine-side awaiter back. That distinction reaches the calling peer: a
    /// duplicate is the peer's own coordinates colliding, an absent owner is a
    /// local client that left, and a refusal is the daemon out of the capacity
    /// this call would need. Reporting all three as a duplicate — which is what
    /// a bare `Err(effect)` left the caller to do — told the peer to fix
    /// something that was not wrong.
    pub fn insert_exact_pending(
        &self,
        key: PendingKey,
        owner: ClientId,
        effect: PendingInbound,
    ) -> Result<PendingTicket, PendingRejected> {
        let mut tables = self.inner.tables.lock();
        if tables.client(owner).is_none() {
            return Err(PendingRejected {
                effect,
                reason: PendingRefusal::OwnerGone,
            });
        }
        if tables.exact_pending_inbound.contains_key(&key) {
            return Err(PendingRejected {
                effect,
                reason: PendingRefusal::Duplicate,
            });
        }
        let entry = match self.inner.lease_entry::<PendingKey, PendingRecord>() {
            Ok(entry) => entry,
            Err(refusal) => {
                return Err(PendingRejected {
                    effect,
                    reason: refusal.into(),
                })
            }
        };
        let operation_id = self.inner.next_operation_id.fetch_add(1, Ordering::Relaxed);
        let ticket_key = key.clone();
        let cancelled = Arc::new(PendingCancellation {
            cancelled: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        tables
            .exact_pending_inbound
            .insert(
                key,
                PendingRecord {
                    owner,
                    operation_id,
                    effect,
                    cancelled: cancelled.clone(),
                },
                entry,
            )
            .expect("absence was established while these tables were held");
        Ok(PendingTicket {
            registry: Arc::downgrade(&self.inner),
            key: ticket_key,
            operation_id,
            cancelled,
        })
    }

    /// Settle one single-shot operation, with success or with the client's
    /// error. `true` only if that exact operation was pending and this caller
    /// owned it: the key, the owner and the private operation id must all
    /// match, and the record must be of the single-shot class.
    ///
    /// The class check is what stops a `RpcRespond` from terminating a stream
    /// that happens to share every public coordinate with it.
    pub fn resolve_exact_single(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        result: Result<serde_json::Value, String>,
    ) -> bool {
        let mut tables = self.inner.tables.lock();
        let ours = match tables.exact_pending_inbound.get(key) {
            Some(pending) => {
                pending.owner == owner
                    && pending.operation_id == operation_id
                    && matches!(&pending.effect, PendingInbound::Single(_))
            }
            None => false,
        };
        if !ours {
            return false;
        }
        let pending = tables
            .exact_pending_inbound
            .remove(key)
            .expect("the record was present while these tables were held");
        // Cancelled under the tables, like every other terminal path, so a
        // concurrent chunk that already holds a cloned sender sees a settled
        // operation. Released before the waiter is woken: resolving the oneshot
        // resumes a task that goes straight back into this registry, and this
        // lock is not reentrant.
        pending.cancelled.cancel();
        drop(tables);
        let PendingInbound::Single(tx) = pending.effect else {
            unreachable!("the response class was checked before removal")
        };
        let _ = tx.send(result);
        true
    }

    /// Push one chunk into an in-flight stream. `true` if it was accepted.
    ///
    /// Synchronous, and that is the whole shape of this function now. It used
    /// to await, because a bounded channel made a full queue something to wait
    /// on — and that wait was what created the race this had to be `biased`
    /// about: the sender was cloned out, the map guard released, and a
    /// settlement landing meanwhile could no longer be seen by looking the
    /// record up again. The queue is resource-bounded rather than
    /// count-bounded now, so admission is decided immediately and there is no
    /// interval for a settlement to land in.
    ///
    /// Cancellation is still checked, because it is still a real answer: every
    /// terminal path — [`Self::close_exact_stream`], [`Self::unregister`],
    /// displacement, and dropping the [`PendingTicket`] — cancels while holding
    /// the registry's tables, before its own terminal item goes out. Reading it
    /// here means a settled stream refuses a late chunk rather than writing one
    /// after the `End` its peer has already been told is final.
    ///
    /// A refusal from the mailbox itself — the provider would not fund this
    /// chunk's retention — answers `false` too. The client learns its chunk was
    /// not accepted, which is the truthful outcome and the one the old bounded
    /// queue expressed by blocking instead.
    pub fn push_exact_stream(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        payload: serde_json::Value,
    ) -> bool {
        let (tx, cancelled) = {
            let tables = self.inner.tables.lock();
            match tables.exact_pending_inbound.get(key) {
                Some(pending) if pending.owner == owner && pending.operation_id == operation_id => {
                    match &pending.effect {
                        PendingInbound::Stream(tx) => (tx.clone(), pending.cancelled.clone()),
                        _ => return false,
                    }
                }
                _ => return false,
            }
        };
        if cancelled.is_cancelled() {
            return false;
        }
        tx.send(myownmesh_core::rpc::RpcStreamItem::Chunk(payload))
            .is_ok()
    }

    /// Terminate one in-flight stream, cleanly or with the client's error.
    ///
    /// The record is removed and its cancellation fired inside one write
    /// acquisition, before the terminal item is sent, so no chunk still parked
    /// on a full queue can overtake it.
    ///
    /// [`RpcStreamItem::End`] is sent rather than the sender merely dropped:
    /// the error the client supplied is the point, and a drop would report
    /// every ending as the same failure.
    ///
    /// [`RpcStreamItem::End`]: myownmesh_core::rpc::RpcStreamItem::End
    pub fn close_exact_stream(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        error: Option<String>,
    ) -> bool {
        let mut tables = self.inner.tables.lock();
        let ours = match tables.exact_pending_inbound.get(key) {
            Some(pending) => {
                pending.owner == owner
                    && pending.operation_id == operation_id
                    && matches!(&pending.effect, PendingInbound::Stream(_))
            }
            None => false,
        };
        if !ours {
            return false;
        }
        let pending = tables
            .exact_pending_inbound
            .remove(key)
            .expect("the record was present while these tables were held");
        pending.cancelled.cancel();
        drop(tables);
        let PendingInbound::Stream(tx) = pending.effect else {
            unreachable!("the response class was checked before removal")
        };
        tx.send(myownmesh_core::rpc::RpcStreamItem::End(
            error.map_or(Ok(()), Err),
        ))
        .is_ok()
    }
}

/// One registry over the daemon's test grant, for controls.
///
/// The fixture entry point, and the only one: production calls
/// [`ClientRegistry::new`] with the scope its owner issued it, and a `Default`
/// that reached for a scope of its own would be a registry admitting clients
/// nobody granted capacity for. This is not compiled into the daemon.
#[cfg(test)]
impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new(crate::test_application_scope())
    }
}
