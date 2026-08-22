//! The promoted session itself, and the one slot a peer entry holds it in.
//!
//! Installation, reuse and revocation live here together because they are one
//! rule seen from three sides: a session is usable exactly while every use-time
//! conjunct still holds, and one that fails a conjunct is destroyed rather than
//! merely refused.

use std::sync::Arc;

use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass};
use crate::runtime::session_broker::SessionCapability;

use super::PeerSessionState;

use super::DedupToken;

/// One promoted session and everything promotion built under it.
///
/// Bundled rather than adjacent so their lifetimes cannot separate. The flow
/// set's name namespace and the reliable stream's sequence space are only
/// meaningful for the exact session that owns them, and the session is only
/// reachable while its connector is current — so the three die together or two
/// of them outlive their meaning.
///
/// The fields are private and are lent in pairs, never handed out. An operation
/// therefore cannot pair one session's authority with another session's state:
/// it receives the authority and the state from the same borrow of the same
/// bundle.
pub(crate) struct PromotedChannel {
    session: SessionCapability,
    /// Opaque to the engine. Constructed by the worker the session was promoted
    /// from, so the flows draw on that exact connector's registry; the engine
    /// never names a label table, a flow, or a port.
    flows: crate::transport::webrtc::SessionRealtimeFlows,
    worker: Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    /// The exact Endpoint Auth task that minted this channel's capability.
    ///
    /// Production promotions always install `Some`. The `None` form exists only
    /// for the transport-lab helper that installs an already-authenticated
    /// capability directly so legacy admission controls can exercise the
    /// promotion fence without counterfeiting an Endpoint Auth exchange.
    endpoint_auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    correlation: String,
    dedup: Option<DedupToken>,
    additional_dedup: Vec<DedupToken>,
}

/// Exact identity and lifecycle custody for one promoted channel. Grouping the
/// fields keeps promotion/install call sites from accidentally separating the
/// worker, Endpoint Auth task, correlation, and their dedup ownership.
pub(crate) struct PromotedChannelBinding {
    pub(crate) worker: Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    pub(crate) endpoint_auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    pub(crate) correlation: String,
    pub(crate) dedup: Option<DedupToken>,
    pub(crate) additional_dedup: Vec<DedupToken>,
}

pub(crate) struct PromotedSession {
    selected: usize,
    channels: Vec<PromotedChannel>,
    app: PeerSessionState,
}

impl PromotedSession {
    /// The post-authentication reservation one promoted session holds, derived
    /// from the record promotion actually builds.
    ///
    /// It lives here, beside [`PromotedSessionSlot::install`], because this is
    /// the module that allocates the thing being paid for. A claim written
    /// anywhere else would be a second statement of this record's shape, and the
    /// two would drift the first time a field is added.
    ///
    /// Two terms, no more:
    ///
    /// * `size_of::<Self>()` — the whole record in one reading. It covers the
    ///   session capability (and with it the authenticated channel it owns by
    ///   value, the shared principal handle, the connector identity and the
    ///   permit carrying this very reservation), the realtime flow set's own
    ///   inline shape, and this session's application state — its reliable
    ///   stream id, sequence, empty queue handle, inbound mark and empty advert
    ///   slot. One `size_of` over the bundle cannot double-count what three
    ///   `size_of`s over its fields might, and cannot miss a field added later.
    /// * the heap `SessionRealtimeFlows::new` allocates for the refcounted roots
    ///   the set is built from. Their number and types are the connector's to
    ///   state: `promotion_root_claim` lives beside `new`, so the roots and
    ///   their charge are read and written in one place. Restating either here —
    ///   a count especially — would go stale the first time a root moves.
    ///
    /// The application state contributes no third term, and that is a property
    /// of the record rather than an omission: at promotion its queue is empty
    /// and holds no node, and its advert slot is empty and holds no buffer.
    /// Everything either of them later retains is funded at the moment it is
    /// retained, by [`SessionCapability::reserve_retained`], and released when it
    /// is not. Pre-paying for them here would be the fixed ceiling this design
    /// exists to remove.
    ///
    /// Two exclusions are by design. The flow registry the set holds is the
    /// connector's own and preexisting — promotion clones a handle, it does not
    /// allocate the registry — so charging it would bill a session for something
    /// that outlives it. And every per-flow, queue and payload lease is charged
    /// where it is taken; a session that opens no flow must not pre-pay for
    /// flows.
    ///
    /// Deliberately not derived from anything measured before authentication: a
    /// pre-authentication lease is not proof that this capacity exists.
    pub(crate) fn promotion_claim(
    ) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record = u64::try_from(std::mem::size_of::<Self>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([(ResourceClass::AccountedMemoryBytes, record)])?
            .checked_add(crate::transport::webrtc::SessionRealtimeFlows::promotion_root_claim()?)
    }

    /// The authority and the realtime flow set it owns.
    fn selected(&self) -> &PromotedChannel {
        &self.channels[self.selected]
    }

    fn selected_mut(&mut self) -> &mut PromotedChannel {
        &mut self.channels[self.selected]
    }

    pub(crate) fn selected_worker(&self) -> &Arc<crate::transport::webrtc::WebRtcConnectorWorker> {
        &self.selected().worker
    }

    pub(crate) fn contains_worker(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> bool {
        self.channels
            .iter()
            .any(|channel| Arc::ptr_eq(&channel.worker, worker))
    }

    pub(crate) fn endpoint_auth_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        self.channels
            .iter()
            .find(|channel| Arc::ptr_eq(&channel.worker, worker))
            .and_then(|channel| channel.endpoint_auth.as_ref().map(Arc::clone))
    }

    pub(crate) fn correlation_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<String> {
        self.channels
            .iter()
            .find(|channel| Arc::ptr_eq(&channel.worker, worker))
            .map(|channel| channel.correlation.clone())
    }

    pub(crate) fn flows_mut(
        &mut self,
    ) -> (
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
        &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) {
        let channel = self.selected_mut();
        (&channel.session, &mut channel.flows, &channel.worker)
    }

    pub(crate) fn flows_for_worker_mut(
        &mut self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<(
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
        &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    )> {
        let channel = self
            .channels
            .iter_mut()
            .find(|channel| Arc::ptr_eq(&channel.worker, worker))?;
        Some((&channel.session, &mut channel.flows, &channel.worker))
    }

    pub(crate) fn flows_for_worker_with_correlation_mut(
        &mut self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<(
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
        &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        &str,
    )> {
        let channel = self
            .channels
            .iter_mut()
            .find(|channel| Arc::ptr_eq(&channel.worker, worker))?;
        Some((
            &channel.session,
            &mut channel.flows,
            &channel.worker,
            channel.correlation.as_str(),
        ))
    }

    /// The authority and the application state it owns.
    pub(crate) fn app_mut(&mut self) -> (&SessionCapability, &mut PeerSessionState) {
        (&self.channels[self.selected].session, &mut self.app)
    }
}

pub(crate) struct RemovedPromotedChannel {
    pub(crate) worker: Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    pub(crate) dedup: Option<DedupToken>,
    pub(crate) additional_dedup: Vec<DedupToken>,
    pub(crate) selected_worker: Option<Arc<crate::transport::webrtc::WebRtcConnectorWorker>>,
    pub(crate) selected_correlation: Option<String>,
    pub(crate) session_empty: bool,
}

/// The one slot a peer entry holds its promoted session in, and the use and
/// revocation rules that govern it.
///
/// The rules live here rather than at each call site because there is exactly
/// one of them and it must be identical everywhere: a session is usable only
/// while every use-time conjunct still holds, and a session that fails one is
/// **dropped**, not merely refused. Refusing alone would leave a revoked session
/// holding its post-authentication reservation and its retained frames, waiting
/// on a peer that will never acknowledge them, until some unrelated path
/// happened to notice.
///
/// Dropping the bundle is also the only retirement signal there is: it closes
/// the flow-owned queues, resolves every caller still waiting on a retained
/// frame, and releases the reservation. There is no separate retirement event
/// and no second place that has to remember.
pub(crate) struct PromotedSessionSlot {
    slot: parking_lot::Mutex<Option<PromotedSession>>,
}

impl PromotedSessionSlot {
    pub(crate) fn new() -> Self {
        Self {
            slot: parking_lot::Mutex::new(None),
        }
    }

    /// Whether a session is installed at all.
    ///
    /// Says nothing about whether it is still usable — that question is only
    /// answerable together with the conjuncts, which is what [`Self::with_live`]
    /// is for. Callers wanting "is this peer past promotion" want this; callers
    /// wanting to *do* something want the lender.
    pub(crate) fn is_installed(&self) -> bool {
        self.slot.lock().is_some()
    }

    pub(crate) fn channel_count(&self) -> usize {
        self.slot
            .lock()
            .as_ref()
            .map_or(0, |session| session.channels.len())
    }

    /// Drop whatever is installed.
    ///
    /// The connector-retirement and entry-teardown edge. A session promoted
    /// under a retired connector must not survive into its replacement, and
    /// dropping it is what releases its reservation and answers its callers.
    pub(crate) fn clear(&self) {
        drop(self.slot.lock().take());
    }

    pub(crate) fn take_workers_with_dedup(
        &self,
    ) -> Vec<(
        Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        Option<DedupToken>,
        Vec<DedupToken>,
    )> {
        self.slot
            .lock()
            .take()
            .map(|session| {
                session
                    .channels
                    .into_iter()
                    .map(|channel| {
                        if let Some(task) = channel.endpoint_auth {
                            task.retire();
                        }
                        (channel.worker, channel.dedup, channel.additional_dedup)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Install a freshly promoted session, replacing anything present.
    ///
    /// Replacement is correct rather than merely tolerated: the only caller
    /// promotes after this slot was found empty or revoked under the registry's
    /// mutation lock, which serializes promotion, and anything that appeared in
    /// the meantime would be a session this one supersedes.
    ///
    /// Infallible, and deliberately: every step that could refuse has already
    /// run inside `promote`, while the authenticated channel was still in its
    /// slot and a refusal was still retryable. Nothing here can fail late.
    pub(crate) fn install(
        &self,
        session: SessionCapability,
        flows: crate::transport::webrtc::SessionRealtimeFlows,
        binding: PromotedChannelBinding,
    ) {
        let PromotedChannelBinding {
            worker,
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
        } = binding;
        *self.slot.lock() = Some(PromotedSession {
            selected: 0,
            channels: vec![PromotedChannel {
                session,
                flows,
                worker,
                endpoint_auth,
                correlation,
                dedup,
                additional_dedup,
            }],
            app: PeerSessionState::new(),
        });
    }

    pub(crate) fn add_channel(
        &self,
        mut session: SessionCapability,
        flows: crate::transport::webrtc::SessionRealtimeFlows,
        binding: PromotedChannelBinding,
        select: bool,
    ) -> Result<(), (Option<DedupToken>, Vec<DedupToken>)> {
        let PromotedChannelBinding {
            worker,
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
        } = binding;
        let mut slot = self.slot.lock();
        let Some(promoted) = slot.as_mut() else {
            return Err((dedup, additional_dedup));
        };
        if promoted.contains_worker(&worker) {
            return Err((dedup, additional_dedup));
        }
        session.join_logical_session(&promoted.selected().session);
        promoted.channels.push(PromotedChannel {
            session,
            flows,
            worker,
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
        });
        if select {
            promoted.selected = promoted.channels.len() - 1;
        }
        Ok(())
    }

    pub(crate) fn contains_worker(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> bool {
        self.slot
            .lock()
            .as_ref()
            .is_some_and(|session| session.contains_worker(worker))
    }

    pub(crate) fn endpoint_auth_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        self.slot
            .lock()
            .as_ref()
            .and_then(|session| session.endpoint_auth_for(worker))
    }

    pub(crate) fn correlation_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<String> {
        self.slot
            .lock()
            .as_ref()
            .and_then(|session| session.correlation_for(worker))
    }

    pub(crate) fn retain_dedup_for_worker(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        token: DedupToken,
    ) -> bool {
        let mut slot = self.slot.lock();
        let Some(session) = slot.as_mut() else {
            return false;
        };
        let Some(channel) = session
            .channels
            .iter_mut()
            .find(|channel| Arc::ptr_eq(&channel.worker, worker))
        else {
            return false;
        };
        channel.additional_dedup.push(token);
        true
    }

    pub(crate) fn remove_channel(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<RemovedPromotedChannel> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        let index = promoted
            .channels
            .iter()
            .position(|channel| Arc::ptr_eq(&channel.worker, worker))?;
        let was_selected = index == promoted.selected;
        let channel = promoted.channels.remove(index);
        if let Some(task) = channel.endpoint_auth {
            task.retire();
        }
        if promoted.channels.is_empty() {
            drop(slot.take());
            return Some(RemovedPromotedChannel {
                worker: channel.worker,
                dedup: channel.dedup,
                additional_dedup: channel.additional_dedup,
                selected_worker: None,
                selected_correlation: None,
                session_empty: true,
            });
        }
        if index < promoted.selected {
            promoted.selected -= 1;
        } else if was_selected {
            promoted.selected = 0;
        }
        Some(RemovedPromotedChannel {
            worker: channel.worker,
            dedup: channel.dedup,
            additional_dedup: channel.additional_dedup,
            selected_worker: Some(Arc::clone(promoted.selected_worker())),
            selected_correlation: promoted.correlation_for(promoted.selected_worker()),
            session_empty: false,
        })
    }

    /// Whether the installed session may still be reused, dropping it if not.
    ///
    /// `current` is the caller's use-time conjunction, evaluated under this
    /// slot's lock against the session's own record. `false` means either
    /// nothing was installed or what was installed has been revoked and is now
    /// gone.
    pub(crate) fn reuse_or_revoke(
        &self,
        current: impl FnOnce(&SessionCapability) -> bool,
    ) -> Reuse {
        let mut slot = self.slot.lock();
        match slot.as_ref() {
            None => Reuse::Vacant,
            Some(bundle) if current(&bundle.selected().session) => Reuse::Current,
            Some(_) => {
                drop(slot.take());
                Reuse::Revoked
            }
        }
    }

    /// Lend the installed session if every use-time conjunct still holds, and
    /// drop it if not.
    ///
    /// Non-promoting: it uses what exists and creates nothing, so a diagnostic
    /// read cannot bring a session into being. It is still not passive — a
    /// revoked session is destroyed here, because observing that a session is no
    /// longer admitted and leaving it installed is what lets a revocation take
    /// effect at a time no caller controls.
    ///
    /// `effect` runs under this slot's lock. Anything it reads that is not in
    /// the bundle must be lockable *after* this slot, never before.
    pub(crate) fn with_live<R>(
        &self,
        current: impl FnOnce(&SessionCapability) -> bool,
        effect: impl FnOnce(&mut PromotedSession) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        if !slot
            .as_ref()
            .is_some_and(|bundle| current(&bundle.selected().session))
        {
            drop(slot.take());
            return None;
        }
        Some(effect(slot.as_mut().expect(
            "the conjunction above answered true, which requires an installed session",
        )))
    }

    pub(crate) fn with_live_worker<R>(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        current: impl FnOnce(&SessionCapability) -> bool,
        effect: impl FnOnce(
            &SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        let (session, flows, worker) = promoted.flows_for_worker_mut(worker)?;
        if !current(session) {
            return None;
        }
        Some(effect(session, flows, worker))
    }

    /// Lend one exact channel together with the correlation that names it.
    ///
    /// The correlation is borrowed from the same [`PromotedChannel`] as the
    /// capability, flow set and worker, while this slot guard is held.  A
    /// caller must not reacquire the slot from its effect closure: doing so is
    /// a non-reentrant self-deadlock and, more importantly, would split the
    /// channel identity from the authority that proved it current.
    pub(crate) fn with_live_worker_and_correlation<R>(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        current: impl FnOnce(&SessionCapability) -> bool,
        effect: impl FnOnce(
            &SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
            &str,
        ) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        let (session, flows, channel_worker, correlation) =
            promoted.flows_for_worker_with_correlation_mut(worker)?;
        if !current(session) {
            return None;
        }
        Some(effect(session, flows, channel_worker, correlation))
    }
}

/// What [`PromotedSessionSlot::reuse_or_revoke`] found.
///
/// Three answers rather than a boolean, because the caller acts differently on
/// each: a current session is reused, a vacant slot is promoted into, and a
/// revoked one is refused outright — attempting to re-promote a peer whose
/// admission was just withdrawn would take a fresh reservation for authority the
/// mesh has already refused.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reuse {
    /// A session is installed and every conjunct still holds.
    Current,
    /// Nothing was installed.
    Vacant,
    /// Something was installed, failed a conjunct, and has been dropped.
    Revoked,
}
