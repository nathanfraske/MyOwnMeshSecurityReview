//! Exact native WebRTC cleanup ownership and conservative claim retention.

use super::*;

#[derive(Clone, Debug)]
pub(super) enum ConnectorCloseStatus {
    Open,
    Closing,
    Closed,
    Failed(String),
}

enum ConnectedClaimRetention {
    Empty,
    One(Box<crate::connector::ConnectedChannelCapability>),
    Multiple(Vec<crate::connector::ConnectedChannelCapability>),
}

/// The WebRTC close owner is the retention behind a generic channel handoff.
///
/// The generic handoff cannot know how to hold a claim through native close;
/// this impl is the one narrow bridge that lets it delegate to the exact owner
/// that does. It adds no behaviour of its own.
impl crate::connector::ConnectedChannelRetention for ConnectorCloseOwner {
    fn retain_connected_claim(
        self: Arc<Self>,
        capability: crate::connector::ConnectedChannelCapability,
    ) {
        ConnectorCloseOwner::retain_connected_claim(&self, capability);
    }
}

impl ConnectedClaimRetention {
    fn release_after_cleanup_success(&mut self) {
        match self {
            Self::Empty => {}
            Self::One(capability) => capability.release_after_cleanup_success(),
            Self::Multiple(capabilities) => {
                for capability in capabilities {
                    capability.release_after_cleanup_success();
                }
            }
        }
    }

    fn retain_after_cleanup_failure(&mut self) {
        match self {
            Self::Empty => {}
            Self::One(capability) => capability.retain_after_cleanup_failure(),
            Self::Multiple(capabilities) => {
                for capability in capabilities {
                    capability.retain_after_cleanup_failure();
                }
            }
        }
    }
}

pub(super) type NativeCloseFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Owner-private close boundary for the native connector allocation.
/// Production wraps the existing webrtc-rs peer connection. Tests supply a
/// deterministic close result without allocating a socket-bearing peer.
pub(super) trait NativeConnectorClosePort: Send + Sync {
    fn close(&self) -> NativeCloseFuture<'_>;
}

pub(super) struct WebRtcNativeClosePort {
    pub(super) peer: Arc<RTCPeerConnection>,
}

impl NativeConnectorClosePort for WebRtcNativeClosePort {
    fn close(&self) -> NativeCloseFuture<'_> {
        Box::pin(async {
            self.peer
                .close()
                .await
                .map_err(|error| Error::Transport(format!("close: {error}")))
        })
    }
}

#[cfg(test)]
pub(super) struct WebRtcNativeCloseErrorPort {
    pub(super) peer: Arc<RTCPeerConnection>,
}

#[cfg(test)]
impl NativeConnectorClosePort for WebRtcNativeCloseErrorPort {
    fn close(&self) -> NativeCloseFuture<'_> {
        Box::pin(async {
            self.peer
                .close()
                .await
                .map_err(|error| Error::Transport(format!("close: {error}")))?;
            Err(Error::Transport(
                "injected native close failure after physical close".to_string(),
            ))
        })
    }
}

/// A deterministic hold point at the one native close. **Controls only.**
///
/// The refusal path this exists for is asynchronous by construction: the engine
/// arm returns as soon as it has started the close, and the actual native close
/// runs on the cleanup executor. A control that wants to state "the claim is
/// still retained while the close is in flight" therefore has no moment it can
/// name — by the time it looks, the close has usually finished and released.
///
/// So the gate names that moment. It is installed before the arm runs, it
/// counts every entry into the native close, it publishes that entry so a
/// control can await it without sleeping, and it parks the close until the
/// control opens it. Nothing here can *cause* a close: it can only hold one that
/// production already started, which is why an armed connector still proves the
/// production ordering rather than a fixture's.
///
/// The failure injection is deliberately applied *after* the physical close has
/// run, so the failure twin exercises the real native close and then reports the
/// failure the owner is supposed to be conservative about. A gate that skipped
/// the close would prove retention over a connector that was never closed.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct NativeCloseGate {
    /// How many times the native close has reached this gate. A `watch` rather
    /// than a counter so a control can await the first entry deterministically.
    entries: watch::Sender<usize>,
    /// The permit. Closes park until this is `true`.
    open: watch::Sender<bool>,
    /// Whether to report a failure for a close that physically ran.
    inject_failure: AtomicBool,
}

#[cfg(all(test, feature = "transport-lab"))]
impl NativeCloseGate {
    fn new() -> Arc<Self> {
        let (entries, _entries_receiver) = watch::channel(0usize);
        let (open, _open_receiver) = watch::channel(false);
        Arc::new(Self {
            entries,
            open,
            inject_failure: AtomicBool::new(false),
        })
    }

    /// Record this entry, then park until the control opens the gate.
    ///
    /// The count is published before parking, so a control that observes the
    /// entry is observing a close that has genuinely reached the native
    /// boundary rather than one that merely submitted.
    async fn hold(&self) {
        self.entries.send_modify(|count| *count += 1);
        let mut open = self.open.subscribe();
        loop {
            // The borrow is released before the await: holding a `watch` guard
            // across a suspension point would block every other sender.
            if *open.borrow() {
                return;
            }
            if open.changed().await.is_err() {
                // The handle was dropped with no receiver left to notify. The
                // handle's own `Drop` opens the gate for exactly this reason,
                // so proceeding is the safe reading: never wedge the executor.
                return;
            }
        }
    }

    /// What this gate reports about a close that has already run successfully.
    ///
    /// Consulted only on the dependency's own success, so an armed gate can add
    /// a failure but can never mask one.
    fn observe_native_close(&self) -> Result<()> {
        if self.inject_failure.load(Ordering::Acquire) {
            return Err(Error::Transport(
                "injected native close failure observed after the physical close".to_string(),
            ));
        }
        Ok(())
    }
}

/// A control's handle on one connector's native close gate. **Controls only.**
///
/// Held by the control for as long as it wants the hold point to exist. Its
/// `Drop` opens the gate unconditionally: a control that panics an assertion
/// mid-hold must not leave a cleanup task parked forever on the shared
/// executor, because that would turn one failing control into a wedged suite.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct NativeCloseGateHandle {
    gate: Arc<NativeCloseGate>,
}

#[cfg(all(test, feature = "transport-lab"))]
impl NativeCloseGateHandle {
    /// How many native closes have reached the gate. The load-bearing
    /// observation: the refusal must start exactly one.
    pub(crate) fn entries(&self) -> usize {
        *self.gate.entries.borrow()
    }

    /// Park until at least one native close has reached the gate.
    ///
    /// No sleep and no retry loop: this is a `watch` change notification, so it
    /// resolves on the entry itself. Callers bound it with a deadline so a
    /// close that never arrives fails the control rather than hanging it.
    pub(crate) async fn wait_for_entry(&self) {
        let mut entries = self.gate.entries.subscribe();
        loop {
            if *entries.borrow() > 0 {
                return;
            }
            if entries.changed().await.is_err() {
                return;
            }
        }
    }

    /// Report a failure for the close that runs, *after* it has run.
    pub(crate) fn inject_close_failure(&self) {
        self.gate.inject_failure.store(true, Ordering::Release);
    }

    /// Let the held close proceed. Idempotent; `Drop` does the same.
    pub(crate) fn open(&self) {
        self.gate.open.send_replace(true);
    }
}

#[cfg(all(test, feature = "transport-lab"))]
impl Drop for NativeCloseGateHandle {
    fn drop(&mut self) {
        self.gate.open.send_replace(true);
    }
}

/// Single cleanup owner for one native peer connection.
pub(super) struct ConnectorCloseOwner {
    pub(super) ownership: ConnectorOwnership,
    resource_owner: MeshConnectorResourceScope,
    cleanup_capability: SyncMutex<Option<crate::runtime::attempt::ConnectorCleanupCapability>>,
    native: SyncMutex<Option<Arc<dyn NativeConnectorClosePort>>>,
    remote_candidates: SyncMutex<Option<Arc<SyncMutex<RemoteCandidateState>>>>,
    realtime_flows: SyncMutex<Option<Arc<RealtimeFlowRegistry>>>,
    native_allocation_started: AtomicBool,
    started: AtomicBool,
    cleanup_submitted: AtomicBool,
    cleanup_complete: AtomicBool,
    status: watch::Sender<ConnectorCloseStatus>,
    status_transition: SyncMutex<()>,
    connected_claims: SyncMutex<ConnectedClaimRetention>,
    remote_description_resources:
        SyncMutex<std::collections::LinkedList<Arc<RemoteDescriptionResourceOwner>>>,
    #[cfg(test)]
    fail_background_start: AtomicBool,
    #[cfg(test)]
    panic_cleanup_future: AtomicBool,
    /// The hold point at this connector's one native close. **Controls only.**
    ///
    /// Installed at most once and never removed, so a control cannot arrange a
    /// hold, observe it, and then quietly disarm the same connector.
    #[cfg(all(test, feature = "transport-lab"))]
    native_close_gate: SyncMutex<Option<Arc<NativeCloseGate>>>,
}

impl ConnectorCloseOwner {
    pub(super) fn new(
        ownership: ConnectorOwnership,
        resource_owner: MeshConnectorResourceScope,
        cleanup_capability: crate::runtime::attempt::ConnectorCleanupCapability,
    ) -> Arc<Self> {
        let (status, _receiver) = watch::channel(ConnectorCloseStatus::Open);
        Arc::new(Self {
            ownership,
            resource_owner: resource_owner.clone(),
            cleanup_capability: SyncMutex::new(Some(cleanup_capability)),
            native: SyncMutex::new(None),
            remote_candidates: SyncMutex::new(None),
            realtime_flows: SyncMutex::new(None),
            native_allocation_started: AtomicBool::new(false),
            started: AtomicBool::new(false),
            cleanup_submitted: AtomicBool::new(false),
            cleanup_complete: AtomicBool::new(false),
            status,
            status_transition: SyncMutex::new(()),
            connected_claims: SyncMutex::new(ConnectedClaimRetention::Empty),
            remote_description_resources: SyncMutex::new(std::collections::LinkedList::new()),
            #[cfg(test)]
            fail_background_start: AtomicBool::new(false),
            #[cfg(test)]
            panic_cleanup_future: AtomicBool::new(false),
            #[cfg(all(test, feature = "transport-lab"))]
            native_close_gate: SyncMutex::new(None),
        })
    }

    pub(super) fn attach_native(self: &Arc<Self>, native: Arc<RTCPeerConnection>) -> bool {
        self.attach_native_port(Arc::new(WebRtcNativeClosePort { peer: native }))
    }

    /// Marks the point after which dependency-owned constructor work may have
    /// allocated native resources that MyOwnMesh cannot individually close.
    ///
    /// This is set before entering the native constructor. If construction is
    /// cancelled before a close port is returned, cleanup retains the exact
    /// connector claim instead of proving a release it cannot observe.
    pub(super) fn mark_native_allocation_started(&self) {
        self.native_allocation_started
            .store(true, Ordering::Release);
    }

    /// Records that native construction returned without a closeable port.
    /// The exact connector claim remains retained because dependency-owned
    /// allocation cannot be disproved.
    pub(super) fn finish_native_allocation_without_close_port(&self, reason: String) {
        self.fail_cleanup(reason);
    }

    pub(super) fn attach_native_port(
        self: &Arc<Self>,
        native: Arc<dyn NativeConnectorClosePort>,
    ) -> bool {
        let mut current = self.native.lock();
        if current.is_some() {
            drop(current);
            self.resource_owner.poison_accounting();
            self.fail_cleanup("duplicate native peer installation".to_string());
            return false;
        }
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Closed | ConnectorCloseStatus::Failed(_)
        ) {
            return false;
        }
        *current = Some(native);
        drop(current);
        if self.started.load(Ordering::Acquire) {
            self.submit_cleanup_if_ready();
        }
        true
    }

    pub(super) fn attach_remote_candidates(
        &self,
        candidates: Arc<SyncMutex<RemoteCandidateState>>,
    ) -> bool {
        let mut current = self.remote_candidates.lock();
        if current.is_some() {
            drop(current);
            self.fail_cleanup("duplicate remote-candidate owner installation".to_string());
            return false;
        }
        *current = Some(candidates);
        true
    }

    pub(super) fn attach_realtime_flows(&self, flows: Arc<RealtimeFlowRegistry>) -> bool {
        let mut current = self.realtime_flows.lock();
        if current.is_some() {
            drop(current);
            self.fail_cleanup("duplicate real-time registry owner installation".to_string());
            return false;
        }
        *current = Some(flows);
        true
    }

    pub(super) fn retain_remote_description_resources(
        &self,
        resources: Arc<RemoteDescriptionResourceOwner>,
    ) {
        let mut retained = self.remote_description_resources.lock();
        if retained
            .iter()
            .any(|current| Arc::ptr_eq(current, &resources))
        {
            return;
        }
        retained.push_back(resources);
    }

    pub(super) fn retire_local(&self) {
        self.ownership.retire();
        if let Some(candidates) = self.remote_candidates.lock().as_ref() {
            drain_remote_candidates(candidates);
        }
        if let Some(flows) = self.realtime_flows.lock().as_ref() {
            flows.retire();
        }
    }

    pub(super) fn retain_connected_claim(
        self: &Arc<Self>,
        mut capability: crate::connector::ConnectedChannelCapability,
    ) {
        let mut retained = self.connected_claims.lock();
        if self.ownership.cleanup_failed.load(Ordering::Acquire) {
            capability.retain_after_cleanup_failure();
        }
        if self.cleanup_complete.load(Ordering::Acquire) {
            drop(capability);
            return;
        }
        *retained = match std::mem::replace(&mut *retained, ConnectedClaimRetention::Empty) {
            ConnectedClaimRetention::Empty => ConnectedClaimRetention::One(Box::new(capability)),
            ConnectedClaimRetention::One(primary) => {
                trace!("native cleanup retains a duplicate connected claim");
                ConnectedClaimRetention::Multiple(vec![*primary, capability])
            }
            ConnectedClaimRetention::Multiple(mut claims) => {
                claims.push(capability);
                ConnectedClaimRetention::Multiple(claims)
            }
        };
        drop(retained);
        self.start();
    }

    /// This close owner as the transport-independent retention obligation.
    ///
    /// The generic handoff calls back through this on drop, so the connected
    /// claim returns to exactly the same retention path it uses today.
    pub(super) fn generic_retention(
        self: &Arc<Self>,
    ) -> Arc<dyn crate::connector::ConnectedChannelRetention> {
        Arc::clone(self) as Arc<dyn crate::connector::ConnectedChannelRetention>
    }

    pub(super) fn start(self: &Arc<Self>) {
        self.retire_local();
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let _transition = self.status_transition.lock();
            let current = self.status.borrow().clone();
            match current {
                ConnectorCloseStatus::Closed => return,
                ConnectorCloseStatus::Failed(_) => {}
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {
                    self.status.send_replace(ConnectorCloseStatus::Closing);
                }
            }
        }
        self.submit_cleanup_if_ready();
    }

    /// Submit cleanup only after either no native allocation was started or an
    /// exact native close port has arrived. A close request racing a native
    /// constructor remains `Closing` and keeps its finite claim. Late port
    /// attachment then wakes this same owner and completes the one close.
    fn submit_cleanup_if_ready(self: &Arc<Self>) {
        let native_ready = self.native.lock().is_some();
        if !native_ready && self.native_allocation_started.load(Ordering::Acquire) {
            return;
        }
        if self.cleanup_submitted.swap(true, Ordering::AcqRel) {
            return;
        }
        #[cfg(test)]
        if self.fail_background_start.load(Ordering::Acquire) {
            self.fail_cleanup("cleanup background task failed to start".to_string());
            return;
        }
        let Some(mut cleanup_capability) = self.cleanup_capability.lock().take() else {
            self.fail_cleanup("connector cleanup capability is missing".to_string());
            return;
        };
        if let Err(error) = cleanup_capability.begin_cleanup() {
            self.fail_cleanup(format!(
                "resource provider refused the cleanup transition: {error}"
            ));
            return;
        }
        let owner = Arc::clone(self);
        let completion_owner = Arc::clone(self);
        let failure_owner = Arc::clone(self);
        if self
            .resource_owner
            .submit_cleanup(
                cleanup_capability,
                Box::pin(async move { owner.run().await }),
                Box::new(move || {
                    completion_owner.publish_cleanup_job_completion();
                }),
                Box::new(move |reason| {
                    failure_owner.fail_cleanup(reason);
                }),
            )
            .is_err()
        {
            self.fail_cleanup("process cleanup executor refused the close owner".to_string());
        }
    }

    async fn run(self: Arc<Self>) {
        #[cfg(test)]
        if self.panic_cleanup_future.load(Ordering::Acquire) {
            panic!("injected cleanup future panic");
        }
        let native = self.native.lock().clone();
        let Some(native) = native else {
            if self.native_allocation_started.load(Ordering::Acquire) {
                self.fail_cleanup(
                    "native construction ended without an observable close owner".to_string(),
                );
            } else {
                self.finish_closed();
            }
            return;
        };
        self.ownership.incarnation.retire();
        self.ownership.operation_fence.wait_for_operations().await;
        // Controls only, compiled out of production. The hold is taken *after*
        // the operation fence has drained and *before* the native close, which
        // is the one window in which "this connector is closing and its claim is
        // still retained" is a true statement about a real close in flight.
        #[cfg(all(test, feature = "transport-lab"))]
        let gate = self.native_close_gate.lock().clone();
        #[cfg(all(test, feature = "transport-lab"))]
        if let Some(gate) = gate.as_ref() {
            gate.hold().await;
        }
        // The one native close is matched directly on the dependency's own
        // future, and that shape is pinned by the Arc 03 connector-worker
        // boundary check. It is pinned because it is the honest shape: nothing
        // between this owner and the dependency gets to decide the outcome of
        // the close in production.
        let outcome = match native.close().await {
            // The physical close has already run and reported success. The only
            // thing that can still turn this into a failure is an installed
            // control gate, and only after the fact — so a failure twin
            // exercises a genuine close and then reports the failure this owner
            // is supposed to be conservative about, rather than skipping the
            // close. In production there is no gate and this is `Ok(())`.
            Ok(()) => self.observe_gated_native_close(),
            Err(error) => Err(error),
        };
        match outcome {
            Ok(()) => self.finish_closed(),
            Err(error) => self.fail_cleanup(error.to_string()),
        }
    }

    /// What an installed control gate reports about a close that has run.
    ///
    /// The gate is installed at most once and is never removed, so re-reading it
    /// here yields the same gate the hold above used.
    #[cfg(all(test, feature = "transport-lab"))]
    fn observe_gated_native_close(&self) -> Result<()> {
        let gate = self.native_close_gate.lock().clone();
        match gate {
            Some(gate) => gate.observe_native_close(),
            None => Ok(()),
        }
    }

    /// Production has no gate: the dependency's close is the whole outcome.
    #[cfg(not(all(test, feature = "transport-lab")))]
    fn observe_gated_native_close(&self) -> Result<()> {
        Ok(())
    }

    fn finish_closed(&self) {
        let _transition = self.status_transition.lock();
        let terminal_failure = matches!(*self.status.borrow(), ConnectorCloseStatus::Failed(_));
        self.cleanup_complete.store(true, Ordering::Release);
        if terminal_failure {
            // A failure recorded before start remains authoritative, but a
            // later successful native close still retires all subordinate
            // connector objects. Their exact failed claims were already moved
            // into provider retention and are not made reusable here.
            self.connected_claims.lock().retain_after_cleanup_failure();
            for resources in self.remote_description_resources.lock().iter() {
                resources.retain_after_cleanup_failure();
            }
        } else {
            self.ownership.complete_cleanup();
            self.connected_claims.lock().release_after_cleanup_success();
        }
        self.native.lock().take();
        self.remote_candidates.lock().take();
        self.realtime_flows.lock().take();
        self.remote_description_resources.lock().clear();
        *self.connected_claims.lock() = ConnectedClaimRetention::Empty;
    }

    fn publish_cleanup_job_completion(&self) {
        let _transition = self.status_transition.lock();
        if self.cleanup_complete.load(Ordering::Acquire)
            && matches!(
                *self.status.borrow(),
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing
            )
        {
            self.status.send_replace(ConnectorCloseStatus::Closed);
        }
    }

    /// Retain this connector's exact cleanup claims after a known native
    /// close failure. The process aggregate remains exact, so unrelated
    /// connector slots remain admissible.
    pub(super) fn fail_cleanup(&self, reason: String) {
        let _transition = self.status_transition.lock();
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Closed | ConnectorCloseStatus::Failed(_)
        ) {
            return;
        }
        self.ownership.cleanup_failed.store(true, Ordering::Release);
        self.retire_local();
        self.ownership.retain_after_cleanup_failure();
        self.connected_claims.lock().retain_after_cleanup_failure();
        for resources in self.remote_description_resources.lock().iter() {
            resources.retain_after_cleanup_failure();
        }
        self.status
            .send_replace(ConnectorCloseStatus::Failed(reason));
    }

    pub(super) async fn wait(self: &Arc<Self>) -> Result<()> {
        let mut status = self.status.subscribe();
        self.start();
        loop {
            match status.borrow().clone() {
                ConnectorCloseStatus::Closed => return Ok(()),
                ConnectorCloseStatus::Failed(error) => {
                    return Err(Error::Transport(format!(
                        "native peer cleanup failed and retained its exact claim: {error}"
                    )));
                }
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {}
            }
            if status.changed().await.is_err() {
                return Err(Error::Transport(
                    "native peer cleanup owner stopped".to_string(),
                ));
            }
        }
    }

    #[cfg(test)]
    pub(super) fn fail_background_start_for_test(&self) {
        self.fail_background_start.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn panic_cleanup_future_for_test(&self) {
        self.panic_cleanup_future.store(true, Ordering::Release);
    }

    /// Install this connector's one native-close hold point. **Controls only.**
    ///
    /// Exactly once per connector: a second installation would let a control
    /// replace a gate whose entries it had already counted, so the invariant a
    /// twin states about "one close" would be about two different gates.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn install_native_close_gate_for_test(&self) -> NativeCloseGateHandle {
        let gate = NativeCloseGate::new();
        let mut installed = self.native_close_gate.lock();
        assert!(
            installed.is_none(),
            "the native close gate is installed exactly once per connector"
        );
        *installed = Some(Arc::clone(&gate));
        NativeCloseGateHandle { gate }
    }

    #[cfg(test)]
    pub(super) fn retained_connected_claims_for_test(&self) -> usize {
        match &*self.connected_claims.lock() {
            ConnectedClaimRetention::Empty => 0,
            ConnectedClaimRetention::One(_) => 1,
            ConnectedClaimRetention::Multiple(claims) => claims.len(),
        }
    }
}
