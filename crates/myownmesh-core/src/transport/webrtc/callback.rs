//! Callback classification, lifecycle fencing, and bounded scheduling.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnectorCallbackClass {
    Control,
    EndpointData,
    Realtime,
}

impl ConnectorCallbackClass {
    pub(super) fn for_event(event: &TransportEvent) -> Self {
        match event {
            TransportEvent::Message(_) => Self::EndpointData,
            TransportEvent::AudioSample(_) | TransportEvent::VideoSample(_) => Self::Realtime,
            _ => Self::Control,
        }
    }

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::EndpointData => 1,
            Self::Realtime => 2,
        }
    }

    pub(super) const fn from_index(index: usize) -> Self {
        match index % 3 {
            0 => Self::Control,
            1 => Self::EndpointData,
            _ => Self::Realtime,
        }
    }
}

struct ConnectorOperationFenceState {
    closing: bool,
    active_operations: usize,
    accounting_poisoned: bool,
}

/// One total ordering boundary for application-affecting connector work.
///
/// Inbound callbacks, endpoint sends, real-time writes, lane operations, track
/// attachment, and close all enter through this owner. Work admitted before
/// close may finish or be discarded by the receiver, but work presented after
/// close cannot enter. Native close waits for all earlier operations to drop
/// their permits.
pub(super) struct ConnectorOperationFence {
    state: SyncMutex<ConnectorOperationFenceState>,
    closed_signal: watch::Sender<bool>,
    active_signal: watch::Sender<usize>,
}

impl Default for ConnectorOperationFence {
    fn default() -> Self {
        let (closed_signal, _receiver) = watch::channel(false);
        let (active_signal, _receiver) = watch::channel(0);
        Self {
            state: SyncMutex::new(ConnectorOperationFenceState {
                closing: false,
                active_operations: 0,
                accounting_poisoned: false,
            }),
            closed_signal,
            active_signal,
        }
    }
}

impl ConnectorOperationFence {
    pub(super) fn try_enter(self: &Arc<Self>) -> Option<ConnectorOperationPermit> {
        let mut state = self.state.lock();
        if state.closing || state.accounting_poisoned {
            return None;
        }
        let Some(active_operations) = state.active_operations.checked_add(1) else {
            state.accounting_poisoned = true;
            state.closing = true;
            self.closed_signal.send_replace(true);
            return None;
        };
        state.active_operations = active_operations;
        self.active_signal.send_replace(active_operations);
        Some(ConnectorOperationPermit {
            fence: Arc::clone(self),
            active: true,
        })
    }

    pub(super) fn begin_close(&self) -> bool {
        let mut state = self.state.lock();
        if state.closing {
            return false;
        }
        state.closing = true;
        self.closed_signal.send_replace(true);
        true
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state.lock().closing
    }

    pub(super) async fn wait_for_operations(&self) {
        let mut active = self.active_signal.subscribe();
        loop {
            if *active.borrow() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn active_operations_for_test(&self) -> usize {
        self.state.lock().active_operations
    }
}

pub(super) struct ConnectorOperationPermit {
    fence: Arc<ConnectorOperationFence>,
    active: bool,
}

impl Drop for ConnectorOperationPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.fence.state.lock();
        let Some(active_operations) = state.active_operations.checked_sub(1) else {
            state.accounting_poisoned = true;
            state.closing = true;
            self.fence.closed_signal.send_replace(true);
            return;
        };
        state.active_operations = active_operations;
        self.fence.active_signal.send_replace(active_operations);
        self.active = false;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnectorLifecyclePhase {
    AwaitingOpen,
    OpenPending,
    OpenCommitted,
    ClosedPending,
    ClosedDelivered,
}

struct ConnectorLifecycleState {
    phase: ConnectorLifecyclePhase,
    open_exposed: bool,
    renegotiation_pending: bool,
    ice_connection_state: Option<RTCIceConnectionState>,
    peer_connection_state: Option<RTCPeerConnectionState>,
}

/// Fixed, lossless owner for connector lifecycle and coalesced observations.
///
/// Open, close, and renegotiation never compete for ordinary callback mailbox
/// capacity. ICE and peer-connection state are latest-value observations.
pub(super) struct ConnectorLifecycleOwner {
    state: SyncMutex<ConnectorLifecycleState>,
    ready: tokio::sync::Notify,
}

impl Default for ConnectorLifecycleOwner {
    fn default() -> Self {
        Self {
            state: SyncMutex::new(ConnectorLifecycleState {
                phase: ConnectorLifecyclePhase::AwaitingOpen,
                open_exposed: false,
                renegotiation_pending: false,
                ice_connection_state: None,
                peer_connection_state: None,
            }),
            ready: tokio::sync::Notify::new(),
        }
    }
}

impl ConnectorLifecycleOwner {
    pub(super) fn record_open(&self) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        let result = match state.phase {
            ConnectorLifecyclePhase::AwaitingOpen => {
                state.phase = ConnectorLifecyclePhase::OpenPending;
                state.open_exposed = false;
                ConnectorCallbackInsertResult::Queued
            }
            ConnectorLifecyclePhase::OpenPending | ConnectorLifecyclePhase::OpenCommitted => {
                ConnectorCallbackInsertResult::PolicyRefused
            }
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered => {
                ConnectorCallbackInsertResult::DiscardedAfterClose
            }
        };
        drop(state);
        if result == ConnectorCallbackInsertResult::Queued {
            self.ready.notify_one();
        }
        result
    }

    pub(super) fn record_close(&self) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        let result = match state.phase {
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered => {
                ConnectorCallbackInsertResult::DiscardedAfterClose
            }
            ConnectorLifecyclePhase::AwaitingOpen
            | ConnectorLifecyclePhase::OpenPending
            | ConnectorLifecyclePhase::OpenCommitted => {
                state.phase = ConnectorLifecyclePhase::ClosedPending;
                state.renegotiation_pending = false;
                state.ice_connection_state = None;
                state.peer_connection_state = None;
                ConnectorCallbackInsertResult::Queued
            }
        };
        drop(state);
        if result == ConnectorCallbackInsertResult::Queued {
            self.ready.notify_one();
        }
        result
    }

    pub(super) fn commit_open(&self) -> bool {
        let mut state = self.state.lock();
        if state.phase != ConnectorLifecyclePhase::OpenPending || !state.open_exposed {
            return false;
        }
        state.phase = ConnectorLifecyclePhase::OpenCommitted;
        true
    }

    pub(super) fn record_renegotiation(&self) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered
        ) {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        state.renegotiation_pending = true;
        drop(state);
        self.ready.notify_one();
        ConnectorCallbackInsertResult::Queued
    }

    pub(super) fn record_ice_state(
        &self,
        value: RTCIceConnectionState,
    ) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered
        ) {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        state.ice_connection_state = Some(value);
        drop(state);
        self.ready.notify_one();
        ConnectorCallbackInsertResult::Queued
    }

    pub(super) fn record_peer_state(
        &self,
        value: RTCPeerConnectionState,
    ) -> ConnectorCallbackInsertResult {
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            ConnectorLifecyclePhase::ClosedPending | ConnectorLifecyclePhase::ClosedDelivered
        ) {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        state.peer_connection_state = Some(value);
        drop(state);
        self.ready.notify_one();
        ConnectorCallbackInsertResult::Queued
    }

    pub(super) fn try_take_event(&self) -> Option<QueuedTransportEvent> {
        let mut state = self.state.lock();
        let event = match state.phase {
            ConnectorLifecyclePhase::ClosedPending => {
                state.phase = ConnectorLifecyclePhase::ClosedDelivered;
                Some(TransportEvent::DataChannelClosed)
            }
            ConnectorLifecyclePhase::OpenPending if !state.open_exposed => {
                state.open_exposed = true;
                Some(TransportEvent::DataChannelOpen)
            }
            _ if state.renegotiation_pending => {
                state.renegotiation_pending = false;
                Some(TransportEvent::RenegotiationNeeded)
            }
            _ => state
                .ice_connection_state
                .take()
                .map(TransportEvent::IceConnectionStateChanged)
                .or_else(|| {
                    state
                        .peer_connection_state
                        .take()
                        .map(TransportEvent::PeerConnectionStateChanged)
                }),
        }?;
        Some(QueuedTransportEvent {
            event,
            observation: None,
        })
    }

    pub(super) fn has_pending(&self) -> bool {
        let state = self.state.lock();
        state.phase == ConnectorLifecyclePhase::ClosedPending
            || (state.phase == ConnectorLifecyclePhase::OpenPending && !state.open_exposed)
            || state.renegotiation_pending
            || state.ice_connection_state.is_some()
            || state.peer_connection_state.is_some()
    }

    #[cfg(test)]
    pub(super) fn phase(&self) -> ConnectorLifecyclePhase {
        self.state.lock().phase
    }

    pub(super) async fn notified(&self) {
        self.ready.notified().await;
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectorCallbackScheduler {
    pub(super) weights: [usize; 3],
    pub(super) cursor: usize,
    pub(super) remaining: usize,
}

impl ConnectorCallbackScheduler {
    pub(super) fn new(weights: ConnectorCallbackServiceWeights) -> Self {
        let weights = [
            weights.control().get(),
            weights.endpoint_data().get(),
            weights.realtime().map_or(0, NonZeroUsize::get),
        ];
        Self {
            weights,
            cursor: 0,
            remaining: weights[0],
        }
    }

    pub(super) fn current(&self) -> ConnectorCallbackClass {
        ConnectorCallbackClass::from_index(self.cursor)
    }

    pub(super) fn skip_current(&mut self) {
        loop {
            self.cursor = (self.cursor + 1) % self.weights.len();
            self.remaining = self.weights[self.cursor];
            if self.remaining != 0 {
                break;
            }
        }
    }

    pub(super) fn delivered(&mut self, class: ConnectorCallbackClass) {
        let index = class.index();
        if index != self.cursor {
            self.cursor = index;
            self.remaining = self.weights[index];
        }
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 {
            self.skip_current();
        }
    }
}
