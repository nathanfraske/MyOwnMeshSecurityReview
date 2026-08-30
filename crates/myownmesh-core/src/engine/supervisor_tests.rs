use std::sync::Arc;

use super::state::NetworkState;

#[cfg(all(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum B2Stage {
    DataChannelOpen,
    AuthStarted,
    PeerProofAccepted,
    PromotionQueued,
    MediaOfferApplied,
    MediaAnswerApplied,
    MediaOfferSent,
}

#[cfg(all(test, feature = "transport-lab"))]
#[derive(Clone, Debug)]
struct B2StageEvent {
    local_device_id: String,
    correlation: String,
    stage: B2Stage,
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct B2StageProbe {
    events: parking_lot::Mutex<Vec<B2StageEvent>>,
    wake: tokio::sync::Notify,
}

#[cfg(all(test, feature = "transport-lab"))]
impl B2StageProbe {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            events: parking_lot::Mutex::new(Vec::new()),
            wake: tokio::sync::Notify::new(),
        })
    }

    fn record(&self, event: B2StageEvent) {
        eprintln!(
            "B2_STAGE local={} correlation={} stage={:?}",
            event.local_device_id, event.correlation, event.stage
        );
        tracing::info!(
            target: "b2_stage",
            local_device = %event.local_device_id,
            correlation = %event.correlation,
            stage = ?event.stage,
            "B2 speculative handoff stage"
        );
        self.events.lock().push(event);
        self.wake.notify_waiters();
    }

    pub(crate) async fn wait_for(&self, local_device_id: &str, correlation: &str, stage: B2Stage) {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.events.lock().iter().any(|event| {
                event.local_device_id == local_device_id
                    && event.correlation == correlation
                    && event.stage == stage
            }) {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(all(test, feature = "transport-lab"))]
static B2_STAGE_PROBE: std::sync::OnceLock<parking_lot::Mutex<Option<Arc<B2StageProbe>>>> =
    std::sync::OnceLock::new();

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn install_b2_stage_probe(probe: Arc<B2StageProbe>) {
    *B2_STAGE_PROBE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock() = Some(probe);
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn clear_b2_stage_probe() {
    *B2_STAGE_PROBE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock() = None;
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn record_b2_stage(state: &Arc<NetworkState>, correlation: &str, stage: B2Stage) {
    if let Some(probe) = B2_STAGE_PROBE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock()
        .clone()
    {
        probe.record(B2StageEvent {
            local_device_id: state.identity.public_id().to_string(),
            correlation: correlation.to_string(),
            stage,
        });
    }
}
