//! Named application channels: the subscriber queues and the gateway
//! operations that install, retire, and deliver into them.

use crate::resource::{LeasedMap, LeasedQueue, ResourceClaim, ResourceClass, ResourceLease};
use crate::runtime::session_broker::SessionCapability;

use super::{ApplicationGateway, GatewayAccepted, GatewayDelivery, GatewayMailbox, GatewayRefusal};

pub(crate) struct GatewayChannelFrame {
    pub(crate) from: String,
    pub(crate) payload: serde_json::Value,
}

pub(crate) struct ChannelSubscriber {
    mailbox: parking_lot::Mutex<GatewayMailbox<GatewayChannelFrame>>,
    ready: tokio::sync::Notify,
    closed: std::sync::atomic::AtomicBool,
    pressure: std::sync::atomic::AtomicU64,
    _allocation: ResourceLease,
}

impl ChannelSubscriber {
    fn new(allocation: ResourceLease) -> Self {
        Self {
            mailbox: parking_lot::Mutex::new(GatewayMailbox::new()),
            ready: tokio::sync::Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
            pressure: std::sync::atomic::AtomicU64::new(0),
            _allocation: allocation,
        }
    }

    fn accept(&self, frame: GatewayChannelFrame, retention: ResourceLease, node: ResourceLease) {
        self.mailbox.lock().accept(frame, retention, node);
        self.ready.notify_one();
    }

    fn note_pressure(&self) {
        self.pressure
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.ready.notify_one();
    }

    pub(crate) async fn recv(
        &self,
    ) -> Result<GatewayDelivery<GatewayChannelFrame>, GatewayRefusal> {
        self.recv_with_before_wait(|| {}).await
    }

    async fn recv_with_before_wait(
        &self,
        mut before_wait: impl FnMut(),
    ) -> Result<GatewayDelivery<GatewayChannelFrame>, GatewayRefusal> {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let skipped = self.pressure.swap(0, std::sync::atomic::Ordering::AcqRel);
            if skipped != 0 {
                return Err(GatewayRefusal::Lag(skipped));
            }
            if let Some(delivery) = self.mailbox.lock().pop() {
                return Ok(delivery);
            }
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(GatewayRefusal::Revoked);
            }
            before_wait();
            notified.await;
        }
    }

    fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.ready.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<GatewayDelivery<GatewayChannelFrame>> {
        self.mailbox.lock().pop()
    }
}

pub(super) struct GatewayChannel {
    subscribers: LeasedQueue<std::sync::Weak<ChannelSubscriber>>,
    _name: ResourceLease,
}

impl Drop for GatewayChannel {
    fn drop(&mut self) {
        while let Some(subscriber) = self.subscribers.pop_front() {
            if let Some(subscriber) = subscriber.upgrade() {
                subscriber.close();
            }
        }
    }
}

impl ApplicationGateway {
    pub(crate) fn subscribe_channel(
        &self,
        name: &str,
    ) -> Result<std::sync::Arc<ChannelSubscriber>, GatewayRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        let subscriber_bytes = std::mem::size_of::<ChannelSubscriber>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(GatewayRefusal::Malformed)?;
        let subscriber_claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, subscriber_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let subscriber = std::sync::Arc::new(ChannelSubscriber::new(
            self.resources
                .acquire(subscriber_claim)
                .map_err(GatewayRefusal::Pressure)?,
        ));
        let mut channels = self.channels.lock();
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        if channels.get(name).is_none() {
            let name_claim = GatewayMailbox::<()>::retention_claim(name.len(), 1)
                .map_err(|_| GatewayRefusal::Malformed)?;
            let name_lease = self
                .resources
                .acquire(name_claim)
                .map_err(GatewayRefusal::Pressure)?;
            let node = self
                .resources
                .acquire(
                    LeasedMap::<String, GatewayChannel>::entry_claim()
                        .map_err(|_| GatewayRefusal::Malformed)?,
                )
                .map_err(GatewayRefusal::Pressure)?;
            channels
                .insert(
                    name.to_string(),
                    GatewayChannel {
                        subscribers: LeasedQueue::new(),
                        _name: name_lease,
                    },
                    node,
                )
                .map_err(|_| GatewayRefusal::Malformed)?;
        }
        let subscriber_node = self
            .resources
            .acquire(
                LeasedQueue::<std::sync::Weak<ChannelSubscriber>>::entry_claim()
                    .map_err(|_| GatewayRefusal::Malformed)?,
            )
            .map_err(GatewayRefusal::Pressure)?;
        channels
            .get_mut(name)
            .expect("the channel entry was installed under this lock")
            .subscribers
            .push(std::sync::Arc::downgrade(&subscriber), subscriber_node);
        Ok(subscriber)
    }

    pub(crate) fn unsubscribe_channel(
        &self,
        name: &str,
        subscriber: &std::sync::Arc<ChannelSubscriber>,
    ) {
        let mut registry = self.channels.lock();
        if let Some(channel) = registry.get_mut(name) {
            channel.subscribers.retain(|candidate| {
                candidate
                    .upgrade()
                    .is_some_and(|candidate| !std::sync::Arc::ptr_eq(&candidate, subscriber))
            });
            if channel.subscribers.is_empty() {
                registry.remove_entry(name);
            }
        }
        subscriber.close();
    }

    pub(crate) fn accept_channel(
        &self,
        session: &SessionCapability,
        claim: ResourceClaim,
        parse_retention: ResourceLease,
        name: &str,
        from: &str,
        payload: serde_json::Value,
    ) -> Result<GatewayAccepted, GatewayRefusal> {
        let mut registry = self.channels.lock();
        let candidate_count = registry
            .get_mut(name)
            .map_or(0, |channel| channel.subscribers.iter().count());
        if candidate_count == 0 {
            return Err(GatewayRefusal::NoReceiver);
        }
        // The temporary live-subscriber snapshot and the all-or-nothing
        // prepared-delivery set each own one exact backing allocation. Fund
        // both before either Vec exists; the lease remains live until both
        // buffers have been consumed below.
        let scratch_count =
            u64::try_from(candidate_count).map_err(|_| GatewayRefusal::Malformed)?;
        let live_bytes = u64::try_from(std::mem::size_of::<std::sync::Arc<ChannelSubscriber>>())
            .map_err(|_| GatewayRefusal::Malformed)?
            .checked_mul(scratch_count)
            .ok_or(GatewayRefusal::Malformed)?;
        let prepared_bytes = u64::try_from(std::mem::size_of::<(
            std::sync::Arc<ChannelSubscriber>,
            ResourceLease,
            ResourceLease,
            serde_json::Value,
        )>())
        .map_err(|_| GatewayRefusal::Malformed)?
        .checked_mul(scratch_count)
        .ok_or(GatewayRefusal::Malformed)?;
        let scratch_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                live_bytes
                    .checked_add(prepared_bytes)
                    .ok_or(GatewayRefusal::Malformed)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let _scratch = session
            .reserve_retained(scratch_claim)
            .map_err(GatewayRefusal::Pressure)?;
        let subscribers = {
            let Some(channel) = registry.get_mut(name) else {
                return Err(GatewayRefusal::NoReceiver);
            };
            let mut live = Vec::with_capacity(candidate_count);
            live.extend(
                channel
                    .subscribers
                    .iter()
                    .filter_map(std::sync::Weak::upgrade),
            );
            channel
                .subscribers
                .retain(|subscriber| subscriber.strong_count() != 0);
            live
        };
        if subscribers.is_empty() {
            return Err(GatewayRefusal::NoReceiver);
        }
        let node_claim = GatewayMailbox::<GatewayChannelFrame>::node_claim()
            .map_err(|_| GatewayRefusal::Malformed)?;
        let from_claim = GatewayMailbox::<GatewayChannelFrame>::retention_claim(
            from.len(),
            usize::from(!from.is_empty()),
        )
        .map_err(|_| GatewayRefusal::Malformed)?;
        let queued_payload = ResourceClaim::single(
            ResourceClass::QueuedBytes,
            claim.amount(ResourceClass::AccountedMemoryBytes),
        );
        let entry_claim = claim
            .checked_add(from_claim)
            .and_then(|claim| claim.checked_add(queued_payload))
            .map_err(|_| GatewayRefusal::Malformed)?;
        let mut original_payload = Some(payload);
        let mut prepared = Vec::with_capacity(candidate_count);
        for (index, subscriber) in subscribers.iter().enumerate() {
            let retention = session.reserve_retained(entry_claim).map_err(|error| {
                for subscriber in &subscribers {
                    subscriber.note_pressure();
                }
                GatewayRefusal::Pressure(error)
            })?;
            let node = session.reserve_retained(node_claim).map_err(|error| {
                for subscriber in &subscribers {
                    subscriber.note_pressure();
                }
                GatewayRefusal::Pressure(error)
            })?;
            let payload = if index + 1 == subscribers.len() {
                original_payload
                    .take()
                    .expect("last subscriber owns payload")
            } else {
                original_payload.as_ref().expect("payload remains").clone()
            };
            prepared.push((std::sync::Arc::clone(subscriber), retention, node, payload));
        }
        for (subscriber, retention, node, payload) in prepared {
            subscriber.accept(
                GatewayChannelFrame {
                    from: from.to_string(),
                    payload,
                },
                retention,
                node,
            );
        }
        drop(registry);
        drop(parse_retention);
        Ok(GatewayAccepted)
    }

    #[cfg(test)]
    pub(crate) fn channel_subscriber_count_for_test(&self, name: &str) -> usize {
        self.channels
            .lock()
            .get_mut(name)
            .map_or(0, |channel| channel.subscribers.iter().count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscriber_fixture() -> (ApplicationGateway, std::sync::Arc<ChannelSubscriber>) {
        let grant = ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|resource| (resource, 1 << 20)),
        )
        .expect("the broad control grant is representable");
        let provider = crate::resource::FiniteResourceProvider::new(grant);
        let port = crate::resource::ResourceProviderPort::new(provider)
            .expect("the control grant funds its process scope");
        let process = crate::resource::ProcessResourceRoot::isolated();
        process
            .install_local_application_provider(port)
            .expect("the control installs its local provider");
        let resources = process
            .issue_local_application_scope()
            .expect("the control issues a local-application scope");
        let gateway = ApplicationGateway::new(resources);
        let subscriber = gateway
            .subscribe_channel("wake-control")
            .expect("the control funds one subscriber");
        (gateway, subscriber)
    }

    #[tokio::test]
    async fn close_in_the_check_to_wait_window_cannot_be_lost() {
        let (_gateway, subscriber) = subscriber_fixture();
        let closer = std::sync::Arc::clone(&subscriber);
        let refusal = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            subscriber.recv_with_before_wait(move || closer.close()),
        )
        .await
        .expect("the registered waiter observes close in the critical window");
        assert!(matches!(refusal, Err(GatewayRefusal::Revoked)));
    }
}
