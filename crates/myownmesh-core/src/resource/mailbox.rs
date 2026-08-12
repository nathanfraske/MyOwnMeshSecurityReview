use std::sync::Arc;

use parking_lot::Mutex;

use super::{
    LeasedQueue, LocalApplicationResourceScope, ResourceClaim, ResourceClaimArithmeticError,
    ResourceClass, ResourceLease, ResourceUnavailable,
};

struct MailboxEntry<T> {
    value: T,
    retention: ResourceLease,
}

struct MailboxInner<T> {
    queue: Mutex<LeasedQueue<MailboxEntry<T>>>,
    ready: tokio::sync::Notify,
    closed_ready: tokio::sync::Notify,
    closed: std::sync::atomic::AtomicBool,
    senders: std::sync::atomic::AtomicUsize,
    owner: LocalApplicationResourceScope,
    _root: ResourceLease,
}

/// Measured off-node retention owned by one mailbox value.
///
/// Implementations count the value itself and every allocation or handle it
/// retains. The mailbox adds one scheduled-work obligation and owns the queue
/// node separately, so all three parts of an accepted entry leave together.
pub trait ResourceMailboxItem {
    fn retained_claim(&self) -> Result<ResourceClaim, ResourceMailboxItemError>;
}

/// Conservatively measure a serializable, JSON-shaped mailbox value and return
/// the off-node claim that must remain leased while the typed value is queued.
///
/// The encoded length bounds both the decoded tree's owned fragments and its
/// allocation count. The value's inline representation is added separately;
/// queued bytes name exactly what a later writer will serialize, and the same
/// measured length prices the serialization pass as parsing/CPU work. This is
/// the shared measurement for pure-data mailbox items; values carrying opaque
/// handles or effects must add those dependencies in their own implementation.
pub fn serialized_mailbox_item_claim<T: serde::Serialize>(
    value: &T,
) -> Result<ResourceClaim, ResourceMailboxItemError> {
    let (retained, queued, allocations) = mailbox_measure_serialized(value)?;
    mailbox_retained_claim::<T>(retained, queued, allocations)
}

pub(crate) fn mailbox_measure_serialized(
    value: &impl serde::Serialize,
) -> Result<(usize, usize, usize), ResourceMailboxItemError> {
    struct CountBytes(Option<usize>);

    impl std::io::Write for CountBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.and_then(|count| count.checked_add(bytes.len()));
            self.0
                .ok_or_else(|| std::io::Error::other("serialized length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut encoded = CountBytes(Some(0));
    serde_json::to_writer(&mut encoded, value)
        .map_err(|_| ResourceMailboxItemError::Measurement("JSON serialization failed"))?;
    let encoded = encoded.0.ok_or(ResourceMailboxItemError::Measurement(
        "JSON serialization length overflowed",
    ))?;
    let allocations = encoded;
    let bytes_per_fragment = std::mem::size_of::<serde_json::Value>()
        .checked_add(1)
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let retained =
        encoded
            .checked_mul(bytes_per_fragment)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    Ok((retained, encoded, allocations))
}

pub(crate) fn mailbox_retained_claim<T>(
    retained_bytes: usize,
    queued_bytes: usize,
    allocations: usize,
) -> Result<ResourceClaim, ResourceMailboxItemError> {
    let fixed = std::mem::size_of::<T>().checked_add(retained_bytes).ok_or(
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let fixed = u64::try_from(fixed).map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    })?;
    let queued =
        u64::try_from(queued_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::QueuedBytes,
        })?;
    let allocations = u64::try_from(allocations)
        .map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })?
        .checked_add(1)
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })?;
    Ok(ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, fixed),
        (ResourceClass::QueuedBytes, queued),
        (ResourceClass::ParsingOrCpuWork, queued),
        (ResourceClass::OpaqueDependencyResidual, allocations),
    ])?)
}

pub(crate) fn checked_measure_add(
    left: (usize, usize, usize),
    right: (usize, usize, usize),
) -> Result<(usize, usize, usize), ResourceMailboxItemError> {
    Ok((
        left.0
            .checked_add(right.0)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        left.1
            .checked_add(right.1)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::QueuedBytes,
            })?,
        left.2
            .checked_add(right.2)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?,
    ))
}

pub(crate) fn strings_measure<'a>(
    strings: impl IntoIterator<Item = &'a str>,
) -> Result<(usize, usize, usize), ResourceMailboxItemError> {
    strings
        .into_iter()
        .try_fold((0usize, 0usize, 0usize), |measure, value| {
            let bytes = measure.0.checked_add(value.len()).ok_or(
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                },
            )?;
            let queued = measure.1.checked_add(value.len()).ok_or(
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::QueuedBytes,
                },
            )?;
            let allocations = measure
                .2
                .checked_add(usize::from(!value.is_empty()))
                .ok_or(ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            Ok((bytes, queued, allocations))
        })
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxItemError {
    #[error("mailbox item claim is not representable: {0}")]
    Claim(#[from] ResourceClaimArithmeticError),
    #[error("mailbox item could not be measured: {0}")]
    Measurement(&'static str),
}

/// Why the exact provider charge for a future accepted item could not be
/// planned. Planning acquires nothing; it only applies the same item, node and
/// provider-record arithmetic that [`ResourceMailboxSender::send`] will use.
#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxPlanningError {
    #[error("mailbox item charge could not be represented: {0}")]
    Item(#[from] ResourceMailboxItemError),
    #[error("mailbox provider-record charge could not be represented: {0:?}")]
    Provider(ResourceUnavailable),
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxCreateError {
    #[error("mailbox root claim is not representable: {0}")]
    Claim(#[from] ResourceClaimArithmeticError),
    #[error("mailbox root was refused by the resource provider: {0:?}")]
    Pressure(ResourceUnavailable),
}

#[derive(Debug)]
pub enum ResourceMailboxSendError<T> {
    Claim {
        value: T,
        error: ResourceMailboxItemError,
    },
    Pressure {
        value: T,
        error: ResourceUnavailable,
    },
    Closed(T),
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceMailboxAdmissionError {
    #[error("mailbox item was not representable: {0}")]
    Claim(#[from] ResourceMailboxItemError),
    #[error("mailbox item was refused by the resource provider: {0:?}")]
    Pressure(ResourceUnavailable),
    #[error("mailbox admission is closed")]
    Closed,
}

impl<T> ResourceMailboxSendError<T> {
    pub fn into_value(self) -> T {
        match self {
            Self::Claim { value, .. } | Self::Pressure { value, .. } | Self::Closed(value) => value,
        }
    }

    pub fn pressure(&self) -> Option<ResourceUnavailable> {
        match self {
            Self::Pressure { error, .. } => Some(*error),
            Self::Claim { .. } | Self::Closed(_) => None,
        }
    }

    pub fn into_admission_error(self) -> ResourceMailboxAdmissionError {
        match self {
            Self::Claim { error, .. } => ResourceMailboxAdmissionError::Claim(error),
            Self::Pressure { error, .. } => ResourceMailboxAdmissionError::Pressure(error),
            Self::Closed(_) => ResourceMailboxAdmissionError::Closed,
        }
    }
}

/// Producer for one resource-backed, count-unbounded mailbox.
///
/// Cloning a producer allocates nothing. Every accepted value arrives with one
/// lease for its off-node retention and one lease for the queue node. The
/// mailbox never guesses an item count or acquires authority on the caller's
/// behalf.
pub struct ResourceMailboxSender<T> {
    inner: Arc<MailboxInner<T>>,
}

impl<T> Clone for ResourceMailboxSender<T> {
    fn clone(&self) -> Self {
        self.inner
            .senders
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |senders| senders.checked_add(1),
            )
            .expect("a live Arc bounds the number of mailbox senders");
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Single consumer for a resource-backed mailbox.
pub struct ResourceMailboxReceiver<T> {
    inner: Arc<MailboxInner<T>>,
}

/// One delivered value. Its off-node retention stays funded until this value
/// is consumed or dropped; the queue-node lease is released by the pop.
pub struct ResourceMailboxDelivery<T> {
    value: T,
    retention: ResourceLease,
}

impl<T> ResourceMailboxDelivery<T> {
    pub fn into_parts(self) -> (T, ResourceLease) {
        (self.value, self.retention)
    }
}

/// Construct one mailbox from its exact local-application owner.
pub fn resource_mailbox<T>(
    owner: LocalApplicationResourceScope,
) -> Result<(ResourceMailboxSender<T>, ResourceMailboxReceiver<T>), ResourceMailboxCreateError> {
    let root = owner
        .acquire(ResourceMailboxSender::<T>::root_claim()?)
        .map_err(ResourceMailboxCreateError::Pressure)?;
    let inner = Arc::new(MailboxInner {
        queue: Mutex::new(LeasedQueue::new()),
        ready: tokio::sync::Notify::new(),
        closed_ready: tokio::sync::Notify::new(),
        closed: std::sync::atomic::AtomicBool::new(false),
        senders: std::sync::atomic::AtomicUsize::new(1),
        owner,
        _root: root,
    });
    Ok((
        ResourceMailboxSender {
            inner: Arc::clone(&inner),
        },
        ResourceMailboxReceiver { inner },
    ))
}

impl<T> ResourceMailboxSender<T> {
    /// Exact claim for the shared mailbox Arc allocation.
    pub fn root_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let bytes = std::mem::size_of::<MailboxInner<T>>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Exact claim for one queue node. Off-node value retention is separate.
    pub fn node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedQueue::<MailboxEntry<T>>::entry_claim()
    }

    fn scheduled_work_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        ResourceClaim::try_from_entries([(ResourceClass::CallbackOrScheduledWork, 1)])
    }

    /// Commit an already-funded value. On closure, both leases and the value
    /// are returned together so the caller observes one lossless refusal.
    ///
    /// The refusal is deliberately stored inline: boxing it would add a fresh
    /// allocation to the mailbox's closed path, where no new resource should
    /// be required merely to hand ownership back to the caller.
    #[allow(clippy::result_large_err)]
    pub(crate) fn accept(
        &self,
        value: T,
        retention: ResourceLease,
        node: ResourceLease,
    ) -> Result<(), (T, ResourceLease, ResourceLease)> {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err((value, retention, node));
        }
        let mut queue = self.inner.queue.lock();
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err((value, retention, node));
        }
        queue.push(MailboxEntry { value, retention }, node);
        drop(queue);
        self.inner.ready.notify_one();
        Ok(())
    }

    /// Close admission and wake the consumer. Already accepted entries remain
    /// available to drain.
    pub fn close(&self) {
        let queue = self.inner.queue.lock();
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        drop(queue);
        self.inner.ready.notify_waiters();
        self.inner.closed_ready.notify_waiters();
    }

    /// Wait until admission closes, including closure caused by the receiver
    /// being dropped. Register before re-checking the flag so closure cannot be
    /// lost between observation and suspension. Closure notifications are
    /// deliberately separate from value-arrival notifications, so a close
    /// witness can never consume the receiver's wake.
    pub async fn closed(&self) {
        loop {
            if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let notified = self.inner.closed_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

impl<T: ResourceMailboxItem> ResourceMailboxSender<T> {
    /// Exact provider capacity consumed by accepting this concrete value.
    ///
    /// The mailbox makes two reservations per item: one for the value plus its
    /// scheduled-work obligation, and one for the queue node. This planning
    /// result includes the provider's bookkeeping record for each reservation.
    /// It creates no scope, lease or admission and is intended for owners that
    /// must size a finite grant from the production admission shape.
    pub fn accepted_item_planning_charge(
        value: &T,
    ) -> Result<ResourceClaim, ResourceMailboxPlanningError> {
        let scheduled = Self::scheduled_work_claim().map_err(ResourceMailboxItemError::from)?;
        let retention = value
            .retained_claim()?
            .checked_add(scheduled)
            .map_err(ResourceMailboxItemError::from)?;
        let retention = super::FiniteResourceProvider::reservation_planning_charge(retention)
            .map_err(ResourceMailboxPlanningError::Provider)?;
        let node = Self::node_claim().map_err(ResourceMailboxItemError::from)?;
        let node = super::FiniteResourceProvider::reservation_planning_charge(node)
            .map_err(ResourceMailboxPlanningError::Provider)?;
        retention
            .checked_add(node)
            .map_err(ResourceMailboxItemError::from)
            .map_err(ResourceMailboxPlanningError::from)
    }

    /// Exact provider charge for accepting one concrete item in a fixture.
    ///
    /// Production admission deliberately acquires the retained value and the
    /// queue node as two reservations. Tests that size a finite provider must
    /// price those same reservations from this implementation rather than
    /// restating their claims and silently borrowing capacity from another
    /// subsystem.
    #[cfg(test)]
    pub(crate) fn accepted_item_charge_for_test(value: &T) -> ResourceClaim {
        Self::accepted_item_planning_charge(value)
            .expect("fixture mailbox accepted-item charge is representable")
    }

    /// Measure and admit one value. Refusal returns the exact value and never
    /// leaves a node, retained allocation, or scheduled-work charge behind.
    pub fn send(&self, value: T) -> Result<(), ResourceMailboxSendError<T>> {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ResourceMailboxSendError::Closed(value));
        }
        let retention_claim = match value.retained_claim().and_then(|claim| {
            claim
                .checked_add(Self::scheduled_work_claim()?)
                .map_err(Into::into)
        }) {
            Ok(claim) => claim,
            Err(error) => return Err(ResourceMailboxSendError::Claim { value, error }),
        };
        let retention = match self.inner.owner.acquire(retention_claim) {
            Ok(lease) => lease,
            Err(error) => return Err(ResourceMailboxSendError::Pressure { value, error }),
        };
        let node_claim = match Self::node_claim() {
            Ok(claim) => claim,
            Err(error) => {
                return Err(ResourceMailboxSendError::Claim {
                    value,
                    error: error.into(),
                })
            }
        };
        let node = match self.inner.owner.acquire(node_claim) {
            Ok(lease) => lease,
            Err(error) => return Err(ResourceMailboxSendError::Pressure { value, error }),
        };
        self.accept(value, retention, node)
            .map_err(|(value, _retention, _node)| ResourceMailboxSendError::Closed(value))
    }
}

impl<T> Drop for ResourceMailboxSender<T> {
    fn drop(&mut self) {
        let previous = self
            .inner
            .senders
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        assert!(previous > 0, "mailbox sender count cannot underflow");
        if previous == 1 {
            self.close();
        }
    }
}

impl<T> ResourceMailboxReceiver<T> {
    pub fn try_recv(&mut self) -> Option<ResourceMailboxDelivery<T>> {
        self.inner
            .queue
            .lock()
            .pop_front()
            .map(|entry| ResourceMailboxDelivery {
                value: entry.value,
                retention: entry.retention,
            })
    }

    pub async fn recv(&mut self) -> Option<ResourceMailboxDelivery<T>> {
        loop {
            let inner = std::sync::Arc::clone(&self.inner);
            let notified = inner.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(delivery) = self.try_recv() {
                return Some(delivery);
            }
            if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            notified.await;
        }
    }
}

impl<T> Drop for ResourceMailboxReceiver<T> {
    fn drop(&mut self) {
        let mut queue = self.inner.queue.lock();
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        while queue.pop_front().is_some() {}
        drop(queue);
        self.inner.ready.notify_waiters();
        self.inner.closed_ready.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestItem(Vec<u8>);

    impl ResourceMailboxItem for TestItem {
        fn retained_claim(&self) -> Result<ResourceClaim, ResourceMailboxItemError> {
            let bytes = u64::try_from(self.0.len()).map_err(|_| {
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                }
            })?;
            Ok(ResourceClaim::try_from_entries([
                (ResourceClass::AccountedMemoryBytes, bytes),
                (ResourceClass::QueuedBytes, bytes),
                (ResourceClass::OpaqueDependencyResidual, 1),
            ])?)
        }
    }

    fn fixture(
        item: Option<&TestItem>,
    ) -> (
        ResourceMailboxSender<TestItem>,
        ResourceMailboxReceiver<TestItem>,
        super::super::FiniteResourceProvider,
    ) {
        let scopes = super::super::FiniteResourceProvider::scope_record_charge_for_test()
            .checked_scale(2)
            .expect("process and local-application scope records fit");
        let root = super::super::FiniteResourceProvider::reservation_charge_for_test(
            ResourceMailboxSender::<TestItem>::root_claim().expect("mailbox root claim fits"),
        )
        .expect("mailbox root reservation fits");
        let mut grant = scopes.checked_add(root).expect("fixture root grant fits");
        if let Some(item) = item {
            grant = grant
                .checked_add(ResourceMailboxSender::<TestItem>::accepted_item_charge_for_test(item))
                .expect("fixture item grant fits");
        }
        let provider = super::super::FiniteResourceProvider::new(grant);
        let observed = provider.clone();
        let port = super::super::ResourceProviderPort::new(provider)
            .expect("fixture provider admits its process scope");
        let process = super::super::ProcessResourceRoot::isolated();
        process
            .install_local_application_provider(port)
            .expect("fixture installs its local provider");
        let scope = process
            .issue_local_application_scope()
            .expect("fixture issues its local scope");
        let (tx, rx) = resource_mailbox(scope).expect("fixture mailbox is funded");
        (tx, rx, observed)
    }

    #[test]
    fn pressure_returns_the_exact_value_and_retains_no_entry() {
        let item = TestItem(vec![7; 32]);
        let (tx, mut rx, provider) = fixture(None);
        let before = provider.in_use();
        let refused = tx.send(item).expect_err("the fixture funds no item");
        assert!(matches!(
            &refused,
            ResourceMailboxSendError::Pressure { .. }
        ));
        assert_eq!(refused.into_value(), TestItem(vec![7; 32]));
        assert!(rx.try_recv().is_none());
        assert_eq!(provider.in_use(), before);
    }

    #[tokio::test]
    async fn dropping_the_last_sender_wakes_the_receiver_closed() {
        let (tx, mut rx, _provider) = fixture(None);
        let last = tx.clone();
        drop(tx);
        drop(last);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .expect("last-sender close wakes the receiver")
                .is_none()
        );
    }

    #[tokio::test]
    async fn dropping_the_receiver_wakes_a_sender_waiting_for_close() {
        let (tx, rx, _provider) = fixture(None);
        let waiter = tokio::spawn(async move { tx.closed().await });
        tokio::task::yield_now().await;
        drop(rx);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("receiver drop wakes the sender-side close witness")
            .expect("the close witness task completes");
    }

    #[test]
    fn a_value_arrival_never_wakes_the_close_witness() {
        use std::future::Future as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll};

        struct WakeCounter(AtomicUsize);
        impl futures::task::ArcWake for WakeCounter {
            fn wake_by_ref(counter: &std::sync::Arc<Self>) {
                counter.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let item = TestItem(vec![6; 32]);
        let (tx, mut rx, _provider) = fixture(Some(&item));
        let close_probe = tx.clone();
        let close_wakes = std::sync::Arc::new(WakeCounter(AtomicUsize::new(0)));
        let close_waker = futures::task::waker(std::sync::Arc::clone(&close_wakes));
        let mut close_context = Context::from_waker(&close_waker);
        let mut close_waiter = Box::pin(close_probe.closed());
        assert!(matches!(
            close_waiter.as_mut().poll(&mut close_context),
            Poll::Pending
        ));

        tx.send(item.clone()).expect("fixture funds one item");
        assert_eq!(
            close_wakes.0.load(Ordering::SeqCst),
            0,
            "a value notification belongs only to the receiver"
        );

        let receiver_waker = futures::task::noop_waker();
        let mut receiver_context = Context::from_waker(&receiver_waker);
        let mut receive = Box::pin(rx.recv());
        let Poll::Ready(Some(delivery)) = receive.as_mut().poll(&mut receiver_context) else {
            panic!("the accepted value is immediately available to its receiver");
        };
        assert_eq!(delivery.into_parts().0, item);
        drop(receive);
        drop(rx);
        assert_eq!(
            close_wakes.0.load(Ordering::SeqCst),
            1,
            "receiver drop wakes the separate close witness exactly once"
        );
        assert!(matches!(
            close_waiter.as_mut().poll(&mut close_context),
            Poll::Ready(())
        ));
    }

    #[tokio::test]
    async fn close_preserves_an_accepted_entry_until_it_is_drained() {
        let item = TestItem(vec![8; 32]);
        let (tx, mut rx, _provider) = fixture(Some(&item));
        tx.send(item).expect("fixture funds one accepted item");
        tx.close();

        let delivered = rx
            .recv()
            .await
            .expect("close does not discard an already accepted item");
        assert_eq!(delivered.into_parts().0, TestItem(vec![8; 32]));
        assert!(
            rx.recv().await.is_none(),
            "the receiver observes closure only after the accepted prefix drains"
        );
    }

    #[test]
    fn dropping_the_receiver_releases_every_queued_entry() {
        let item = TestItem(vec![9; 32]);
        let (tx, rx, provider) = fixture(Some(&item));
        let before = provider.in_use();
        tx.send(item).expect("fixture funds one item");
        assert_ne!(provider.in_use(), before);
        drop(rx);
        assert_eq!(provider.in_use(), before);
        assert!(matches!(
            tx.send(TestItem(vec![1])),
            Err(ResourceMailboxSendError::Closed(_))
        ));
    }
}
