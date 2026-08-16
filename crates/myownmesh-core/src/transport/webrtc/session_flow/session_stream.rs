//! One session-scoped signal, and the single consumer that holds it.
//!
//! The producer half stores items and stores at most one wake; the consumer
//! half is a lease over that signal, held by whoever is currently reading. The
//! two are separate types because the lifetimes are: the stream dies with the
//! session's flow set, and the reader can come and go while it lives.
//!
//! Closure is the drop, here as everywhere in this lane. Nothing announces the
//! end of a stream, because an announcement is an item that could be lost,
//! reordered, or delivered twice, and the drop can be none of those.

use super::*;

/// One session-scoped, single-consumer stream.
///
/// The same mechanical-closure shape as [`RealtimeFlowQueue`], for the same
/// reasons and with the same two non-negotiables: `notify_one` in `Drop`, so
/// the wake survives the gap between observing empty and parking; and a claim
/// guard, so exactly one consumer can ever be waiting on that single permit.
///
/// Session-scoped rather than per-flow because the consumer is one task
/// serving every flow of a session. Per-flow signals would leave it choosing
/// between polling each flow on a timer and sweeping the whole label space,
/// and both of those answer "has anything arrived" by asking as many questions
/// as the session has names instead of being told once. This way it parks once
/// and is woken by exactly the thing it was waiting for.
///
/// The items are held in a [`crate::resource::LeasedQueue`], so one queued item
/// is one funded allocation and taking it releases exactly that. A ring would
/// have kept — and left unaccounted — the space every burst ever needed, for as
/// long as the session lasted.
pub(super) struct SessionStream<T> {
    items: SyncMutex<crate::resource::LeasedQueue<T>>,
    pub(super) ready: Arc<tokio::sync::Notify>,
    claimed: std::sync::atomic::AtomicBool,
}

/// Dropping the stream ends it.
///
/// Retirement is the drop, never a message inside the stream. A `Retired`
/// item would be a second fact that could be dropped, reordered, or emitted
/// twice; the end of the stream is the drop itself and can be none of those.
impl<T> Drop for SessionStream<T> {
    fn drop(&mut self) {
        self.ready.notify_one();
    }
}

impl<T> SessionStream<T> {
    pub(super) fn new() -> Self {
        Self {
            items: SyncMutex::new(crate::resource::LeasedQueue::new()),
            ready: Arc::new(tokio::sync::Notify::new()),
            claimed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Claim the right to be this stream's reader, if nobody currently holds
    /// it.
    ///
    /// A CAS rather than a swap, and *currently* rather than *ever*: the claim
    /// is a lease held by a live [`SessionStreamReader`] and returned when
    /// that reader drops. A daemon whose consumer pipe dies must be able to
    /// reconnect to the same session, and a one-shot claim would have made the
    /// session unreadable for the rest of its life over a client that hung up.
    ///
    /// One holder at a time is still enforced, and still for the original
    /// reason: closure is delivered by a single stored permit, so two
    /// simultaneous waiters would leave one that never wakes.
    pub(super) fn claim(&self) -> bool {
        self.claimed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    /// Append one item, in the node its `record` lease already paid for.
    ///
    /// Synchronous and lock-scoped: producers run under the registry mutation
    /// lock, and the guard is released before the wake.
    pub(super) fn push(&self, item: T, record: crate::resource::ResourceLease) {
        {
            let mut items = self.items.lock();
            items.push(item, record);
        }
        self.ready.notify_one();
    }

    /// Take the oldest item, releasing the node that held it.
    fn take(&self) -> Option<T> {
        self.items.lock().pop_front()
    }

    /// Drop every queued item `discard` answers true for, in place.
    ///
    /// Order-preserving, and each discarded item is destroyed where it sat: its
    /// node's record lease and whatever the item itself holds are released at
    /// the moment it stops being queued, not at some later sweep.
    ///
    /// It exists for exactly one caller — a close, which must not leave units
    /// addressed to a name the session is about to make claimable again. No
    /// wake is emitted: nothing arrived, and a consumer that was parked has
    /// strictly less to take than before, so there is nothing to tell it about.
    pub(super) fn purge(&self, discard: impl FnMut(&T) -> bool) {
        let mut discard = discard;
        self.items.lock().retain(|item| !discard(item));
    }
}

/// The consumer end of a session stream.
///
/// Deliberately holds only a `Weak`. A reader can never keep a session's flow
/// set alive, which is what lets the set's drop be the end-of-stream rather
/// than something that has to be announced before it happens.
pub(crate) struct SessionStreamReader<T> {
    pub(super) stream: std::sync::Weak<SessionStream<T>>,
    /// Strong on purpose: it has to outlive the stream in order to deliver the
    /// very wake that says the stream is gone.
    pub(super) ready: Arc<tokio::sync::Notify>,
}

/// The reader *is* the claim.
///
/// Returning it on drop is what makes a consumer reconnectable: a daemon whose
/// client pipe dies drops its reader, and the next one takes the lease and
/// picks up the queue where the first left it. Nothing is lost in the gap
/// because items accumulate on the stream, not in the reader.
///
/// Nothing to return once the stream is gone, and nothing that could take it:
/// a lease is only ever issued by the session's flow set, so when that set has
/// been dropped there is no object left to ask.
impl<T> Drop for SessionStreamReader<T> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.upgrade() {
            stream
                .claimed
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
}

impl<T> SessionStreamReader<T> {
    /// The next item, or `None` once the session's flow set has been dropped.
    ///
    /// `None` is terminal. It means the promoted session that owned these
    /// flows is gone, so there will never be another item and the consumer
    /// should end.
    ///
    /// **Holds nothing across the await.** Not the registry mutation lock —
    /// the caller obtained this reader and released that lock long before
    /// awaiting. Not the stream's own lock, which `take` releases before
    /// returning. And not a strong reference to the stream: the upgraded `Arc`
    /// is dropped at the end of the `if let`, because a reader parked while
    /// holding one would keep the flow set alive and wait forever for an end
    /// it was itself preventing.
    pub(crate) async fn next(&self) -> Option<T> {
        loop {
            if let Some(stream) = self.stream.upgrade() {
                if let Some(item) = stream.take() {
                    return Some(item);
                }
            } else {
                return None;
            }
            self.ready.notified().await;
        }
    }

    /// The next item if one is already queued, without waiting.
    ///
    /// One take from the same queue, registering no waker and consuming no
    /// wake. `None` covers both an empty live stream and a dropped one, because
    /// neither answer involves waiting to find out which.
    ///
    /// Gated to the same conjunction as [`RealtimeInboundArrivals::try_next`],
    /// because that wrapper is its only caller and this is compiled exactly when
    /// it is.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn try_next(&self) -> Option<T> {
        self.stream.upgrade()?.take()
    }
}
