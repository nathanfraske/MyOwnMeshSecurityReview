//! A FIFO in which every retained entry owns exactly one allocation and pays
//! for exactly that allocation.
//!
//! **Why not `VecDeque`.** A ring buffer's allocation is not a property of what
//! it holds: it grows by doubling, keeps the spare half after the queue drains,
//! and reallocates the whole buffer on a push that no single entry asked for.
//! An owner accounting a ring exactly would have to charge the capacity rather
//! than the entries — and then release nothing when an entry is popped, because
//! the capacity is still there. The result is either an under-charge that grows
//! silently under load or a per-entry lease that describes memory the entry does
//! not own. Both are the same defect: the accounting and the representation
//! disagree.
//!
//! Here they cannot disagree. One entry is one `Box`, whose size is
//! `size_of::<LeasedQueueNode<T>>()` and whose spare capacity is zero, and the
//! lease that paid for it lives inside it. Popping the entry drops the lease;
//! dropping the queue drops every entry and therefore every lease. There is no
//! sweep, no capacity term, and nothing to reconcile.
//!
//! **What it deliberately is not.** It carries no waker, no notification, no
//! ceiling and no expiry. Admission is the owner refusing to fund the next
//! entry's claim, which is a decision the provider already makes and this type
//! has no business duplicating. An owner that needs to be woken when an entry
//! arrives composes this with its own signal, so that the signal's lifetime and
//! the storage's lifetime stay separately stated.

use super::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};

/// One retained entry: the caller's value, the lease that paid for this node,
/// and the link to the next.
///
/// Field order is the drop order and is chosen: the value is destroyed first,
/// and only then is the allocation that held it paid back. A lease released
/// before the thing it accounts for is gone would leave a window in which the
/// provider believes memory is free while it is still occupied.
struct LeasedQueueNode<T> {
    value: T,
    /// Covers this node's allocation and whatever the caller retained with it.
    _entry: ResourceLease,
    next: Option<Box<LeasedQueueNode<T>>>,
}

/// A first-in, first-out queue whose every entry is separately funded.
///
/// Held as two chains rather than one so that appending is O(1) without any
/// tail pointer: `oldest` runs oldest-first and is what readers see, `newest`
/// runs newest-first and is where pushes land. They are merged lazily, and only
/// by the operations that actually need the whole order.
///
/// Generic over the entry because the shape — exact per-entry funding, release
/// on removal, release on drop — is the same fact for an inbound realtime unit
/// and for a retained reliable frame, and two copies of it would be two places
/// to get the drop order wrong.
pub(crate) struct LeasedQueue<T> {
    /// Oldest first. The head is the front of the queue whenever it is present.
    oldest: Option<Box<LeasedQueueNode<T>>>,
    /// Newest first. Empty until something is pushed onto a live queue.
    newest: Option<Box<LeasedQueueNode<T>>>,
    len: usize,
}

/// Dropping the queue drops every entry it still holds.
///
/// Written out rather than derived because the derived drop is recursive: it
/// would descend one stack frame per retained entry, and a queue deep enough to
/// be worth accounting is deep enough to overflow the stack while being freed.
/// Unlinking first means every node is dropped with an empty `next`.
///
/// Each node's own drop is what releases that entry — the value first, then its
/// lease — so an owner whose entry carries a completion signal, a payload lease
/// or a reply channel gets all of them resolved by this, with nothing to
/// remember to call.
///
/// The chains are merged first, so entries are destroyed oldest-first. Dropping
/// the push chain as it stands would destroy the newest entries first, and an
/// owner whose entries resolve a caller's completion signal would then answer
/// its callers backwards on the one path where every one of them answers at
/// once. Merging is the same order of work as the drop it precedes.
impl<T> Drop for LeasedQueue<T> {
    fn drop(&mut self) {
        self.merge();
        let mut cursor = self.oldest.take();
        while let Some(mut node) = cursor {
            cursor = node.next.take();
        }
    }
}

impl<T> Default for LeasedQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LeasedQueue<T> {
    pub(crate) const fn new() -> Self {
        Self {
            oldest: None,
            newest: None,
            len: 0,
        }
    }

    /// Everything one entry costs: this queue's node, plus whatever the caller
    /// retains inside it.
    ///
    /// The single calibration point. An owner never writes the node's size
    /// itself — it states only its own retention, and this adds the exact
    /// representation term for the entry that will hold it. The node's size is
    /// `size_of` over the concrete node type, so it already includes the
    /// caller's value inline, the lease handle, and the link; the residual is 1
    /// because the entry is exactly one allocation.
    ///
    /// `retained` is the caller's own claim for that entry and nothing is
    /// assumed about it: a queue of inline values passes
    /// [`ResourceClaim::ZERO`], and a queue of entries owning a heap payload
    /// passes that payload's bytes. Acquiring the resulting claim is the
    /// caller's, because the scope and the authority class are the owner's
    /// facts, and a refusal is the owner's error to report.
    #[must_use = "the entry claim must be acquired before the entry is pushed"]
    pub(crate) fn entry_claim(
        retained: ResourceClaim,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record_bytes =
            u64::try_from(std::mem::size_of::<LeasedQueueNode<T>>()).map_err(|_| {
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                }
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, record_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])?
        .checked_add(retained)
    }

    /// Append one entry, which now owns the lease that funded it.
    ///
    /// Infallible on purpose: the decision was made when the lease was
    /// acquired. A push that could still fail would leave the caller holding a
    /// lease for an entry that does not exist.
    pub(crate) fn push(&mut self, value: T, entry: ResourceLease) {
        self.newest = Some(Box::new(LeasedQueueNode {
            value,
            _entry: entry,
            next: self.newest.take(),
        }));
        // Not saturating: the count and the chain must agree, and a saturated
        // count would disagree silently. It cannot overflow either — every
        // entry is a live allocation, so `usize::MAX` of them is unreachable —
        // which is exactly why stating the invariant costs nothing.
        self.len = self
            .len
            .checked_add(1)
            .expect("one live allocation per entry bounds the count");
    }

    /// The oldest entry, without removing it.
    ///
    /// Takes `&mut self` because answering may require moving the push chain
    /// across, which is a change to the representation and not to the contents.
    pub(crate) fn front(&mut self) -> Option<&T> {
        self.expose_front();
        self.oldest.as_ref().map(|node| &node.value)
    }

    /// Remove and return the oldest entry, releasing that entry's lease.
    pub(crate) fn pop_front(&mut self) -> Option<T> {
        self.expose_front();
        let node = *self.oldest.take()?;
        let LeasedQueueNode {
            value,
            _entry,
            next,
        } = node;
        self.oldest = next;
        // Reached only after a node really came off the chain, so this cannot
        // underflow unless the count and the chain have already diverged —
        // which is the thing worth failing on rather than absorbing.
        self.len = self
            .len
            .checked_sub(1)
            .expect("an entry was removed, so the count was not zero");
        // `_entry` is released here, after the value it funded has been handed
        // back to the caller and is no longer this queue's to account for.
        Some(value)
    }

    /// Every entry, oldest first, mutable in place.
    ///
    /// In place rather than remove-and-reinsert because the entries an owner
    /// mutates — marking one written, recording one acknowledged — must keep
    /// both their position and their lease. Reinserting would reorder the queue
    /// and re-fund an entry that never stopped existing.
    pub(crate) fn iter_mut(&mut self) -> LeasedQueueIterMut<'_, T> {
        self.merge();
        LeasedQueueIterMut {
            cursor: self.oldest.as_deref_mut(),
        }
    }

    /// Every entry, oldest first.
    pub(crate) fn iter(&mut self) -> LeasedQueueIter<'_, T> {
        self.merge();
        LeasedQueueIter {
            cursor: self.oldest.as_deref(),
        }
    }

    /// Keep the entries `keep` answers `true` for, in order, and drop the rest.
    ///
    /// The one removal that is not from the front, and it exists because some
    /// owners are tables rather than pipelines: a binding table forgets every
    /// entry naming a closed flow, wherever those entries sit. Each removed
    /// entry is dropped here, which releases its funding at the moment it stops
    /// being retained — the same rule as [`Self::pop_front`], applied to a
    /// different question about which entry goes.
    ///
    /// Kept entries keep their nodes and their leases. Nothing is reallocated
    /// and nothing is re-funded, because nothing that stays ever stopped
    /// existing.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        self.merge();
        let mut kept = None;
        let mut len = 0;
        let mut cursor = self.oldest.take();
        while let Some(mut node) = cursor {
            cursor = node.next.take();
            if keep(&node.value) {
                node.next = kept;
                kept = Some(node);
                len += 1;
            }
            // Otherwise `node` is dropped here, with an empty `next`: its value
            // first, then the lease that funded it.
        }
        // `kept` came out newest-first; one reversal restores insertion order.
        self.oldest = Self::reverse_onto(kept, None);
        self.len = len;
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Controls only. An owner that wants to know whether there is work reaches
    /// for the entry itself — `front` or `pop_front` — because the answer it
    /// actually needs is the entry, and asking emptiness first would be a second
    /// look at a queue that can change between the two.
    #[cfg(test)]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Make the head of `oldest` be the front of the queue.
    ///
    /// Only moves anything when `oldest` has run out, which is what keeps
    /// pushing and popping amortised constant: each entry is moved across at
    /// most once in its life. A merge on every access would be correct and
    /// quadratic.
    fn expose_front(&mut self) {
        if self.oldest.is_none() {
            self.oldest = Self::reverse_onto(self.newest.take(), None);
        }
    }

    /// Collapse both chains into `oldest`, in order.
    ///
    /// Three reversals rather than a walk to the tail. Appending would mean
    /// holding a mutable borrow that advances through the chain and is used
    /// after the loop that advanced it; reversing moves whole nodes instead, so
    /// the ordering is stated by the data movement and needs no borrow to
    /// survive the loop.
    fn merge(&mut self) {
        if self.newest.is_none() {
            return;
        }
        // Reversed, the read chain runs newest-first, which is the same
        // direction as the push chain — so prepending the push chain's entries
        // and then that reversal's entries yields one oldest-first chain.
        let reversed_oldest = Self::reverse_onto(self.oldest.take(), None);
        let ordered = Self::reverse_onto(self.newest.take(), None);
        self.oldest = Self::reverse_onto(reversed_oldest, ordered);
    }

    /// Prepend every node of `chain`, in chain order, onto `acc`.
    ///
    /// Moves nodes; allocates nothing and drops nothing.
    fn reverse_onto(
        chain: Option<Box<LeasedQueueNode<T>>>,
        acc: Option<Box<LeasedQueueNode<T>>>,
    ) -> Option<Box<LeasedQueueNode<T>>> {
        let mut cursor = chain;
        let mut acc = acc;
        while let Some(mut node) = cursor {
            cursor = node.next.take();
            node.next = acc;
            acc = Some(node);
        }
        acc
    }
}

/// A borrowing walk over the entries, oldest first.
pub(crate) struct LeasedQueueIter<'a, T> {
    cursor: Option<&'a LeasedQueueNode<T>>,
}

impl<'a, T> Iterator for LeasedQueueIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.cursor.take()?;
        self.cursor = node.next.as_deref();
        Some(&node.value)
    }
}

/// A mutating walk over the entries, oldest first.
pub(crate) struct LeasedQueueIterMut<'a, T> {
    cursor: Option<&'a mut LeasedQueueNode<T>>,
}

impl<'a, T> Iterator for LeasedQueueIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.cursor.take()?;
        self.cursor = node.next.as_deref_mut();
        Some(&mut node.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };
    use std::sync::{Arc, Mutex};

    /// Where a destroyed entry records itself, in the order it was destroyed.
    type DropLog = Arc<Mutex<Vec<u64>>>;

    fn drop_log() -> DropLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn dropped_orders(log: &DropLog) -> Vec<u64> {
        log.lock()
            .expect("the control drop log is uncontended")
            .clone()
    }

    /// An entry that reports its own destruction, and when.
    ///
    /// Stands in for the entries real owners hold: a payload lease, a reply
    /// channel, a completion signal. What matters is that the queue runs its
    /// `Drop`, because that is what resolves those truthfully when a session is
    /// replaced rather than drained — and that it runs them oldest-first, so
    /// callers waiting on those signals are answered in the order they queued.
    struct ControlEntry {
        order: u64,
        dropped: DropLog,
    }

    impl Drop for ControlEntry {
        fn drop(&mut self) {
            self.dropped
                .lock()
                .expect("the control drop log is uncontended")
                .push(self.order);
        }
    }

    /// The retention one control entry declares beyond its node.
    ///
    /// Non-zero and in a dimension the node term does not use, so a claim that
    /// dropped either term is visible rather than absorbed.
    fn control_retention() -> ResourceClaim {
        ResourceClaim::single(ResourceClass::QueuedBytes, 64)
    }

    /// A grant that funds exactly `entries` entries and nothing spare.
    ///
    /// Derived from the same `entry_claim` the queue's owner would use, plus
    /// the provider's own per-reservation and per-scope bookkeeping, so a
    /// control never states a capacity number of its own.
    fn control_grant(entries: u64) -> ResourceClaim {
        let scope_record = FiniteResourceProvider::scope_record_charge_for_test();
        let per_entry = LeasedQueue::<ControlEntry>::entry_claim(control_retention())
            .expect("the control entry claim is representable")
            .checked_add(scope_record)
            .expect("the control entry claim plus its reservation record is representable");
        (0..entries)
            .try_fold(scope_record, |total, _| total.checked_add(per_entry))
            .expect("the bounded control grant is representable")
    }

    fn control_provider(
        entries: u64,
    ) -> (FiniteResourceProvider, ResourceProviderPort, ResourceScope) {
        let provider = FiniteResourceProvider::new(control_grant(entries));
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the control grant accounts for the process scope");
        let scope = port.process_scope();
        (provider, port, scope)
    }

    fn push_control_entry(
        queue: &mut LeasedQueue<ControlEntry>,
        port: &ResourceProviderPort,
        scope: &ResourceScope,
        order: u64,
        dropped: &DropLog,
    ) {
        let entry = port
            .acquire(
                scope,
                ResourceAuthorityClass::Admitted,
                LeasedQueue::<ControlEntry>::entry_claim(control_retention())
                    .expect("the control entry claim is representable"),
            )
            .expect("the control grant funds this entry");
        queue.push(
            ControlEntry {
                order,
                dropped: Arc::clone(dropped),
            },
            entry,
        );
    }

    /// Insertion order survives a push that lands while the read chain is
    /// already occupied.
    ///
    /// This is the exact case a two-chain queue gets wrong by moving the push
    /// chain across whenever it is non-empty: entries 3 and 4 would then be
    /// read before entry 2, which is still waiting. The control is arranged so
    /// that both chains are occupied at once, which a queue that only ever
    /// merges into an empty read chain reaches on the very first interleaved
    /// push.
    #[test]
    fn v4_arc05_insertion_order_survives_a_push_onto_an_occupied_read_chain() {
        let dropped = drop_log();
        let (_provider, port, scope) = control_provider(4);
        let mut queue = LeasedQueue::new();

        push_control_entry(&mut queue, &port, &scope, 1, &dropped);
        push_control_entry(&mut queue, &port, &scope, 2, &dropped);
        // Draws entry 1 across and leaves entry 2 sitting in the read chain.
        assert_eq!(
            queue.pop_front().map(|entry| entry.order),
            Some(1),
            "the first entry pushed is the first entry taken"
        );
        push_control_entry(&mut queue, &port, &scope, 3, &dropped);
        push_control_entry(&mut queue, &port, &scope, 4, &dropped);

        assert_eq!(
            queue.iter().map(|entry| entry.order).collect::<Vec<_>>(),
            vec![2, 3, 4],
            "reading spans both chains in insertion order"
        );
        assert_eq!(queue.front().map(|entry| entry.order), Some(2));
        assert_eq!(queue.len(), 3);
        assert_eq!(
            std::iter::from_fn(|| queue.pop_front())
                .map(|entry| entry.order)
                .collect::<Vec<_>>(),
            vec![2, 3, 4],
            "draining answers the same order the walk reported"
        );
        assert!(queue.is_empty());
    }

    /// One entry leaving releases exactly that entry's funding, and the rest
    /// stays paid for until it leaves too.
    #[test]
    fn v4_arc05_each_entry_releases_its_own_funding_when_it_leaves() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(3);
        let mut queue = LeasedQueue::new();
        for order in 1..=3 {
            push_control_entry(&mut queue, &port, &scope, order, &dropped);
        }

        let full = provider.in_use();
        assert!(
            full.amount(ResourceClass::QueuedBytes) > 0
                && full.amount(ResourceClass::AccountedMemoryBytes) > 0,
            "three funded entries are holding both the retention and the node terms"
        );

        drop(queue.pop_front());
        let after_one = provider.in_use();
        assert!(
            after_one.amount(ResourceClass::QueuedBytes) < full.amount(ResourceClass::QueuedBytes),
            "taking one entry released that entry's retention"
        );
        assert!(
            after_one.amount(ResourceClass::QueuedBytes) > 0,
            "the entries still queued are still paid for"
        );

        // The provider is funded for exactly three entries at a time, so the
        // release is what makes room for a fourth. A queue that released
        // nothing on pop would refuse here.
        push_control_entry(&mut queue, &port, &scope, 4, &dropped);
        assert_eq!(queue.len(), 3);
    }

    /// Dropping the queue drops every entry, oldest first, and releases every
    /// entry's funding.
    #[test]
    fn v4_arc05_dropping_the_queue_drops_and_releases_every_entry() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(4);
        let mut queue = LeasedQueue::new();
        for order in 1..=3 {
            push_control_entry(&mut queue, &port, &scope, order, &dropped);
        }
        // Entries in both chains at once: the front lookup draws the first
        // three across, and the fourth is pushed after it, so a drop that
        // reached only the chain a reader had already touched would leave the
        // fourth entry — and a drop that took the chains as they stand would
        // answer 4 before 1.
        assert_eq!(queue.front().map(|entry| entry.order), Some(1));
        push_control_entry(&mut queue, &port, &scope, 4, &dropped);
        assert!(dropped_orders(&dropped).is_empty());

        drop(queue);

        assert_eq!(
            dropped_orders(&dropped),
            vec![1, 2, 3, 4],
            "every entry's own drop ran, oldest first — which is the order an \
             owner's per-entry completion signals are answered in"
        );
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            0,
            "no entry's retention outlived the queue that held it"
        );
    }

    /// The entry claim states the node and the caller's retention, and neither
    /// term is the other.
    #[test]
    fn v4_arc05_the_entry_claim_charges_the_node_beside_the_callers_retention() {
        let retention = control_retention();
        let entry = LeasedQueue::<ControlEntry>::entry_claim(retention)
            .expect("the control entry claim is representable");

        assert_eq!(
            entry.amount(ResourceClass::QueuedBytes),
            retention.amount(ResourceClass::QueuedBytes),
            "the caller's retention is carried through unchanged"
        );
        assert_eq!(
            entry.amount(ResourceClass::AccountedMemoryBytes),
            u64::try_from(std::mem::size_of::<LeasedQueueNode<ControlEntry>>())
                .expect("the node size is representable"),
            "the node term is the exact size of one entry's single allocation"
        );
        assert_eq!(
            entry.amount(ResourceClass::OpaqueDependencyResidual),
            1,
            "one entry is one allocation"
        );

        // Non-vacuity: the node term is not zero, so a claim that dropped it
        // would differ from this one rather than coincide with it.
        assert_ne!(
            entry.amount(ResourceClass::AccountedMemoryBytes),
            retention.amount(ResourceClass::AccountedMemoryBytes)
        );
    }
}
