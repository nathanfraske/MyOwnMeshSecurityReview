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
//! lease that paid for it lives inside it. Popping an entry and dropping the
//! whole queue both move each node out of its `Box` before releasing the node
//! lease. There is no sweep, no capacity term, and nothing to reconcile.
//!
//! **What it deliberately is not.** It carries no waker, no notification, no
//! ceiling and no expiry. Admission is the owner refusing to fund the next
//! entry's claim, which is a decision the provider already makes and this type
//! has no business duplicating. An owner that needs to be woken when an entry
//! arrives composes this with its own signal, so that the signal's lifetime and
//! the storage's lifetime stay separately stated.

use super::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};

/// One retained entry: the caller's value and the link to the next.
///
/// The lease that funds this allocation is deliberately **not** here. It lives
/// in the [`FundedNode`] link that owns the box, because a lease stored inside
/// the allocation it pays for is released by that allocation's own drop glue —
/// which runs while the allocation is still there. See [`FundedNode`].
struct LeasedQueueNode<T> {
    value: T,
    next: Option<FundedNode<T>>,
}

/// A node allocation and the lease that pays for it, in that order.
///
/// **The lease is a sibling of the box, not a field inside it.** The removal
/// paths here were already careful to move a node out of its `Box` before
/// releasing the lease, but care is not a property — [`LeasedQueue::retain`]
/// drops a rejected node without moving it out, and that path released the
/// funding while the allocation was still there. Making the link own the lease
/// makes every path right at once, including the ones that only ever drop.
///
/// The box cannot be taken out. [`Deref`](std::ops::Deref) borrows the node so
/// the chain walks and reversals below read exactly as they did when the links
/// were plain boxes, and [`FundedNode::into_value`] is the single consuming
/// exit, written so the allocation is freed before the lease goes back.
struct FundedNode<T> {
    node: Box<LeasedQueueNode<T>>,
    /// Covers only this queue node's allocation. Any off-node retention in
    /// `value` owns a separate lease for its full lifetime.
    ///
    /// Declared after `node`, and that order is the entire point.
    _entry: ResourceLease,
}

impl<T> std::ops::Deref for FundedNode<T> {
    type Target = LeasedQueueNode<T>;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl<T> std::ops::DerefMut for FundedNode<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl<T> FundedNode<T> {
    /// Detach the value, free its allocation, and only then release its lease.
    ///
    /// Moving out of `*node` frees the allocation at the end of that statement,
    /// and `_entry` — a local from this function's own destructuring — is
    /// released after it, on return. The value is handed back still owning
    /// whatever separate lease its off-node storage holds.
    ///
    /// Callers reach this with `next` already taken, so nothing downstream is
    /// dropped here and this cannot walk the rest of the chain.
    fn into_value(self) -> T {
        let FundedNode { node, _entry } = self;
        let LeasedQueueNode { value, .. } = *node;
        // The allocation is gone as of the statement above. `_entry` is
        // released below, when this frame ends — never before.
        value
    }
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
    ///
    /// Holds the head node's lease as well as the head node, since a link owns
    /// the funding of the node it points at.
    oldest: Option<FundedNode<T>>,
    /// Newest first. Empty until something is pushed onto a live queue.
    newest: Option<FundedNode<T>>,
    len: usize,
}

/// Dropping the queue drops every entry it still holds.
///
/// Written out rather than derived because the derived drop is recursive: it
/// would descend one stack frame per retained entry, and a queue deep enough to
/// be worth accounting is deep enough to overflow the stack while being freed.
/// Unlinking first means every node is dropped with an empty `next`.
///
/// Each node is dropped as a [`FundedNode`]: the value is destroyed, the node's
/// allocation is freed, and only then does its lease go back. An owner whose
/// entry carries a completion signal, a payload lease or a reply channel
/// therefore gets all of them resolved here, with nothing to remember to call.
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
            // `node` drops here with an empty `next`, so this cannot recurse
            // through the rest of the chain. The link owns the ordering: box
            // first, lease after.
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

    /// Everything one entry costs: exactly this queue's node.
    ///
    /// The single calibration point. An owner never writes the node's size
    /// itself — it states only its own retention, and this adds the exact
    /// representation term for the entry that will hold it. The node's size is
    /// `size_of` over the concrete node type, so it already includes the
    /// caller's value inline and the link — and the link is now a pointer *and*
    /// the next node's lease handle, since [`FundedNode`] holds a node's funding
    /// beside its box rather than inside it. That inline lease handle is part of
    /// this allocation and is counted here exactly once, by the node that
    /// allocates it.
    ///
    /// This entry's own lease is not in this allocation at all: it is held by
    /// the previous node's link, or by the queue's `oldest`/`newest` field for a
    /// chain head. Every node allocation is paid for by exactly one claim, taken
    /// here. The residual is 1 because the entry is exactly one allocation.
    ///
    /// Anything `T` retains off-node owns a separate lease inside `T`. That
    /// separation is load-bearing: [`Self::pop_front`] releases the removed
    /// node before returning `T`, while the returned value can remain live for
    /// arbitrarily longer. A combined lease would tell the provider that the
    /// value's retention had ended while the caller still owned it.
    #[must_use = "the entry claim must be acquired before the entry is pushed"]
    pub(crate) fn entry_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record_bytes =
            u64::try_from(std::mem::size_of::<LeasedQueueNode<T>>()).map_err(|_| {
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                }
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, record_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Append one entry, which now owns the lease that funded it.
    ///
    /// Infallible on purpose: the decision was made when the lease was
    /// acquired. A push that could still fail would leave the caller holding a
    /// lease for an entry that does not exist.
    pub(crate) fn push(&mut self, value: T, entry: ResourceLease) {
        self.newest = Some(FundedNode {
            node: Box::new(LeasedQueueNode {
                value,
                next: self.newest.take(),
            }),
            _entry: entry,
        });
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
    ///
    /// Controls only. An owner that wants the oldest entry takes it —
    /// [`Self::pop_front`] — because looking first and then taking is two views
    /// of a queue that can change between them, and the borrow this returns
    /// would have to be released before the take anyway. What the controls need
    /// it for is the opposite: asserting *which* entry is at the front without
    /// consuming it, so the ordering assertion and the release assertion can be
    /// separate.
    #[cfg(test)]
    pub(crate) fn front(&mut self) -> Option<&T> {
        self.expose_front();
        self.oldest.as_ref().map(|node| &node.value)
    }

    /// Remove and return the oldest entry, releasing only its node lease.
    pub(crate) fn pop_front(&mut self) -> Option<T> {
        self.expose_front();
        let mut node = self.oldest.take()?;
        self.oldest = node.next.take();
        // Reached only after a node really came off the chain, so this cannot
        // underflow unless the count and the chain have already diverged —
        // which is the thing worth failing on rather than absorbing.
        self.len = self
            .len
            .checked_sub(1)
            .expect("an entry was removed, so the count was not zero");
        // The node lease funds only the removed node; `into_value` frees that
        // allocation before releasing it. Any off-node retention travels with
        // the value under a lease owned by T.
        Some(node.into_value())
    }

    /// Remove and return the newest entry, releasing only its node lease.
    ///
    /// Used by an owner unwinding an insertion whose subsequent scheduling
    /// link could not be installed. It preserves every older entry and moves no
    /// allocation that remains live.
    pub(crate) fn pop_back(&mut self) -> Option<T> {
        self.merge();
        let mut cursor = &mut self.oldest;
        loop {
            let is_last = cursor.as_ref()?.next.is_none();
            if is_last {
                // Already the tail, so its `next` is empty and nothing else
                // leaves the chain with it.
                let node = cursor.take()?;
                self.len = self
                    .len
                    .checked_sub(1)
                    .expect("an entry was removed, so the count was not zero");
                return Some(node.into_value());
            }
            cursor = &mut cursor.as_mut()?.next;
        }
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
    /// different question about which entry goes. A rejected node is dropped
    /// rather than moved out, and it is [`FundedNode`] that makes that ordering
    /// right: this loop does not have to remember to free before releasing,
    /// because it cannot express the other order.
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

    /// Whether this owner currently retains no queue nodes.
    ///
    /// A consumer normally reaches for `pop_front` directly. The predicate is
    /// also valid immediately after a pop while the caller still holds the
    /// queue's enclosing owner lock: that same-owner observation lets a bounded
    /// service loop reschedule remaining work without racing a producer or
    /// taking an unfenced second look.
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
        chain: Option<FundedNode<T>>,
        acc: Option<FundedNode<T>>,
    ) -> Option<FundedNode<T>> {
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
        _retention: ResourceLease,
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
        let node = LeasedQueue::<ControlEntry>::entry_claim()
            .expect("the control entry claim is representable")
            .checked_add(scope_record)
            .expect("the control entry claim plus its reservation record is representable");
        let retention = control_retention()
            .checked_add(scope_record)
            .expect("the retention claim plus its reservation record is representable");
        (0..entries)
            .try_fold(scope_record, |total, _| {
                total.checked_add(node)?.checked_add(retention)
            })
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
        let node = port
            .acquire(
                scope,
                ResourceAuthorityClass::Admitted,
                LeasedQueue::<ControlEntry>::entry_claim()
                    .expect("the control entry claim is representable"),
            )
            .expect("the control grant funds this entry");
        let retention = port
            .acquire(scope, ResourceAuthorityClass::Admitted, control_retention())
            .expect("the control grant funds this value's retention");
        queue.push(
            ControlEntry {
                order,
                dropped: Arc::clone(dropped),
                _retention: retention,
            },
            node,
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

        let removed = queue.pop_front().expect("one entry is queued");
        let after_one = provider.in_use();
        assert!(
            after_one.amount(ResourceClass::QueuedBytes) == full.amount(ResourceClass::QueuedBytes),
            "taking one entry keeps its off-node retention funded while the value lives"
        );
        assert!(
            after_one.amount(ResourceClass::AccountedMemoryBytes)
                < full.amount(ResourceClass::AccountedMemoryBytes),
            "taking one entry releases exactly its queue node"
        );
        drop(removed);
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
        let (provider, port, scope) = control_provider(5);
        let mut queue = LeasedQueue::new();
        for order in 1..=3 {
            push_control_entry(&mut queue, &port, &scope, order, &dropped);
        }
        // Entries in both chains at once: the front lookup draws the first
        // three across, then two more land newest-first on the push chain. A
        // drop that skipped the merge would destroy that second chain as 5, 4
        // instead of 4, 5, which makes the merge itself load-bearing here.
        assert_eq!(queue.front().map(|entry| entry.order), Some(1));
        for order in 4..=5 {
            push_control_entry(&mut queue, &port, &scope, order, &dropped);
        }
        assert!(dropped_orders(&dropped).is_empty());

        drop(queue);

        assert_eq!(
            dropped_orders(&dropped),
            vec![1, 2, 3, 4, 5],
            "every entry's own drop ran, oldest first — which is the order an \
             owner's per-entry completion signals are answered in"
        );
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            0,
            "no entry's retention outlived the queue that held it"
        );
    }

    /// The entry claim states only the node; value retention is independent.
    #[test]
    fn v4_arc05_the_entry_claim_charges_only_the_queue_node() {
        let retention = control_retention();
        let entry = LeasedQueue::<ControlEntry>::entry_claim()
            .expect("the control entry claim is representable");

        assert_eq!(
            entry.amount(ResourceClass::QueuedBytes),
            0,
            "the value's off-node retention is not released with the node"
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
