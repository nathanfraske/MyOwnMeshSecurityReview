//! An ordered map in which every entry owns exactly one allocation and pays for
//! exactly that allocation.
//!
//! **Why not `BTreeMap`.** A B-tree entry does not own an allocation. Several
//! entries share a node, and the node is freed only when it empties, so an
//! owner charging per entry and releasing per removal releases memory the
//! allocator still holds: a map that fills and drains gives back everything it
//! claimed while the nodes are still there. The bytes of a slot are real, but
//! the *allocation* term cannot be released at the moment an entry leaves,
//! because nothing about that moment says whether an allocation left with it.
//!
//! **Why not a sorted `Vec` either.** That makes the collection's capacity
//! exact, which is a different thing from making an entry's cost exact: the
//! buffer and its slack survive every removal, so no entry can release its own
//! share, and the shift on each insert and remove is linear in the session's
//! own size — which an adversary chooses.
//!
//! **A treap.** One `Box` per entry, so `size_of::<LeasedMapNode<K, V>>()` is
//! the allocation and there is no spare capacity anywhere. Ordered by key for
//! lookup, heap-ordered by a priority derived from hashing the key, which keeps
//! the expected depth logarithmic without any rebalancing that allocates.
//! Insertion and removal move nodes by rotation and allocate nothing beyond the
//! one node being added.
//!
//! **The priority is not identity and not authority.** It is a balancing detail
//! and nothing reads it but the rotations below. It is derived per map from a
//! [`std::collections::hash_map::RandomState`], so it is unpredictable across
//! processes and a peer choosing names cannot choose a shape.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};

use super::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};

/// One retained entry: the caller's key and value, the lease that paid for this
/// node, and the two links.
///
/// Field order is the drop order and is chosen: the key and value are destroyed
/// first, and only then is the allocation that held them paid back. A lease
/// released before the thing it accounts for is gone would leave a window in
/// which the provider believes memory is free while it is still occupied.
struct LeasedMapNode<K, V> {
    key: K,
    value: V,
    /// Covers only this map node's allocation. Any off-node retention in
    /// `key` or `value` owns a separate lease for its full lifetime.
    _entry: ResourceLease,
    /// Heap order. A balancing detail — never compared for identity, never
    /// serialized, never shown to a caller.
    priority: u64,
    left: Option<Box<LeasedMapNode<K, V>>>,
    right: Option<Box<LeasedMapNode<K, V>>>,
}

/// The candidate an insert refused, still in the node that was allocated and
/// funded for it.
///
/// **One pointer, and the refusal costs no allocation of its own.** The insert
/// had already boxed the key, the value and the lease before it discovered the
/// collision, so handing that same box back is both the cheapest and the most
/// truthful answer: nothing was unpacked, nothing was rebuilt, and the caller
/// holds exactly what it supplied.
///
/// **Dropping it is the release, and there is nothing else to do with it.** The
/// node's fields are destroyed in declaration order — key, then value, then the
/// lease that paid for all three — so the funding goes back only once what it
/// accounted for is gone. Its links were never attached, so this is a leaf's
/// drop and cannot recurse.
///
/// There is deliberately no accessor. A caller that could take the value back
/// out would be holding a payload whose lease had already been released with
/// the node around it, and every caller in the crate wants only the fact of the
/// refusal.
pub(crate) struct RefusedEntry<K, V> {
    /// Never read; it exists to be dropped. Underscored for the same reason a
    /// node's `_entry` is: the whole content of this field is its destructor.
    _node: Box<LeasedMapNode<K, V>>,
}

/// Names the refusal and nothing inside it.
///
/// Needed because callers `expect` on this result, and deliberately not derived:
/// a derived `Debug` would demand `K: Debug` and `V: Debug` of every map, and
/// would put a caller's payload and its accounting handle into a panic message.
/// Which key collided is already known to the caller that supplied it.
impl<K, V> std::fmt::Debug for RefusedEntry<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefusedEntry")
    }
}

/// An ordered map whose every entry is separately funded.
///
/// Generic over key and value because the shape — exact per-entry funding,
/// release on removal, release on drop — is the same fact for a session's held
/// names and for its live flows, and two copies of it would be two places to
/// get the drop order wrong.
pub(crate) struct LeasedMap<K, V> {
    root: Option<Box<LeasedMapNode<K, V>>>,
    len: usize,
    /// Seeds the per-entry priority. Per map and per process, so the tree's
    /// shape is not a function a caller can compute.
    priorities: RandomState,
}

/// Dropping the map drops every entry it still holds.
///
/// Written out rather than derived because the derived drop is recursive: it
/// would descend one stack frame per level, and although a treap's expected
/// depth is logarithmic, a teardown that is only *probably* shallow is not a
/// property worth relying on when the alternative is this short.
///
/// The tree is flattened toward a right spine by rotation and then unlinked, so
/// every node is dropped with both children empty and nothing is allocated
/// while freeing. Entries are destroyed in key order, which is incidental but
/// makes the teardown observable rather than arbitrary.
impl<K, V> Drop for LeasedMap<K, V> {
    fn drop(&mut self) {
        let mut root = self.root.take();
        while let Some(mut node) = root {
            match node.left.take() {
                Some(mut pivot) => {
                    // Rotate the left child up. No allocation, and the tree
                    // shrinks toward a spine one step at a time.
                    node.left = pivot.right.take();
                    pivot.right = Some(node);
                    root = Some(pivot);
                }
                None => {
                    root = node.right.take();
                    // `node` drops here with no children: its key and value
                    // first, then the lease that funded it.
                }
            }
        }
    }
}

impl<K, V> Default for LeasedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> LeasedMap<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            root: None,
            len: 0,
            priorities: RandomState::new(),
        }
    }

    /// Everything one entry costs: exactly this map's node.
    ///
    /// The single calibration point. An owner never writes the node's size
    /// itself. The node's size is
    /// `size_of` over the concrete node type, so it already includes the key
    /// and value inline, the lease handle, the priority and both links; the
    /// residual is 1 because the entry is exactly one allocation, and unlike a
    /// B-tree slot that residual is released at the moment the entry is.
    /// Off-node retention owned by `K` or `V` carries its own lease in that
    /// value, so removal may release this node and safely return both values.
    #[must_use = "the entry claim must be acquired before the entry is inserted"]
    pub(crate) fn entry_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record_bytes =
            u64::try_from(std::mem::size_of::<LeasedMapNode<K, V>>()).map_err(|_| {
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                }
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, record_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// How many entries are live.
    ///
    /// Controls only. No owner asks a leased map its size: what an owner is
    /// bounded by is its grant, and the entry count is a second number that
    /// could disagree with it. The count exists because the controls below have
    /// to check that a removal removed exactly one node and no more, which the
    /// resource ledger alone cannot say.
    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }
}

impl<K: Ord + Hash, V> LeasedMap<K, V> {
    /// Whether any live value satisfies `predicate`, without allocating an
    /// iterator stack or exposing the map's representation.
    pub(crate) fn any_value(&self, mut predicate: impl FnMut(&V) -> bool) -> bool {
        fn visit<K, V>(
            node: Option<&LeasedMapNode<K, V>>,
            predicate: &mut impl FnMut(&V) -> bool,
        ) -> bool {
            let Some(node) = node else { return false };
            predicate(&node.value)
                || visit(node.left.as_deref(), predicate)
                || visit(node.right.as_deref(), predicate)
        }
        visit(self.root.as_deref(), &mut predicate)
    }

    /// Borrow one live value satisfying `predicate` mutably.
    ///
    /// The walk allocates nothing. It is used for bounded teardown quanta: one
    /// retained child is removed under the owner lock, then dropped after the
    /// lock is released.
    pub(crate) fn find_value_mut(
        &mut self,
        mut predicate: impl FnMut(&V) -> bool,
    ) -> Option<&mut V> {
        fn visit<'a, K, V>(
            node: Option<&'a mut LeasedMapNode<K, V>>,
            predicate: &mut impl FnMut(&V) -> bool,
        ) -> Option<&'a mut V> {
            let node = node?;
            if predicate(&node.value) {
                return Some(&mut node.value);
            }
            if let Some(value) = visit(node.left.as_deref_mut(), predicate) {
                return Some(value);
            }
            visit(node.right.as_deref_mut(), predicate)
        }
        visit(self.root.as_deref_mut(), &mut predicate)
    }

    /// Insert one entry, which now owns the lease that funded it.
    ///
    /// A key already present is **refused**, and the candidate comes straight
    /// back in the `Err` still inside the node that was allocated for it, so
    /// dropping the result destroys the value and releases the funding.
    /// Replacing silently would destroy a live entry that something else is
    /// still holding a name for, and refusing while keeping the lease would
    /// retain funding for an entry that does not exist.
    ///
    /// The `Err` is one pointer wide, which is not a micro-optimisation: this
    /// signature is on the success path of every insert in the crate, and
    /// handing back an unpacked value and lease would widen every one of them
    /// by the size of the caller's payload to describe a case that did not
    /// happen.
    pub(crate) fn insert(
        &mut self,
        key: K,
        value: V,
        entry: ResourceLease,
    ) -> Result<(), RefusedEntry<K, V>> {
        let priority = self.priority(&key);
        let node = Box::new(LeasedMapNode {
            key,
            value,
            _entry: entry,
            priority,
            left: None,
            right: None,
        });
        match Self::insert_node(&mut self.root, node) {
            Some(refused) => Err(RefusedEntry { _node: refused }),
            None => {
                // Not saturating: the count and the tree must agree, and a
                // saturated count would disagree silently. It cannot overflow
                // either — every entry is a live allocation, so `usize::MAX` of
                // them is unreachable.
                self.len = self
                    .len
                    .checked_add(1)
                    .expect("one live allocation per entry bounds the count");
                Ok(())
            }
        }
    }

    /// This map's priority for one key.
    ///
    /// `hash_one` over a borrow of the key, so nothing is moved and no second
    /// hasher state is spelled out here — the `RandomState` seeded per map is
    /// the only thing that decides the value, which is what keeps the shape
    /// unpredictable across processes.
    fn priority(&self, key: &K) -> u64 {
        self.priorities.hash_one(key)
    }

    /// Place `node`, or hand it back if its key is already present.
    ///
    /// Recursive, and bounded by the tree's depth rather than its size: the
    /// priorities are hashes of the keys, so the expected depth is logarithmic
    /// and no caller-chosen key order produces a spine.
    ///
    /// **Mutation may recurse; teardown may not.** A mutation walks one root-to-
    /// leaf path under priorities a caller cannot guess and a population the
    /// owner's leases already bound, so its depth is bounded twice over. Drop
    /// has neither guarantee — it runs on every node, on a tree of whatever size
    /// the owner funded, and on a path that must not allocate to unwind — so it
    /// is written iteratively rather than recursively.
    fn insert_node(
        slot: &mut Option<Box<LeasedMapNode<K, V>>>,
        node: Box<LeasedMapNode<K, V>>,
    ) -> Option<Box<LeasedMapNode<K, V>>> {
        let Some(mut current) = slot.take() else {
            *slot = Some(node);
            return None;
        };
        let refused = match node.key.cmp(&current.key) {
            Ordering::Equal => Some(node),
            Ordering::Less => {
                let refused = Self::insert_node(&mut current.left, node);
                if refused.is_none() && Self::outranks(current.left.as_deref(), current.priority) {
                    current = Self::rotate_right(current);
                }
                refused
            }
            Ordering::Greater => {
                let refused = Self::insert_node(&mut current.right, node);
                if refused.is_none() && Self::outranks(current.right.as_deref(), current.priority) {
                    current = Self::rotate_left(current);
                }
                refused
            }
        };
        *slot = Some(current);
        refused
    }

    fn outranks(child: Option<&LeasedMapNode<K, V>>, priority: u64) -> bool {
        child.is_some_and(|child| child.priority > priority)
    }

    /// Move the left child above this node. Allocates nothing.
    fn rotate_right(mut node: Box<LeasedMapNode<K, V>>) -> Box<LeasedMapNode<K, V>> {
        let mut pivot = node
            .left
            .take()
            .expect("a right rotation is only reached with a left child");
        node.left = pivot.right.take();
        pivot.right = Some(node);
        pivot
    }

    /// Move the right child above this node. Allocates nothing.
    fn rotate_left(mut node: Box<LeasedMapNode<K, V>>) -> Box<LeasedMapNode<K, V>> {
        let mut pivot = node
            .right
            .take()
            .expect("a left rotation is only reached with a right child");
        node.right = pivot.left.take();
        pivot.left = Some(node);
        pivot
    }

    /// Join two subtrees, every key in `left` ordering before every key in
    /// `right`. Allocates nothing.
    fn merge(
        left: Option<Box<LeasedMapNode<K, V>>>,
        right: Option<Box<LeasedMapNode<K, V>>>,
    ) -> Option<Box<LeasedMapNode<K, V>>> {
        match (left, right) {
            (None, right) => right,
            (left, None) => left,
            (Some(mut left_node), Some(right_node)) => {
                if left_node.priority >= right_node.priority {
                    left_node.right = Self::merge(left_node.right.take(), Some(right_node));
                    Some(left_node)
                } else {
                    let mut right_node = right_node;
                    right_node.left = Self::merge(Some(left_node), right_node.left.take());
                    Some(right_node)
                }
            }
        }
    }
}

impl<K: Ord + Hash, V> LeasedMap<K, V> {
    /// The value under `key`, if the map holds one.
    ///
    /// Borrowed lookup, so asking about a name costs nothing the name does not
    /// already own — a caller with raw bytes never has to build a funded key
    /// merely to ask a question.
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find(key).map(|node| &node.value)
    }

    pub(crate) fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find_mut(key).map(|node| &mut node.value)
    }

    /// The stored key beside its value, for a caller that needs the map's own
    /// copy rather than the one it looked up with.
    ///
    /// Controls only, and that is a property of the production paths rather than
    /// an accident. A caller holding the map's key holds the leased label that
    /// funds it, which is the session's to hold and not a lookup's to hand out;
    /// the two consumers are the test seams that have to build a delivery
    /// addressed to a flow, and both are themselves gated.
    #[cfg(test)]
    pub(crate) fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find(key).map(|node| (&node.key, &node.value))
    }

    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find(key).is_some()
    }

    /// Remove one entry, releasing exactly that entry's funding.
    ///
    /// Controls only. Production takes entries out through
    /// [`Self::remove_entry`], because the owners here are keyed by a leased
    /// label and the key is half of what they need back — dropping it inside
    /// this call would release a shared record the caller still has ordering
    /// obligations around. This is the value-only convenience the controls use,
    /// and gating it keeps the production path a single shape.
    #[cfg(test)]
    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.remove_entry(key).map(|(_, value)| value)
    }

    /// Remove one entry and hand back both halves, releasing that entry's
    /// funding as the node drops.
    pub(crate) fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let node = Self::remove_node(&mut self.root, key)?;
        // Reached only after a node really came out of the tree, so this cannot
        // underflow unless the count and the tree have already diverged — which
        // is the thing worth failing on rather than absorbing.
        self.len = self
            .len
            .checked_sub(1)
            .expect("an entry was removed, so the count was not zero");
        let LeasedMapNode {
            key, value, _entry, ..
        } = *node;
        // `_entry` is released here, after the key and value it funded have
        // been handed back and are no longer this map's to account for.
        Some((key, value))
    }

    fn find<Q>(&self, key: &Q) -> Option<&LeasedMapNode<K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut cursor = self.root.as_deref();
        while let Some(node) = cursor {
            cursor = match key.cmp(node.key.borrow()) {
                Ordering::Less => node.left.as_deref(),
                Ordering::Greater => node.right.as_deref(),
                Ordering::Equal => return Some(node),
            };
        }
        None
    }

    fn find_mut<Q>(&mut self, key: &Q) -> Option<&mut LeasedMapNode<K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut cursor = self.root.as_deref_mut();
        while let Some(node) = cursor {
            match key.cmp(node.key.borrow()) {
                Ordering::Less => cursor = node.left.as_deref_mut(),
                Ordering::Greater => cursor = node.right.as_deref_mut(),
                Ordering::Equal => return Some(node),
            }
        }
        None
    }

    /// Detach the node under `key`, leaving the rest of the tree ordered.
    ///
    /// The detached node comes back with both children taken, so its own drop
    /// is a leaf's drop and cannot recurse.
    fn remove_node<Q>(
        slot: &mut Option<Box<LeasedMapNode<K, V>>>,
        key: &Q,
    ) -> Option<Box<LeasedMapNode<K, V>>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut current = slot.take()?;
        let removed = match key.cmp(current.key.borrow()) {
            Ordering::Equal => {
                *slot = Self::merge(current.left.take(), current.right.take());
                return Some(current);
            }
            Ordering::Less => Self::remove_node(&mut current.left, key),
            Ordering::Greater => Self::remove_node(&mut current.right, key),
        };
        *slot = Some(current);
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };
    use std::sync::{Arc, Mutex};

    type DropLog = Arc<Mutex<Vec<u32>>>;

    fn drop_log() -> DropLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    /// A value that reports its own destruction.
    struct ControlValue {
        key: u32,
        dropped: DropLog,
        _retention: ResourceLease,
    }

    impl Drop for ControlValue {
        fn drop(&mut self) {
            self.dropped
                .lock()
                .expect("the control drop log is uncontended")
                .push(self.key);
        }
    }

    /// The retention one control entry declares beyond its node. Non-zero and
    /// in a dimension the node term does not use, so a claim that dropped
    /// either term is visible rather than absorbed.
    fn control_retention() -> ResourceClaim {
        ResourceClaim::single(ResourceClass::QueuedBytes, 64)
    }

    fn control_entry_claim() -> ResourceClaim {
        LeasedMap::<u32, ControlValue>::entry_claim()
            .expect("the control entry claim is representable")
    }

    /// A grant that funds exactly `entries` entries and nothing spare, derived
    /// from the same `entry_claim` an owner would use plus the provider's own
    /// per-reservation and per-scope bookkeeping.
    fn control_grant(entries: u64) -> ResourceClaim {
        let scope_record = FiniteResourceProvider::scope_record_charge_for_test();
        let node = control_entry_claim()
            .checked_add(scope_record)
            .expect("the control entry claim plus its reservation record is representable");
        let retention = control_retention()
            .checked_add(scope_record)
            .expect("the value retention plus its reservation record is representable");
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

    fn control_lease(port: &ResourceProviderPort, scope: &ResourceScope) -> ResourceLease {
        port.acquire(
            scope,
            ResourceAuthorityClass::Admitted,
            control_entry_claim(),
        )
        .expect("the control grant funds this entry")
    }

    fn control_value(
        key: u32,
        dropped: &DropLog,
        port: &ResourceProviderPort,
        scope: &ResourceScope,
    ) -> ControlValue {
        ControlValue {
            key,
            dropped: Arc::clone(dropped),
            _retention: port
                .acquire(scope, ResourceAuthorityClass::Admitted, control_retention())
                .expect("the control grant funds this value's retention"),
        }
    }

    /// Keys are found by order regardless of insertion order, and a key that
    /// was never inserted is not found.
    ///
    /// The insertion order is deliberately not sorted: a structure that ignored
    /// its priorities and simply chained entries would still answer these
    /// lookups, so the negative and the count below are what make it a test of
    /// an ordered map rather than of a list.
    #[test]
    fn v4_arc05_entries_are_found_by_key_whatever_order_they_arrived_in() {
        let dropped = drop_log();
        let (_provider, port, scope) = control_provider(5);
        let mut map = LeasedMap::new();
        for key in [30_u32, 10, 50, 20, 40] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }

        assert_eq!(map.len(), 5);
        for key in [10_u32, 20, 30, 40, 50] {
            assert_eq!(map.get(&key).map(|value| value.key), Some(key));
            assert!(map.contains_key(&key));
            assert_eq!(map.get_key_value(&key).map(|(key, _)| *key), Some(key));
        }
        assert!(map.get(&35).is_none(), "a key never inserted is not found");
        assert!(!map.contains_key(&35));
    }

    /// A duplicate key is refused, and the refusal retains nothing.
    #[test]
    fn v4_arc05_a_duplicate_key_is_refused_and_its_funding_goes_back() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(2);
        let mut map = LeasedMap::new();
        assert!(map
            .insert(
                7_u32,
                control_value(7, &dropped, &port, &scope),
                control_lease(&port, &scope),
            )
            .is_ok());
        let held = provider.in_use();

        let refused = map.insert(
            7_u32,
            control_value(700, &dropped, &port, &scope),
            control_lease(&port, &scope),
        );
        assert!(refused.is_err(), "the live entry is not replaced");
        drop(refused);

        assert_eq!(
            provider.in_use(),
            held,
            "the refused entry's funding went back, so a caller that retries \
             forever retains nothing"
        );
        assert_eq!(map.len(), 1);
        assert_eq!(
            dropped
                .lock()
                .expect("the control drop log is uncontended")
                .as_slice(),
            [700],
            "the refused value was destroyed and the live one was not"
        );
    }

    /// Removing one entry releases exactly that entry's node and lease, and
    /// leaves the rest of the map intact and still funded.
    #[test]
    fn v4_arc05_removing_one_entry_releases_exactly_that_entrys_funding() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(4);
        let mut map = LeasedMap::new();
        for key in [1_u32, 2, 3] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }
        let full = provider.in_use();

        let removed = map.remove(&2).expect("the entry was there");
        assert_eq!(removed.key, 2);
        let after_node_removal = provider.in_use();
        assert_eq!(
            after_node_removal.amount(ResourceClass::QueuedBytes),
            full.amount(ResourceClass::QueuedBytes),
            "the returned value keeps its own retention funded"
        );
        drop(removed);

        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            full.amount(ResourceClass::QueuedBytes)
                - control_retention().amount(ResourceClass::QueuedBytes),
            "exactly one entry's retention was released — not a share of a \
             shared node, and not nothing"
        );
        assert_eq!(map.len(), 2);
        assert!(map.get(&2).is_none());
        assert!(map.contains_key(&1) && map.contains_key(&3));

        // The provider funds four entries at a time, and three were taken, so
        // the fourth admits only because the removal really gave one back.
        assert!(map
            .insert(
                4_u32,
                control_value(4, &dropped, &port, &scope),
                control_lease(&port, &scope),
            )
            .is_ok());
    }

    /// Dropping the map drops every entry and releases every entry's funding.
    #[test]
    fn v4_arc05_dropping_the_map_drops_and_releases_every_entry() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(5);
        let mut map = LeasedMap::new();
        for key in [30_u32, 10, 50, 20, 40] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }
        assert!(dropped
            .lock()
            .expect("the control drop log is uncontended")
            .is_empty());

        drop(map);

        let mut destroyed = dropped
            .lock()
            .expect("the control drop log is uncontended")
            .clone();
        destroyed.sort_unstable();
        assert_eq!(
            destroyed,
            vec![10, 20, 30, 40, 50],
            "every entry's own drop ran"
        );
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            0,
            "no entry's retention outlived the map that held it"
        );
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::AccountedMemoryBytes),
            0,
            "no entry's node bytes outlived the map that held it"
        );

        // The third dimension needs the scope gone before it can be asserted at
        // zero, and that is a property of the provider rather than a hedge: the
        // residual dimension is also where the provider records its own scope,
        // so a live scope holds one legitimately. Tearing the scope down after
        // the map lets the assertion be a plain zero instead of an arithmetic
        // that would quietly still pass if a node's residual leaked.
        drop(scope);
        drop(port);
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::OpaqueDependencyResidual),
            0,
            "no entry's allocation residual outlived the map that held it"
        );
    }
}
