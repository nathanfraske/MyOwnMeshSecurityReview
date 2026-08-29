//! The discovery half of the mDNS driver — DNS-SD registration and browsing —
//! behind one seam with two backends:
//!
//! - [`embedded`] (the default): the pure-Rust `mdns-sd` daemon, raw multicast
//!   sockets. Works anywhere the OS lets an application join the mDNS
//!   multicast group.
//! - [`system`] (iOS always; opt-in elsewhere via the `system-dnssd` feature):
//!   the platform's own DNS-SD daemon through the stable `dnssd` C API —
//!   mDNSResponder on Apple platforms, Avahi's `libdns_sd` compat shim on
//!   Linux. iOS 14+ blocks raw multicast sockets unless the app holds the
//!   Apple-granted `com.apple.developer.networking.multicast` entitlement, but
//!   talking to mDNSResponder needs no entitlement — only the standard
//!   `NSLocalNetworkUsageDescription` / `NSBonjourServices` Info.plist keys.
//!   This is what makes **local claiming** work properly on an iPhone.
//!
//! Both backends speak standard mDNS/DNS-SD on the wire — same service type,
//! same TXT records — so a peer using one discovers a peer using the other.
//! The signaling exchange itself (the unicast TCP connection) is
//! backend-independent and lives in [`super::driver`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Maximum number of distinct service instances that may own a resolve at
/// once. Repeated browse hints for an owned instance coalesce into one pending
/// follow-up instead of spawning an unbounded resolve herd.
pub const MAX_RESOLVE_OWNERS: usize = 256;
/// Capacity of the backend-to-driver discovery event queue. Browse callbacks
/// must never be able to allocate without bound when the engine is stalled.
pub const DISCOVERY_EVENT_CAPACITY: usize = 128;
/// Maximum DNS-SD service-instance/name length accepted from a backend.
pub const MAX_DNS_NAME_BYTES: usize = 255;
/// Maximum number of TXT entries copied from one discovery response.
pub const MAX_TXT_ENTRIES: usize = 64;
/// Maximum key/value sizes copied from one TXT entry.
pub const MAX_TXT_KEY_BYTES: usize = 128;
pub const MAX_TXT_VALUE_BYTES: usize = 255;
/// Maximum total TXT payload and resolved IPv4 addresses retained per event.
pub const MAX_TXT_BYTES: usize = 4096;
pub const MAX_RESOLVED_ADDRESSES: usize = 32;

/// What a backend needs to advertise + browse one service instance.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// DNS-SD service type, in the `_x._tcp.local.` form ([`super::wire::SERVICE_TYPE`]).
    pub service_type: String,
    /// Our instance name (a bare DNS label, [`super::wire::instance_name`]).
    pub instance: String,
    /// Port the SRV record advertises (our TCP exchange listener).
    pub port: u16,
    /// TXT records for the advertisement ([`super::wire::txt_properties`]).
    pub txt: Vec<(String, String)>,
}

/// One discovery observation. `key` is a backend-opaque identifier that is
/// stable between a `Resolved` and the `Removed` that withdraws it — the
/// driver treats it as an opaque map key and never interprets it.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A service instance resolved (first sight or cache refresh): where its
    /// exchange listens and its TXT records.
    Resolved {
        key: String,
        addrs: Vec<IpAddr>,
        port: u16,
        txt: HashMap<String, String>,
    },
    /// An instance withdrew (goodbye) or expired from the cache.
    Removed { key: String },
}

/// Result of admitting one exact service-instance browse hint.
#[derive(Debug)]
pub enum ResolveHint {
    /// This instance has one active resolve owner.
    Started(ResolveLease),
    /// A resolve is already active (or already has a pending follow-up) for
    /// this exact instance; no additional owner was allocated.
    Coalesced,
    /// The ownership table is full or has been shut down.
    Refused,
}

/// Result of completing one active resolve owner.
#[derive(Debug)]
pub enum ResolveCompletion {
    /// There is no follow-up for this instance.
    Finished,
    /// A coalesced hint earned one exact follow-up owner.
    Followup(ResolveLease),
}

#[derive(Debug)]
struct ResolveSlot {
    generation: u64,
    pending: bool,
}

#[derive(Debug)]
struct ResolveOwnershipInner {
    slots: Mutex<HashMap<String, ResolveSlot>>,
    next_generation: AtomicU64,
    stopped: AtomicBool,
}

/// Provider-side ownership for service-instance resolution.
///
/// The key is the exact backend service-instance name, not a device id decoded
/// later from untrusted TXT. One active owner and at most one coalesced pending
/// hint exist per key. Cancellation removes only the requested key; a stale
/// lease cannot cancel a newer generation for the same instance. Shutdown
/// invalidates all generations before clearing the table.
#[derive(Clone, Debug)]
pub struct ResolveOwnership {
    inner: Arc<ResolveOwnershipInner>,
}

impl Default for ResolveOwnership {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolveOwnership {
    /// Create an empty, bounded ownership table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ResolveOwnershipInner {
                slots: Mutex::new(HashMap::new()),
                next_generation: AtomicU64::new(1),
                stopped: AtomicBool::new(false),
            }),
        }
    }

    /// Admit a browse hint for one exact service instance.
    pub fn admit(&self, instance: impl Into<String>) -> ResolveHint {
        let instance = instance.into();
        let mut slots = self.inner.slots.lock().unwrap_or_else(|e| e.into_inner());
        if self.inner.stopped.load(Ordering::Acquire) {
            return ResolveHint::Refused;
        }
        if let Some(slot) = slots.get_mut(&instance) {
            slot.pending = true;
            return ResolveHint::Coalesced;
        }
        if slots.len() >= MAX_RESOLVE_OWNERS {
            return ResolveHint::Refused;
        }
        let Some(generation) = next_generation(&self.inner.next_generation) else {
            return ResolveHint::Refused;
        };
        slots.insert(
            instance.clone(),
            ResolveSlot {
                generation,
                pending: false,
            },
        );
        ResolveHint::Started(ResolveLease {
            tracker: Arc::clone(&self.inner),
            instance,
            generation,
        })
    }

    /// Cancel all active and pending work for one exact service instance.
    pub fn cancel(&self, instance: &str) -> bool {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(instance)
            .is_some()
    }

    /// Invalidate every active and pending resolve owner.
    pub fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Number of exact service instances with an active owner.
    pub fn active_count(&self) -> usize {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Number of exact service instances with one coalesced pending hint.
    pub fn pending_count(&self) -> usize {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|slot| slot.pending)
            .count()
    }
}

/// One exact active resolve owner. Dropping it cancels only its generation.
#[derive(Debug)]
pub struct ResolveLease {
    tracker: Arc<ResolveOwnershipInner>,
    instance: String,
    generation: u64,
}

impl ResolveLease {
    /// The exact backend service-instance name owned by this lease.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Explicitly cancel this generation.
    pub fn cancel(self) -> bool {
        self.tracker
            .cancel_generation(&self.instance, self.generation)
    }

    /// Complete this owner and retain one coalesced follow-up, if any.
    pub fn complete(self) -> ResolveCompletion {
        self.complete_with(|| {})
    }

    pub(crate) fn complete_with<F>(self, publish: F) -> ResolveCompletion
    where
        F: FnOnce(),
    {
        let tracker = Arc::clone(&self.tracker);
        let instance = self.instance.clone();
        let generation = self.generation;
        let mut slots = tracker.slots.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = slots.get_mut(&instance) else {
            return ResolveCompletion::Finished;
        };
        if slot.generation != generation || tracker.stopped.load(Ordering::Acquire) {
            return ResolveCompletion::Finished;
        }
        publish();
        if slot.pending {
            let Some(next_generation) = next_generation(&tracker.next_generation) else {
                slots.remove(&instance);
                return ResolveCompletion::Finished;
            };
            slot.generation = next_generation;
            slot.pending = false;
            drop(slots);
            ResolveCompletion::Followup(ResolveLease {
                tracker,
                instance,
                generation: next_generation,
            })
        } else {
            slots.remove(&instance);
            ResolveCompletion::Finished
        }
    }
}

impl Drop for ResolveLease {
    fn drop(&mut self) {
        self.tracker
            .cancel_generation(&self.instance, self.generation);
    }
}

impl ResolveOwnershipInner {
    fn cancel_generation(&self, instance: &str, generation: u64) -> bool {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if slots
            .get(instance)
            .is_some_and(|slot| slot.generation == generation)
        {
            slots.remove(instance);
            true
        } else {
            false
        }
    }
}

/// Allocate a generation without ever wrapping or reusing an exhausted value.
/// Zero is the permanent exhausted sentinel; MAX is handed out once and then
/// the counter is sealed.
fn next_generation(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            if value == 0 {
                None
            } else if value == u64::MAX {
                Some(0)
            } else {
                Some(value + 1)
            }
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_exhaustion_refuses_without_reuse() {
        let ownership = ResolveOwnership::new();
        ownership
            .inner
            .next_generation
            .store(u64::MAX, Ordering::Release);
        let last = ownership.admit("last");
        assert!(matches!(&last, ResolveHint::Started(_)));
        assert!(matches!(
            ownership.admit("after-exhaustion"),
            ResolveHint::Refused
        ));
        drop(last);
        assert!(matches!(
            ownership.admit("still-exhausted"),
            ResolveHint::Refused
        ));
    }
}

#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
mod system;
#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
pub use system::Discovery;

#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
mod embedded;
#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
pub use embedded::Discovery;
