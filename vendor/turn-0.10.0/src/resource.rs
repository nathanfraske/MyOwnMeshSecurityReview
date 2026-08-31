//! Dependency-neutral admission and custody hooks for embedders.
//!
//! The TURN crate deliberately does not depend on an application resource
//! provider. An embedding owner supplies this small interface and retains the
//! returned lease beside the exact native object or task it funded.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A bounded dependency-owned object or task category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    ReadLoop,
    CommandLoop,
    Allocation,
    AllocationTimer,
    PacketPump,
    Permission,
    ChannelBind,
    Reservation,
    Nonce,
    Queue,
    RelayProbe,
}

/// Finite work retained by one admitted object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceCharge {
    pub units: u64,
    pub retained_bytes: u64,
}

impl ResourceCharge {
    pub const fn units(units: u64) -> Self {
        Self {
            units,
            retained_bytes: 0,
        }
    }

    pub const fn with_bytes(units: u64, retained_bytes: u64) -> Self {
        Self {
            units,
            retained_bytes,
        }
    }
}

/// Typed refusal from the owner-selected provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceAdmissionError;

/// One noncloneable exact owner charge. Dropping the concrete implementation
/// releases the provider reservation; TURN only stores and moves this trait
/// object and never fabricates or duplicates it.
pub trait ResourceLease: Send + Sync {}

/// Owner-supplied admission authority. Implementations must acquire before
/// the corresponding native bind, channel, task, or retained map mutation.
pub trait ResourceAdmission: Send + Sync {
    fn acquire(
        &self,
        kind: ResourceKind,
        charge: ResourceCharge,
    ) -> Result<Box<dyn ResourceLease>, ResourceAdmissionError>;
}

#[cfg(test)]
pub(crate) struct UnboundedTestAdmission;

#[cfg(test)]
impl ResourceAdmission for UnboundedTestAdmission {
    fn acquire(
        &self,
        _kind: ResourceKind,
        _charge: ResourceCharge,
    ) -> Result<Box<dyn ResourceLease>, ResourceAdmissionError> {
        Ok(Box::new(UnboundedTestLease))
    }
}

#[cfg(test)]
struct UnboundedTestLease;

#[cfg(test)]
impl ResourceLease for UnboundedTestLease {}

/// Bounded adapter for vendored integration examples and downstream fixture
/// crates. It is intentionally simple but finite: every acquired unit (and
/// each retained KiB) consumes one slot, and dropping the lease restores it.
/// Production embeddings should provide their own owner-selected adapter.
#[doc(hidden)]
pub struct BoundedTestAdmission {
    remaining: Arc<AtomicU64>,
}

impl BoundedTestAdmission {
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(limit)),
        }
    }
}

struct BoundedTestLease {
    remaining: Arc<AtomicU64>,
    charge: u64,
}

impl ResourceLease for BoundedTestLease {}

impl Drop for BoundedTestLease {
    fn drop(&mut self) {
        self.remaining.fetch_add(self.charge, Ordering::Release);
    }
}

impl ResourceAdmission for BoundedTestAdmission {
    fn acquire(
        &self,
        _kind: ResourceKind,
        charge: ResourceCharge,
    ) -> Result<Box<dyn ResourceLease>, ResourceAdmissionError> {
        let retained_slots = charge
            .retained_bytes
            .checked_add(1023)
            .ok_or(ResourceAdmissionError)?
            / 1024;
        let needed = charge
            .units
            .checked_add(retained_slots)
            .ok_or(ResourceAdmissionError)?;
        if needed == 0 {
            return Err(ResourceAdmissionError);
        }
        let mut current = self.remaining.load(Ordering::Acquire);
        loop {
            if current < needed {
                return Err(ResourceAdmissionError);
            }
            match self.remaining.compare_exchange_weak(
                current,
                current - needed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Box::new(BoundedTestLease {
                        remaining: Arc::clone(&self.remaining),
                        charge: needed,
                    }))
                }
                Err(observed) => current = observed,
            }
        }
    }
}
