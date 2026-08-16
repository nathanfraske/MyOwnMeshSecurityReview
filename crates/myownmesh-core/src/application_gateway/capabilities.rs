//! The retained local capability advertisement for a joined network.

use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};

/// Why a local capability advertisement was not committed.
pub(crate) enum CapabilityReplaceRefusal {
    Revoked,
    Unavailable(String),
}

struct LeasedLocalCapabilityAdvert {
    encoded: Box<[u8]>,
    _lease: ResourceLease,
}

/// The one retained local advertisement for a joined network. This is
/// Application Gateway state, not RPC transport state, and its canonical byte
/// representation is funded for exactly as long as it is installed.
pub(crate) struct LocalCapabilityState {
    held: parking_lot::Mutex<Option<LeasedLocalCapabilityAdvert>>,
}

impl LocalCapabilityState {
    pub(crate) fn new() -> Self {
        Self {
            held: parking_lot::Mutex::new(None),
        }
    }

    fn replace(
        &self,
        closed: &std::sync::atomic::AtomicBool,
        broker: Option<&crate::runtime::session_broker::SessionBroker>,
        advert: &crate::protocol::CapabilityAdvert,
    ) -> Result<(), CapabilityReplaceRefusal> {
        if closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(CapabilityReplaceRefusal::Revoked);
        }
        // Counted before anything is built, so a refusal below costs no buffer.
        // Under pressure, or against a gateway that closed, this path allocates
        // nothing at all.
        let encoded_len = advert.encoded_len().ok_or_else(|| {
            CapabilityReplaceRefusal::Unavailable(
                "local capability advertisement is too large to account".to_string(),
            )
        })?;
        let bytes = u64::try_from(encoded_len).map_err(|_| {
            CapabilityReplaceRefusal::Unavailable(
                "local capability advertisement is too large to account".to_string(),
            )
        })?;
        let claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| {
            CapabilityReplaceRefusal::Unavailable(
                "local capability advertisement claim overflowed".to_string(),
            )
        })?;
        let lease = broker
            .ok_or_else(|| {
                CapabilityReplaceRefusal::Unavailable(
                    "no local application resource owner is installed".to_string(),
                )
            })?
            .reserve_local_application(claim)
            .map_err(|e| {
                CapabilityReplaceRefusal::Unavailable(format!(
                    "local capability advertisement refused: {e:?}"
                ))
            })?;
        let mut held = self.held.lock();
        if closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(CapabilityReplaceRefusal::Revoked);
        }
        // The only encode, after the only acquisition, and inside the fence that
        // decides whether it will be installed. A closed gateway refuses above
        // with nothing built and the lease released on the way out.
        let encoded = advert.encode_exact(encoded_len).ok_or_else(|| {
            CapabilityReplaceRefusal::Unavailable(
                "local capability advertisement did not encode to its counted size".to_string(),
            )
        })?;
        *held = Some(LeasedLocalCapabilityAdvert {
            encoded,
            _lease: lease,
        });
        Ok(())
    }

    pub(crate) fn current(&self) -> Option<crate::protocol::CapabilityAdvert> {
        self.held
            .lock()
            .as_ref()
            .and_then(|held| serde_json::from_slice(&held.encoded).ok())
    }

    pub(crate) fn clear(&self) {
        drop(self.held.lock().take());
    }
}

impl super::ApplicationGateway {
    /// Replace the retained advert only while this gateway is still live.
    ///
    /// The second close check is under the same mutex that `clear` takes. A
    /// close that wins before that check therefore cannot be followed by a new
    /// retained advert that the one-shot close path will never clear.
    pub(crate) fn replace_capabilities(
        &self,
        broker: Option<&crate::runtime::session_broker::SessionBroker>,
        advert: &crate::protocol::CapabilityAdvert,
    ) -> Result<(), CapabilityReplaceRefusal> {
        self.capabilities.replace(&self.closed, broker, advert)
    }
}
