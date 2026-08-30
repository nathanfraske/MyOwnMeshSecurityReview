//! Typed signaling ports.
//!
//! The transition keeps two ingress lanes distinct at the type boundary:
//! durable semantic exchanges are admitted by [`DurableSemanticPort`], while
//! carrier observations are admitted by [`EphemeralTransportPort`]. Neither
//! port contains the other's value, and neither carrier provenance nor a
//! transport observation can become semantic authority.
//!
//! This module is intentionally a narrow target-node facade. The temporary
//! engine supervisor may still use its compatibility dispatch while callers
//! migrate; it is not a second queue, parser, resource owner, or authority
//! store.

pub(crate) use crate::engine::semantic_ingress::DurableSemanticPort;
pub(crate) use crate::engine::signaling_ingress::EphemeralTransportPort;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_separate_named_lanes() {
        let _durable = DurableSemanticPort;
        let _ephemeral = EphemeralTransportPort;
    }
}
