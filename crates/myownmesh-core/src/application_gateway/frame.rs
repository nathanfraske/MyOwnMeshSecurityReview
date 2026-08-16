//! Encoded application frames, and the claim their parse is admitted against.

use bytes::Bytes;

use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};
use crate::runtime::session_broker::SessionCapability;

use super::GatewayRefusal;

/// An encoded application frame whose bytes and parse work were admitted by
/// the exact promoted session before full payload deserialization.
pub(crate) struct AdmittedApplicationFrame {
    encoded: Bytes,
    claim: ResourceClaim,
    _work: ResourceLease,
}

pub(crate) struct DecodedApplicationFrame {
    message: crate::protocol::MeshMessage,
    claim: ResourceClaim,
    _work: ResourceLease,
}

impl AdmittedApplicationFrame {
    pub(crate) fn claim(
        encoded_bytes: usize,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        structural_json_claim(encoded_bytes)
    }

    pub(crate) fn admit(
        session: &SessionCapability,
        encoded: Bytes,
    ) -> Result<Self, GatewayRefusal> {
        let claim = Self::claim(encoded.len()).map_err(|_| GatewayRefusal::Malformed)?;
        let work = session
            .reserve_retained(claim)
            .map_err(GatewayRefusal::Pressure)?;
        Ok(Self {
            encoded,
            claim,
            _work: work,
        })
    }

    pub(crate) fn decode(self) -> Result<DecodedApplicationFrame, GatewayRefusal> {
        let message =
            serde_json::from_slice(&self.encoded).map_err(|_| GatewayRefusal::Malformed)?;
        Ok(DecodedApplicationFrame {
            message,
            claim: self.claim,
            _work: self._work,
        })
    }
}

/// The exact claim one JSON input of `max_frame_bytes` will be admitted
/// against, for an owner that has to size a resource provider.
///
/// This exists because the derivation below is the only thing that can answer
/// it, and a provider owner outside this crate previously had to guess. Guessing
/// is what left self-funded test providers granting a residual denominated in
/// records against a claim denominated in bytes, so their first inbound `Hello`
/// was refused with no latch set and no warning. The formula is not restated
/// here — this calls the same function — so the two cannot drift.
///
/// **This sizes a grant. It is not a wire gate and not a limit.** Nothing
/// consults it at admission; a frame is admitted against
/// [`structural_json_claim`] at its own actual length. Passing a value here says
/// only how large an input the owner is willing to fund, and an owner that funds
/// too little sees a refusal rather than a truncation.
pub fn json_input_work_claim(
    max_frame_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    structural_json_claim(max_frame_bytes)
}

/// A mechanically conservative JSON-tree claim derived from the only quantity
/// available before parsing. A JSON value cannot contain more structural values
/// or owned scalar fragments than input bytes. Charging one full `Value` slot
/// and one opaque allocation per byte therefore covers adversarial tree
/// amplification instead of pretending wire length equals decoded retention.
pub(crate) fn structural_json_claim(
    encoded_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes =
        u64::try_from(encoded_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let value_slot = u64::try_from(std::mem::size_of::<serde_json::Value>()).map_err(|_| {
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let bytes_per_input =
        value_slot
            .checked_add(1)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    let decoded =
        bytes
            .checked_mul(bytes_per_input)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, decoded),
        (ResourceClass::ParsingOrCpuWork, bytes),
        (ResourceClass::OpaqueDependencyResidual, bytes),
    ])
}

impl DecodedApplicationFrame {
    pub(crate) fn message(&self) -> &crate::protocol::MeshMessage {
        &self.message
    }

    pub(crate) fn into_parts(self) -> (crate::protocol::MeshMessage, ResourceClaim, ResourceLease) {
        (self.message, self.claim, self._work)
    }
}

#[cfg(test)]
mod decode_fence_controls {
    use super::*;
    use crate::runtime::session_broker::session_funding_for_test;

    /// The property the inbound path's three-phase split rests on: admission
    /// decides whether the parse may happen **without performing it**.
    ///
    /// Stated as a control because it is load-bearing and invisible. If `admit`
    /// ever grew a parse — a validation pass, a cheap shape check, a length
    /// probe that deserializes — the engine would be back to holding the
    /// registry's single mutation lock across peer-chosen work, and every other
    /// control in this batch would still pass. Bytes that cannot possibly parse
    /// are what makes it discriminating: they are admitted and funded, and only
    /// the separate `decode` step refuses them.
    #[test]
    fn admission_funds_a_frame_it_has_not_parsed() {
        let garbage = Bytes::from_static(b"{ this is not json");
        let claim = AdmittedApplicationFrame::claim(garbage.len())
            .expect("the structural claim over a short frame is representable");
        // Funded for exactly this frame and nothing else, so `admit` succeeding
        // below is attributable to it not needing to parse — and not to slack
        // the fixture happened to have.
        let session = session_funding_for_test(crate::runtime::runtime_for_test(), claim);

        let frame = AdmittedApplicationFrame::admit(&session, garbage.clone())
            .expect("admission measures the encoded length; it does not read the bytes");
        assert_eq!(
            frame.claim, claim,
            "non-vacuity: funded against its own length, so the lease is real and \
             the escape below carries it"
        );

        // Only here, outside every fence in production, does the input's shape
        // matter — and this is the step whose duration the sender chooses.
        assert_eq!(frame.decode().err(), Some(GatewayRefusal::Malformed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_admission_does_not_equate_wire_length_with_decoded_tree_retention() {
        let wire = 7usize;
        let claim = structural_json_claim(wire).expect("the small claim is representable");
        assert_eq!(claim.amount(ResourceClass::ParsingOrCpuWork), wire as u64);
        assert_eq!(
            claim.amount(ResourceClass::OpaqueDependencyResidual),
            wire as u64,
            "every possible owned fragment has an explicit residual"
        );
        assert!(
            claim.amount(ResourceClass::AccountedMemoryBytes) > wire as u64,
            "decoded Value slots, rather than wire bytes alone, are funded"
        );
    }
}
