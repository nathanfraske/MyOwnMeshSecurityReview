//! Handshake frames: `hello`, `auth_response`, `approve`, `deny`.
//!
//! The hello/auth_response pair binds both sides to independently drawn
//! contributions and the exact channel. Approve/deny is the user-facing trust
//! gate after mutual authentication. Canonical governance proof is exchanged
//! as semantic facts, never as unsigned fields on a handshake frame.

use serde::{Deserialize, Serialize};

pub(crate) fn verification_code_has_protocol_shape(code: &str) -> bool {
    code.len() == 6
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Sent immediately on channel open by both ends. Carries only the identity,
/// endpoint-auth contribution, human verification code, and closed profile
/// advertisement needed before a session exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloMessage {
    /// The closed wire profile version. Unknown frame kinds and unsupported
    /// profiles fail closed; there is no optional-frame negotiation.
    pub protocol: u32,
    /// Bare-pubkey Device ID, base32-lowercase, with any display suffix omitted.
    pub device_id: String,
    /// Self-reported cosmetic label.
    #[serde(default)]
    pub label: String,
    /// Fresh per-attempt contribution bound into endpoint authentication.
    pub nonce: String,
    /// Six-character human verification code.
    pub verification_code: String,
    /// Closed profile advertisement; must include `endpoint_auth_v1`.
    #[serde(default)]
    pub features: Vec<String>,
}

/// Response proving possession of the key matching `HelloMessage::device_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponseMessage {
    /// Base32-lowercase signature over the endpoint-auth transcript.
    pub signature: String,
}

/// Sent once the peer is cleared for application traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveMessage {}

/// Reason carried when a denial reflects signed semantic eviction state.
pub const DENY_REASON_EVICTED: &str = "evicted";

/// Sent when the local side rejects the peer. The reason is a decision hint;
/// any governance proof is a separately exchanged canonical signed fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyMessage {
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod verification_code_tests {
    use super::verification_code_has_protocol_shape;

    #[test]
    fn verification_code_is_exactly_six_lowercase_ascii_alphanumerics() {
        assert!(verification_code_has_protocol_shape("abc123"));
        for malformed in ["abc12", "abc1234", "ABC123", "abc-12", "\u{e5}bc123"] {
            assert!(
                !verification_code_has_protocol_shape(malformed),
                "{malformed:?}"
            );
        }
    }
}
