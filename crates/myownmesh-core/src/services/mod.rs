//! Mesh-native service advertisements for signaling, STUN, TURN, and the
//! frozen LegacyV1 ordinary-member relay wire name.
//!
//! The heavyweight network servers themselves, including the STUN / TURN
//! listener and the Nostr-compatible signaling relay, live outside
//! core (`myownmesh-services` and `myownmesh-signaling::server`) so
//! embedders that only want the mesh runtime don't inherit those
//! dependency trees (the `turn` / `stun` / extra websocket-server
//! plumbing). This module owns only the stable advertised names and endpoint
//! hints. Frozen LegacyV1 forwarding lives under `legacy_v1/` and is not TURN,
//! signaling, or a generic relay.

use serde::{Deserialize, Serialize};

/// A role a device can advertise when it offers infrastructure to the
/// mesh. Surfaced as stable tag strings inside
/// [`crate::protocol::CapabilityAdvert::tags`] (each prefixed
/// `service:`) so existing peers, which already exchange capability
/// tags at handshake, discover service hosts with no wire-format
/// change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRole {
    /// Frozen pre-V4 application-frame forwarding between roster members.
    /// This role is not TURN, signaling, or a generic opaque relay.
    LegacyV1MemberRelay,
    /// Hosts a signaling relay usable in place of public Nostr.
    Signaling,
    /// Answers STUN binding requests.
    Stun,
    /// Relays media / data via TURN allocations.
    Turn,
}

impl ServiceRole {
    /// The stable capability-tag string for this role. Prefixed so a
    /// reader scanning a peer's tags can tell service roles apart from
    /// embedder-defined tags at a glance, and so the namespace can't
    /// collide with an embedder's own tag.
    pub const fn tag(self) -> &'static str {
        match self {
            ServiceRole::LegacyV1MemberRelay => "service:relay",
            ServiceRole::Signaling => "service:signaling",
            ServiceRole::Stun => "service:stun",
            ServiceRole::Turn => "service:turn",
        }
    }

    /// Every role, for iteration.
    pub fn all() -> [ServiceRole; 4] {
        [
            Self::LegacyV1MemberRelay,
            Self::Signaling,
            Self::Stun,
            Self::Turn,
        ]
    }

    /// Parse a capability tag back into a role. Returns `None` for tags
    /// that aren't service roles.
    pub fn from_tag(tag: &str) -> Option<ServiceRole> {
        Self::all().into_iter().find(|r| r.tag() == tag)
    }
}

/// JSON key under which a [`ServiceAdvert`] is nested inside
/// `CapabilityAdvert::extra`.
pub const SERVICE_ADVERT_KEY: &str = "services";

/// Structured advisory a service host publishes inside
/// [`crate::protocol::CapabilityAdvert::extra`] under the
/// [`SERVICE_ADVERT_KEY`] key. The role *tags* answer "what does this
/// device do"; this answers "and here's how to reach it": the
/// endpoints a peer can drop straight into its own `signaling.servers` /
/// `stun_servers` / `turn_servers` config to adopt the host. Every
/// field is optional so a host can advertise a role via tag without
/// committing to a reachable address (e.g. when it sits behind NAT and
/// only the relay role is useful).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceAdvert {
    /// `ws://host:port` for the signaling relay, when hosted and
    /// reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signaling_url: Option<String>,
    /// `stun:host:port`, when hosted and reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun_url: Option<String>,
    /// `turn:host:port`, when hosted and reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_url: Option<String>,
    /// True only for the frozen LegacyV1 ordinary-member application relay.
    /// The serialized key stays `relay` for wire compatibility.
    #[serde(default, rename = "relay", skip_serializing_if = "is_false")]
    pub legacy_v1_member_relay: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ServiceAdvert {
    /// Read a peer's service advert out of its capability `extra` blob.
    /// Returns `None` when absent or malformed (a malformed advert is
    /// treated as "no services" rather than failing the whole peer).
    pub fn from_extra(extra: &serde_json::Value) -> Option<ServiceAdvert> {
        let v = extra.get(SERVICE_ADVERT_KEY)?;
        serde_json::from_value(v.clone()).ok()
    }

    /// Nest this advert into a capability `extra` blob under
    /// [`SERVICE_ADVERT_KEY`], creating the object if needed. A no-op
    /// when the advert is empty so we don't bloat hello frames for
    /// devices that host nothing.
    pub fn write_into_extra(&self, extra: &mut serde_json::Value) {
        if self.is_empty() {
            return;
        }
        if !extra.is_object() {
            *extra = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(obj) = extra.as_object_mut() {
            obj.insert(
                SERVICE_ADVERT_KEY.to_string(),
                serde_json::to_value(self).unwrap_or(serde_json::Value::Null),
            );
        }
    }

    /// True when this advert carries no service at all.
    pub fn is_empty(&self) -> bool {
        self.signaling_url.is_none()
            && self.stun_url.is_none()
            && self.turn_url.is_none()
            && !self.legacy_v1_member_relay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_tags_round_trip() {
        for role in ServiceRole::all() {
            assert_eq!(ServiceRole::from_tag(role.tag()), Some(role));
        }
        assert_eq!(ServiceRole::from_tag("ring_topology"), None);
        assert_eq!(ServiceRole::from_tag("service:nope"), None);
    }

    #[test]
    fn role_tag_strings_are_stable() {
        // These strings travel on the wire — pin them so a refactor
        // can't silently break discovery across versions.
        assert_eq!(ServiceRole::LegacyV1MemberRelay.tag(), "service:relay");
        assert_eq!(ServiceRole::Signaling.tag(), "service:signaling");
        assert_eq!(ServiceRole::Stun.tag(), "service:stun");
        assert_eq!(ServiceRole::Turn.tag(), "service:turn");
    }

    #[test]
    fn advert_extra_round_trip() {
        let advert = ServiceAdvert {
            signaling_url: Some("ws://10.0.0.5:4848".into()),
            turn_url: Some("turn:10.0.0.5:3478".into()),
            legacy_v1_member_relay: true,
            ..Default::default()
        };
        let mut extra = serde_json::json!({ "other": "kept" });
        advert.write_into_extra(&mut extra);
        // Existing keys survive.
        assert_eq!(extra.get("other").and_then(|v| v.as_str()), Some("kept"));
        let back = ServiceAdvert::from_extra(&extra).unwrap();
        assert_eq!(back, advert);
    }

    #[test]
    fn empty_advert_not_written() {
        let advert = ServiceAdvert::default();
        let mut extra = serde_json::Value::Null;
        advert.write_into_extra(&mut extra);
        assert!(extra.is_null());
        assert_eq!(ServiceAdvert::from_extra(&extra), None);
    }

    #[test]
    fn relay_only_advert_skips_url_fields() {
        let advert = ServiceAdvert {
            legacy_v1_member_relay: true,
            ..Default::default()
        };
        let s = serde_json::to_string(&advert).unwrap();
        // Optional URL fields are omitted entirely when absent.
        assert_eq!(s, r#"{"relay":true}"#);
    }
}
