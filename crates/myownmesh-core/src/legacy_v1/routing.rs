//! Frozen topology-aware application routing for LegacyV1.
//!
//! Routed frames use a typed envelope on [`ROUTING_CHANNEL`]. Opaque plain
//! relay frames use the separate [`super::relay::RELAY_CHANNEL`]. The wire
//! channel decides the compatibility behavior. Application payload content is
//! never inspected to infer routing.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, trace};

use crate::engine::connection::PeerStatus;
use crate::engine::state::NetworkState;
use crate::error::{Error, Result};

/// Dedup-ring capacity for `(origin, frame id)` pairs.
pub(crate) const ROUTING_SEEN_CAPACITY: usize = 2048;

/// Explicit routed wire. This must remain disjoint from the plain relay wire.
pub(crate) const ROUTING_CHANNEL: &str = "__mesh_route__/v1";

/// One explicitly routed LegacyV1 application frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RoutedEnvelope {
    #[serde(default)]
    dst: String,
    #[serde(default)]
    src: String,
    channel: String,
    body: Value,
    ttl: u8,
    id: u64,
}

impl RoutedEnvelope {
    fn has_valid_shape(&self) -> bool {
        !self.channel.is_empty()
            && self.channel != ROUTING_CHANNEL
            && self.channel != super::relay::RELAY_CHANNEL
            && self.id != 0
    }
}

fn fresh_frame_id() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen::<u64>() | 1
}

fn first_sighting(state: &NetworkState, origin: &str, id: u64) -> bool {
    let mut seen = state.routing_seen.lock();
    if seen
        .iter()
        .any(|(seen_origin, seen_id)| *seen_id == id && seen_origin == origin)
    {
        return false;
    }
    if seen.len() >= ROUTING_SEEN_CAPACITY {
        seen.pop_front();
    }
    seen.push_back((origin.to_string(), id));
    true
}

fn connected_ids(state: &NetworkState) -> Vec<String> {
    state
        .peer_snapshot()
        .into_iter()
        .filter(|peer| matches!(peer.status, PeerStatus::Active | PeerStatus::Shelved))
        .map(|peer| peer.device_id)
        .collect()
}

/// Consume one value that was decoded from the exact routed wire.
pub(crate) async fn on_routed_frame(
    state: &Arc<NetworkState>,
    from: &str,
    envelope: RoutedEnvelope,
) {
    if !envelope.has_valid_shape() {
        trace!("dropping malformed LegacyV1 routed envelope");
        return;
    }

    let me = state.identity.public_id().to_string();
    let origin = if envelope.src.is_empty() {
        from.to_string()
    } else {
        envelope.src.clone()
    };

    if origin != from {
        let carrier_forwards = {
            let known = connected_ids(state);
            state.topology_impl.read().forwards(from, &known)
        };
        if !carrier_forwards {
            debug!(
                from = %crate::engine::short_peer(from),
                origin = %crate::engine::short_peer(&origin),
                "dropping routed frame from a non-forwarding carrier"
            );
            return;
        }
    }

    if !first_sighting(state, &origin, envelope.id) {
        return;
    }

    let broadcast = envelope.dst.is_empty();
    let for_me = broadcast || envelope.dst == me;
    if for_me {
        state.dispatch_channel_frame(&envelope.channel, &origin, envelope.body.clone());
    }
    if !broadcast && envelope.dst == me {
        return;
    }

    let (i_forward, connected) = {
        let connected = connected_ids(state);
        let forwards = state.topology_impl.read().forwards(&me, &connected);
        (forwards, connected)
    };
    if !i_forward || envelope.ttl == 0 {
        if !broadcast && !i_forward {
            trace!(
                dst = %crate::engine::short_peer(&envelope.dst),
                "routed frame reached a non-forwarder that is not its destination"
            );
        }
        return;
    }

    state.traffic.record_forwarded();
    let onward = RoutedEnvelope {
        dst: envelope.dst.clone(),
        src: origin.clone(),
        channel: envelope.channel,
        body: envelope.body,
        ttl: envelope.ttl - 1,
        id: envelope.id,
    };

    if broadcast {
        for peer in connected {
            if peer == from || peer == origin {
                continue;
            }
            let _ = send_envelope(state, &peer, &onward).await;
        }
    } else {
        let hops = if connected.iter().any(|peer| peer == &onward.dst) {
            vec![onward.dst.clone()]
        } else {
            state
                .topology_impl
                .read()
                .next_hops(&me, &onward.dst, &connected)
        };
        for hop in hops {
            if hop == from {
                continue;
            }
            if send_envelope(state, &hop, &onward).await.is_ok() {
                break;
            }
        }
    }
}

async fn send_envelope(
    state: &Arc<NetworkState>,
    peer: &str,
    envelope: &RoutedEnvelope,
) -> Result<()> {
    let channel: crate::Channel<RoutedEnvelope> =
        crate::Channel::new(ROUTING_CHANNEL.to_string(), Arc::clone(state));
    channel
        .send_to(peer, envelope)
        .await
        .map_err(|error| Error::Network(format!("LegacyV1 routed send to {peer} failed: {error}")))
}

pub(crate) async fn send_routed(
    state: &Arc<NetworkState>,
    destination: &str,
    channel: &str,
    payload: &Value,
) -> Result<()> {
    if channel.is_empty() || channel == ROUTING_CHANNEL || channel == super::relay::RELAY_CHANNEL {
        return Err(Error::Network(
            "LegacyV1 routed application channel is empty or reserved".to_string(),
        ));
    }
    let me = state.identity.public_id().to_string();
    let (hops, ttl) = {
        let connected = connected_ids(state);
        let topology = state.topology_impl.read();
        (
            topology.next_hops(&me, destination, &connected),
            topology.flood_ttl(),
        )
    };
    if hops.is_empty() {
        return Err(Error::Network(format!(
            "no route to {destination}: the topology names no reachable next hop"
        )));
    }

    let id = fresh_frame_id();
    first_sighting(state, &me, id);
    let envelope = RoutedEnvelope {
        dst: destination.to_string(),
        src: me,
        channel: channel.to_string(),
        body: payload.clone(),
        ttl,
        id,
    };
    let mut last_error = None;
    for hop in hops {
        match send_envelope(state, &hop, &envelope).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::Network(format!("no forwarder accepted the frame for {destination}"))
    }))
}

pub(crate) async fn broadcast_flood(
    state: &Arc<NetworkState>,
    channel: &str,
    payload: &Value,
) -> usize {
    if channel.is_empty() || channel == ROUTING_CHANNEL || channel == super::relay::RELAY_CHANNEL {
        return 0;
    }
    let me = state.identity.public_id().to_string();
    let id = fresh_frame_id();
    first_sighting(state, &me, id);
    let envelope = RoutedEnvelope {
        dst: String::new(),
        src: me,
        channel: channel.to_string(),
        body: payload.clone(),
        ttl: state.topology_impl.read().flood_ttl(),
        id,
    };
    let targets: Vec<String> = state
        .peer_snapshot()
        .into_iter()
        .filter(|peer| {
            matches!(peer.status, PeerStatus::Active) && !peer.local_shelved && !peer.remote_shelved
        })
        .map(|peer| peer.device_id)
        .collect();
    let mut delivered = 0usize;
    for peer in targets {
        if send_envelope(state, &peer, &envelope).await.is_ok() {
            delivered += 1;
        }
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn routed_and_plain_relay_wires_are_disjoint() {
        assert_ne!(ROUTING_CHANNEL, super::super::relay::RELAY_CHANNEL);
        let routed = RoutedEnvelope {
            dst: "c".to_string(),
            src: "a".to_string(),
            channel: "app.control".to_string(),
            body: json!({"__channel": "arbitrary-application-key"}),
            ttl: 3,
            id: 42,
        };
        let encoded = serde_json::to_value(&routed).expect("typed routed envelope encodes");
        assert_eq!(
            serde_json::from_value::<RoutedEnvelope>(encoded)
                .expect("typed routed envelope decodes"),
            routed
        );
        assert!(routed.has_valid_shape());
    }

    #[test]
    fn mixed_version_plain_payload_is_not_reclassified_as_routed() {
        let old_routing_wrapper = json!({
            "__channel": "legacy.application",
            "__destination": "c",
            "__payload": {"value": 7}
        });
        let plain_wire_value = json!({
            "dst": "c",
            "src": "a",
            "payload": old_routing_wrapper
        });
        let plain =
            serde_json::from_value::<super::super::relay::RelayEnvelope>(plain_wire_value.clone())
                .expect("the old wrapper remains an opaque plain-relay payload");
        assert_eq!(plain.payload, old_routing_wrapper);
        assert!(
            serde_json::from_value::<RoutedEnvelope>(plain_wire_value).is_err(),
            "the routed owner cannot decode a plain relay envelope by inspecting its payload"
        );
        assert_ne!(ROUTING_CHANNEL, super::super::relay::RELAY_CHANNEL);
    }

    #[tokio::test]
    async fn dedup_ring_drops_replays_and_is_bounded() {
        let state = crate::engine::build_test_state("route-dedup");
        assert!(first_sighting(&state, "origin-a", 7));
        assert!(!first_sighting(&state, "origin-a", 7));
        assert!(first_sighting(&state, "origin-b", 7));
        for id in 0..(ROUTING_SEEN_CAPACITY as u64 + 10) {
            first_sighting(&state, "origin-c", 1000 + id);
        }
        assert!(state.routing_seen.lock().len() <= ROUTING_SEEN_CAPACITY);
    }

    #[tokio::test]
    async fn spoke_cannot_launder_routed_origin() {
        let state = crate::engine::build_test_state("route-launder");
        let envelope = RoutedEnvelope {
            dst: String::new(),
            src: "claimed-origin".to_string(),
            channel: "app.control".to_string(),
            body: json!(1),
            ttl: 2,
            id: 99,
        };
        on_routed_frame(&state, "carrier-spoke", envelope).await;
        assert!(state.routing_seen.lock().is_empty());
    }

    #[test]
    fn reserved_or_malformed_routed_channels_are_rejected() {
        for channel in ["", ROUTING_CHANNEL, super::super::relay::RELAY_CHANNEL] {
            let envelope = RoutedEnvelope {
                dst: "c".to_string(),
                src: "a".to_string(),
                channel: channel.to_string(),
                body: Value::Null,
                ttl: 1,
                id: 1,
            };
            assert!(!envelope.has_valid_shape());
        }
    }
}
