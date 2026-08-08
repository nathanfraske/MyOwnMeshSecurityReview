//! Explicit runtime authority for frozen pre-V4 application routing compatibility.
//!
//! This profile does not belong to the V4 connector, Endpoint Auth, or
//! session-capability path. It exists only so downstream applications can
//! retain the historical routing and relay behavior while they migrate. New
//! code must enable the `legacy-v1` feature and pass this runtime at the
//! construction boundary.

#![allow(
    deprecated,
    reason = "deprecated uses are confined to this frozen LegacyV1 compatibility subtree"
)]

pub mod relay;
mod routing;

pub use relay::{relay_targets, RelayEnvelope, RelayService, RELAY_CHANNEL};

/// Explicit opt-in runtime for the frozen LegacyV1 routing and relay behavior.
///
/// This type exists only when the `legacy-v1` feature is enabled. Possessing it
/// lets a compatibility owner bind the separate LegacyV1 network facade. No
/// V4 connector or session capability can obtain that facade implicitly.
#[derive(Clone, Debug)]
pub struct LegacyV1Runtime {
    _sealed: (),
}

impl LegacyV1Runtime {
    /// Construct the one frozen compatibility runtime.
    #[deprecated(
        since = "0.3.2",
        note = "LegacyV1 application routing is frozen and scheduled for removal after downstream migration"
    )]
    pub const fn frozen() -> Self {
        Self { _sealed: () }
    }
}

/// Explicit network facade for the frozen multi-hop application path.
#[deprecated(
    since = "0.3.2",
    note = "LegacyV1 application routing is frozen and scheduled for removal after downstream migration"
)]
pub struct LegacyV1Network {
    state: std::sync::Arc<crate::engine::state::NetworkState>,
    listener: tokio::task::JoinHandle<()>,
}

#[allow(
    deprecated,
    reason = "this implementation is confined to the frozen LegacyV1 subtree"
)]
impl LegacyV1Network {
    pub fn bind(runtime: &LegacyV1Runtime, network: &crate::JoinedNetwork) -> Self {
        Self::bind_state(runtime, network.state())
    }

    fn bind_state(
        runtime: &LegacyV1Runtime,
        state: std::sync::Arc<crate::engine::state::NetworkState>,
    ) -> Self {
        let _authority = runtime;
        let listener_state = std::sync::Arc::clone(&state);
        let channel: crate::Channel<routing::RoutedEnvelope> = crate::Channel::new(
            routing::ROUTING_CHANNEL.to_string(),
            std::sync::Arc::clone(&state),
        );
        let mut subscription = channel.subscribe();
        let listener = tokio::spawn(async move {
            while let Some(item) = subscription.recv().await {
                let message = match item {
                    Ok(message) => message,
                    Err(_) => continue,
                };
                routing::on_routed_frame(&listener_state, &message.from, message.body).await;
            }
        });
        Self { state, listener }
    }

    pub async fn send_to(
        &self,
        destination: &str,
        channel: &str,
        payload: &serde_json::Value,
    ) -> crate::Result<()> {
        routing::send_routed(&self.state, destination, channel, payload).await
    }

    pub async fn broadcast(&self, channel: &str, payload: &serde_json::Value) -> usize {
        routing::broadcast_flood(&self.state, channel, payload).await
    }
}

impl Drop for LegacyV1Network {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

/// LegacyV1 routing controls.
///
/// Only routing controls live here. The native endpoint-authentication controls
/// that used to share this module are basal V4 behaviour, not compatibility
/// behaviour, and now live in `endpoint_auth::native_link` so that deleting this
/// subtree cannot delete them. The two-connector fixture moved with them and is
/// borrowed back here, which is why this module needs `transport-lab` as well as
/// `legacy-v1` to exercise its native control.
#[cfg(all(test, feature = "transport-lab"))]
mod tests {
    use super::*;
    use crate::endpoint_auth::native_link::connect;
    use crate::protocol::MeshMessage;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "opens two native WebRTC links; run in the isolated WSL legacy-v1 control"]
    async fn v4_arc03h_legacy_v1_delivers_one_payload_across_two_native_hops() {
        let (state_a, command_a) =
            crate::engine::build_test_state_with_command_driver("legacy-hop-a");
        let (state_b, command_b) =
            crate::engine::build_test_state_with_command_driver("legacy-hop-b");
        let (state_c, command_c) =
            crate::engine::build_test_state_with_command_driver("legacy-hop-c");
        let id_a = state_a.identity.public_id().to_string();
        let id_b = state_b.identity.public_id().to_string();
        let id_c = state_c.identity.public_id().to_string();
        for state in [&state_a, &state_b, &state_c] {
            *state.topology.write() = crate::TopologyMode::Star { hub: id_b.clone() };
            *state.topology_impl.write() =
                crate::topology::from_mode(&crate::TopologyMode::Star { hub: id_b.clone() });
        }

        let mut ab = connect(&state_a, &state_b).await;
        let mut bc = connect(&state_b, &state_c).await;
        crate::engine::insert_admitted_legacy_test_peer(
            &state_a,
            &id_b,
            Arc::clone(&ab.left),
            Arc::clone(&ab.left_auth),
        );
        crate::engine::insert_admitted_legacy_test_peer(
            &state_b,
            &id_a,
            Arc::clone(&ab.right),
            Arc::clone(&ab.right_auth),
        );
        crate::engine::insert_admitted_legacy_test_peer(
            &state_b,
            &id_c,
            Arc::clone(&bc.left),
            Arc::clone(&bc.left_auth),
        );
        crate::engine::insert_admitted_legacy_test_peer(
            &state_c,
            &id_b,
            Arc::clone(&bc.right),
            Arc::clone(&bc.right_auth),
        );
        {
            let mut relay_roster = state_b.roster.write();
            crate::roster::add_peer_in(&mut relay_roster, &id_a, "legacy-hop-a");
            crate::roster::add_peer_in(&mut relay_roster, &id_c, "legacy-hop-c");
        }

        let app_channel: crate::Channel<serde_json::Value> =
            crate::Channel::new("legacy-v1-test".to_string(), Arc::clone(&state_c));
        let mut application = app_channel.subscribe();
        let historical_wire: crate::Channel<relay::RelayEnvelope> =
            crate::Channel::new(relay::RELAY_CHANNEL.to_string(), Arc::clone(&state_c));
        let mut historical_delivery = historical_wire.subscribe();
        let runtime = LegacyV1Runtime::frozen();
        let legacy_a = LegacyV1Network::bind_state(&runtime, Arc::clone(&state_a));
        let _legacy_b = LegacyV1Network::bind_state(&runtime, Arc::clone(&state_b));
        let _legacy_c = LegacyV1Network::bind_state(&runtime, Arc::clone(&state_c));
        let _relay_b = RelayService::start(Arc::clone(&state_b), 0, &runtime);
        let pump_b = crate::engine::spawn_admitted_legacy_test_pump(
            Arc::clone(&state_b),
            id_a.clone(),
            Arc::clone(&ab.right),
            ab.right_events
                .take()
                .expect("B owns the AB endpoint event stream"),
        );
        let pump_c = crate::engine::spawn_admitted_legacy_test_pump(
            Arc::clone(&state_c),
            id_b.clone(),
            Arc::clone(&bc.right),
            bc.right_events
                .take()
                .expect("C owns the BC endpoint event stream"),
        );
        let historical = relay::RelayEnvelope {
            dst: id_c.clone(),
            src: id_a.clone(),
            payload: serde_json::json!({
                "__channel": "legacy-v1-test",
                "__body": {"must": "fail-closed"},
                "__ttl": 2,
                "__id": 7001
            }),
        };
        let historical = serde_json::to_vec(&MeshMessage::Channel {
            channel: relay::RELAY_CHANNEL.to_string(),
            payload: serde_json::to_value(historical)
                .expect("historical routed wrapper encodes on its old relay wire"),
        })
        .expect("historical mixed-version frame encodes as endpoint bytes");
        ab.left
            .send_owned(historical.into())
            .await
            .expect("historical frame reaches the corrected intermediate owner");

        let plain_barrier_payload = serde_json::json!({"barrier": "plain-relay"});
        let plain_barrier = relay::RelayEnvelope {
            dst: id_c.clone(),
            src: id_a.clone(),
            payload: plain_barrier_payload.clone(),
        };
        let plain_barrier = serde_json::to_vec(&MeshMessage::Channel {
            channel: relay::RELAY_CHANNEL.to_string(),
            payload: serde_json::to_value(plain_barrier)
                .expect("plain-relay barrier encodes on its reserved wire"),
        })
        .expect("plain-relay barrier encodes as endpoint bytes");
        ab.left
            .send_owned(plain_barrier.into())
            .await
            .expect("plain-relay barrier reaches the corrected intermediate owner");
        let delivered_barrier =
            tokio::time::timeout(Duration::from_secs(2), historical_delivery.recv())
                .await
                .expect("the ordered plain-relay barrier reaches C")
                .expect("historical-wire subscription remains open")
                .expect("plain-relay barrier decodes");
        assert_eq!(delivered_barrier.body.payload, plain_barrier_payload);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), historical_delivery.recv())
                .await
                .is_err(),
            "the historical routed wrapper was not forwarded before or after the ordered plain-relay barrier"
        );
        let malformed = serde_json::to_vec(&MeshMessage::Channel {
            channel: routing::ROUTING_CHANNEL.to_string(),
            payload: serde_json::json!({"malformed": true}),
        })
        .expect("malformed routed control frame encodes as endpoint bytes");
        ab.left
            .send_owned(malformed.into())
            .await
            .expect("malformed routed frame crosses the first native link");
        let payload = serde_json::json!({"proof": "two-native-hops"});
        legacy_a
            .send_to(&id_c, "legacy-v1-test", &payload)
            .await
            .expect("A hands the payload to B");

        let delivered = tokio::time::timeout(Duration::from_secs(2), application.recv())
            .await
            .expect("application delivery is bounded")
            .expect("application channel remains open")
            .expect("application payload decodes");
        assert_eq!(delivered.from, id_a);
        assert_eq!(delivered.body, payload);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), application.recv())
                .await
                .is_err(),
            "directed LegacyV1 payload is delivered exactly once"
        );

        for worker in [&ab.left, &ab.right, &bc.left, &bc.right] {
            worker
                .retire_and_close()
                .await
                .expect("native legacy test connector closes");
        }
        pump_b.abort();
        pump_c.abort();
        for state in [&state_a, &state_b, &state_c] {
            let _ = state.cmd_tx.send(crate::engine::NetworkCmd::Shutdown);
        }
        for command in [command_a, command_b, command_c] {
            command.await.expect("legacy command driver stops cleanly");
        }
    }
}
