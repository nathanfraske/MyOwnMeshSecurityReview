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
        let channel: crate::Channel<RelayEnvelope> =
            crate::Channel::new(RELAY_CHANNEL.to_string(), std::sync::Arc::clone(&state));
        let mut subscription = channel.subscribe();
        let listener = tokio::spawn(async move {
            while let Some(item) = subscription.recv().await {
                let message = match item {
                    Ok(message) => message,
                    Err(_) => continue,
                };
                let Ok(payload) = serde_json::to_value(&message.body) else {
                    continue;
                };
                if routing::on_relay_frame(&listener_state, &message.from, &payload).await {
                    continue;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MeshMessage;
    use crate::transport::webrtc::WebRtcConnectorEventReceiver;
    use crate::transport::{DataChannelOpenOwnership, Role, TransportEvent, WebRtcConnectorWorker};
    use std::sync::Arc;
    use std::time::Duration;

    struct TestLink {
        left: Arc<WebRtcConnectorWorker>,
        _left_events: WebRtcConnectorEventReceiver,
        left_auth: Arc<crate::endpoint_auth::EndpointAuthTask>,
        right: Arc<WebRtcConnectorWorker>,
        right_events: WebRtcConnectorEventReceiver,
        right_auth: Arc<crate::endpoint_auth::EndpointAuthTask>,
    }

    async fn connect(
        left_state: &Arc<crate::engine::state::NetworkState>,
        right_state: &Arc<crate::engine::state::NetworkState>,
    ) -> TestLink {
        let (left, mut left_events) = left_state
            .transport
            .open_connector_peer(
                Role::Offerer,
                &[],
                &[],
                left_state.peer_connection_resource_scope(),
            )
            .await
            .expect("left connector opens");
        let (right, mut right_events) = right_state
            .transport
            .open_connector_peer(
                Role::Answerer,
                &[],
                &[],
                right_state.peer_connection_resource_scope(),
            )
            .await
            .expect("right connector opens");
        let left = Arc::new(left);
        let right = Arc::new(right);

        let offer = left.create_offer().await.expect("create offer");
        right
            .apply_remote_description(offer)
            .await
            .expect("apply offer");
        let answer = right.create_answer().await.expect("create answer");
        left.apply_remote_description(answer)
            .await
            .expect("apply answer");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut left_auth = None;
        let mut right_auth = None;
        while (left_auth.is_none() || right_auth.is_none())
            && tokio::time::Instant::now() < deadline
        {
            tokio::select! {
                event = left_events.recv() => {
                    let event = event.expect("left connector remains live");
                    if let Some(event) = left.accept_event(event) {
                        match event {
                            TransportEvent::LocalIceCandidate(Some(candidate)) => {
                                right.add_remote_candidate(candidate).await.expect("right accepts candidate");
                            }
                            TransportEvent::DataChannelOpen if left_auth.is_none() => {
                                let handoff = match left.confirm_data_channel_open() {
                                    DataChannelOpenOwnership::Connected(handoff) => handoff,
                                    _ => panic!("left exact candidate promotes once"),
                                };
                                left_events.commit_data_channel_open();
                                left_auth = Some(Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(handoff)));
                            }
                            _ => {}
                        }
                    }
                }
                event = right_events.recv() => {
                    let event = event.expect("right connector remains live");
                    if let Some(event) = right.accept_event(event) {
                        match event {
                            TransportEvent::LocalIceCandidate(Some(candidate)) => {
                                left.add_remote_candidate(candidate).await.expect("left accepts candidate");
                            }
                            TransportEvent::DataChannelOpen if right_auth.is_none() => {
                                let handoff = match right.confirm_data_channel_open() {
                                    DataChannelOpenOwnership::Connected(handoff) => handoff,
                                    _ => panic!("right exact candidate promotes once"),
                                };
                                right_events.commit_data_channel_open();
                                right_auth = Some(Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(handoff)));
                            }
                            _ => {}
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }

        TestLink {
            left,
            _left_events: left_events,
            left_auth: left_auth.expect("left data channel opens"),
            right,
            right_events,
            right_auth: right_auth.expect("right data channel opens"),
        }
    }

    async fn next_legacy_payload(
        worker: &WebRtcConnectorWorker,
        events: &mut WebRtcConnectorEventReceiver,
    ) -> (String, serde_json::Value) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = events.recv().await.expect("connector remains live");
                if let Some(TransportEvent::Message(bytes)) = worker.accept_event(event) {
                    let message: MeshMessage =
                        serde_json::from_slice(&bytes).expect("mesh frame decodes");
                    if let MeshMessage::Channel { channel, payload } = message {
                        if channel == RELAY_CHANNEL {
                            return (channel, payload);
                        }
                    }
                }
            }
        })
        .await
        .expect("legacy payload reaches the next native peer")
    }

    #[tokio::test]
    #[ignore = "opens two native WebRTC links; run in the isolated WSL legacy-v1 control"]
    async fn v4_arc03h_legacy_v1_delivers_one_payload_across_two_native_hops() {
        let state_a = crate::engine::build_test_state("legacy-hop-a");
        let state_b = crate::engine::build_test_state("legacy-hop-b");
        let state_c = crate::engine::build_test_state("legacy-hop-c");
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

        let app_channel: crate::Channel<serde_json::Value> =
            crate::Channel::new("legacy-v1-test".to_string(), Arc::clone(&state_c));
        let mut application = app_channel.subscribe();
        let runtime = LegacyV1Runtime::frozen();
        let legacy_a = LegacyV1Network::bind_state(&runtime, Arc::clone(&state_a));
        let _legacy_b = LegacyV1Network::bind_state(&runtime, Arc::clone(&state_b));
        let _legacy_c = LegacyV1Network::bind_state(&runtime, Arc::clone(&state_c));
        let _relay_b = RelayService::start(Arc::clone(&state_b), 0, &runtime);
        state_b.dispatch_channel_frame(
            RELAY_CHANNEL,
            &id_a,
            serde_json::json!({"malformed": true}),
        );
        let payload = serde_json::json!({"proof": "two-native-hops"});
        legacy_a
            .send_to(&id_c, "legacy-v1-test", &payload)
            .await
            .expect("A hands the payload to B");

        let (_, at_b) = next_legacy_payload(&ab.right, &mut ab.right_events).await;
        state_b.dispatch_channel_frame(RELAY_CHANNEL, &id_a, at_b);
        let (_, at_c) = next_legacy_payload(&bc.right, &mut bc.right_events).await;
        state_c.dispatch_channel_frame(RELAY_CHANNEL, &id_b, at_c);
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
    }
}
