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
        right_events: Option<WebRtcConnectorEventReceiver>,
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
                        let (event, _callback_resources) = event.into_parts();
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
                        let (event, _callback_resources) = event.into_parts();
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
            right_events: Some(right_events),
            right_auth: right_auth.expect("right data channel opens"),
        }
    }

    /// Terminating-signaling-MITM / fingerprint substitution, through the live
    /// `on_auth_response` handler.
    ///
    /// An interceptor that terminates DTLS on each leg must present its own
    /// certificate, so the fingerprints the victim observes differ from the
    /// ones the real peer signed. This drives that condition on a real link:
    /// the AuthResponse is otherwise entirely correct — right signer, right
    /// identities, right mesh context, right profile, right contributions —
    /// and differs only in the fingerprint pair it commits to.
    ///
    /// Transcript-level inequality is not the gate; this asserts the exact
    /// current peer is refused and removed by the production handler.
    #[tokio::test]
    #[ignore = "opens a native WebRTC link; run in the isolated WSL legacy-v1 control"]
    async fn v4_arc04_substituted_fingerprint_is_refused_by_the_live_handler() {
        let state_a = crate::engine::build_test_state("arc04-mitm-a");
        let state_b = crate::engine::build_test_state("arc04-mitm-b");
        let id_a = state_a.identity.public_id().to_string();
        let id_b = state_b.identity.public_id().to_string();

        let link = connect(&state_a, &state_b).await;
        // Pre-promotion state on purpose: this control must observe the forged
        // proof fail to promote, so it cannot start with a capability already
        // installed. The shared *admitted* fixture preinstalls one, which would
        // mask exactly the outcome under test.
        crate::engine::insert_legacy_test_peer_pending_auth(
            &state_a,
            &id_b,
            Arc::clone(&link.left),
            Arc::clone(&link.left_auth),
        );
        let owner =
            crate::engine::legacy_test_owner(&state_a, &id_b).expect("peer owner is installed");
        assert!(
            !crate::engine::legacy_test_has_authenticated_channel(&state_a, &owner),
            "non-vacuity: the channel must be unauthenticated before the forged proof"
        );

        // The genuine channel material this side observes.
        let observed_local = link
            .left
            .local_fingerprint()
            .await
            .expect("the live link exposes our fingerprint");
        let observed_remote = link
            .left
            .remote_fingerprint()
            .await
            .expect("the live link exposes the peer's fingerprint");

        // What an interceptor would have presented instead.
        let substituted_remote = format!("{observed_remote}:ff");
        assert_ne!(
            substituted_remote, observed_remote,
            "non-vacuity: the substituted fingerprint must differ from the observed one"
        );

        // Both contributions, recorded as a completed exchange would leave them.
        let our_contribution = crate::endpoint_auth::LocalContribution::generate();
        let peer_contribution = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical");
        let our_contribution_bytes = crate::engine::legacy_test_seed_contributions(
            &state_a,
            &owner,
            our_contribution,
            peer_contribution.clone(),
        )
        .expect("the exact current peer records both contributions");

        // The peer's half, signed over the SUBSTITUTED pair. Everything else
        // matches what this side will reconstruct.
        let signer_role = crate::endpoint_auth::EndpointAuthAttempt::role_of(&id_a, &id_b).peer();
        let forged = crate::signing::sign_with(
            state_b.identity.signing_key(),
            &crate::endpoint_auth::EndpointAuthAttempt::transcript_bytes(
                &state_a.network_id,
                crate::endpoint_auth::EndpointAuthProfile::V1Ed25519Dtls,
                signer_role,
                &id_a,
                &id_b,
                &our_contribution_bytes,
                peer_contribution.as_str(),
                &observed_local,
                &substituted_remote,
            ),
        );

        crate::engine::handshake::on_auth_response(
            &state_a,
            &owner,
            crate::protocol::handshake::AuthResponseMessage { signature: forged },
        )
        .await;

        assert!(
            !crate::engine::legacy_test_has_authenticated_channel(&state_a, &owner),
            "a proof committing to a substituted fingerprint must not authenticate \
             this channel"
        );
    }

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
