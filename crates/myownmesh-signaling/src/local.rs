//! In-process loopback signaling. Used by tests and by embedding
//! apps that want to wire two `Mesh` instances together in the
//! same process without taking a dependency on a Nostr relay.
//!
//! A single [`LocalBroker`] owns the routing table. Each peer joins with the
//! outbound queue the engine fills and somewhere to put what arrives; the
//! broker fans the engine's outbound messages to the matching destination.
//! There is no inbound queue in between — see [`crate::InboundSink`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::trace;

use crate::{CarrierAttribution, InboundSink, OutboundSource, SignalingMessage};

/// Engine-side outbound message — the engine emits these for the
/// signaling driver to deliver.
#[derive(Debug, Clone)]
pub enum LocalOutbound {
    /// Sent on join: "I'm here, room handle = X".
    Announce { device_id: String },
    /// Sent during a peer exchange.
    DirectedToPeer { to: String, msg: SignalingMessage },
    /// Leave broadcast.
    Leave { device_id: String },
}

/// Engine-side inbound message — broker delivers these into the
/// engine's command queue.
#[derive(Debug, Clone)]
pub enum LocalInbound {
    PeerAnnounced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Message {
        from: String,
        msg: SignalingMessage,
    },
    PeerLeft {
        device_id: String,
        attribution: CarrierAttribution,
    },
}

/// One peer's hook into the broker. Stored in the broker's
/// routing table.
struct PeerHandle {
    device_id: String,
    inbound: InboundSink<LocalInbound>,
}

#[derive(Default)]
struct BrokerInner {
    /// Room-handle → vec of currently-joined peer handles.
    rooms: HashMap<String, Vec<PeerHandle>>,
}

/// Local broker. Shareable across mesh instances in the same
/// process; each `join` returns the per-peer outbound sender the
/// engine writes to.
#[derive(Default, Clone)]
pub struct LocalBroker {
    inner: Arc<Mutex<BrokerInner>>,
}

impl LocalBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join a peer to the named room, holding the inbound queue here.
    ///
    /// The standalone convenience: the broker builds an unbounded queue and
    /// hands back its receiver, which is what an embedder with no accountant
    /// wants. A consumer that *has* one calls [`Self::join_with_sink`] and keeps
    /// no queue at all.
    pub fn join(
        &self,
        room: &str,
        device_id: &str,
    ) -> (
        mpsc::UnboundedSender<LocalOutbound>,
        mpsc::UnboundedReceiver<LocalInbound>,
    ) {
        let (in_tx, in_rx) = mpsc::unbounded_channel::<LocalInbound>();
        let (out_tx, out_rx) = mpsc::unbounded_channel::<LocalOutbound>();
        self.join_with_sink(
            room,
            device_id,
            Box::new(crate::UnboundedSource::new(out_rx)),
            InboundSink::from_unbounded(in_tx),
        );
        (out_tx, in_rx)
    }

    /// Join a peer to the named room, delivering into the caller's sink.
    ///
    /// The broker keeps no inbound queue: every report is offered to `inbound`
    /// on the task that produced it, so a consumer that will not admit a value
    /// is not turned into a place the broker stores it.
    ///
    /// The broker keeps no outbound queue either: it pulls `outbound`, so a
    /// translated value exists only when the broker is ready to route it. See
    /// [`OutboundSource`].
    ///
    /// # The sink is called under the routing lock
    ///
    /// Registration and fan-out both offer while the routing table is held, so
    /// a sink that tried to call back into this broker would deadlock. Admitting
    /// a value is all a sink is for, and the consumers here do exactly that; the
    /// alternative — copying the peer list out and offering afterwards — would
    /// let a peer that left in between be delivered to.
    pub fn join_with_sink(
        &self,
        room: &str,
        device_id: &str,
        mut outbound: Box<dyn OutboundSource<LocalOutbound>>,
        inbound: InboundSink<LocalInbound>,
    ) {
        // Register and announce to existing peers.
        {
            let mut inner = self.inner.lock();
            let peers = inner.rooms.entry(room.to_string()).or_default();
            // Existing peers learn about us, and we learn about
            // them. Both directions fire so each side initiates
            // its handshake from the same announce signal.
            for p in peers.iter() {
                let _ = p.inbound.send(LocalInbound::PeerAnnounced {
                    device_id: device_id.to_string(),
                    attribution: CarrierAttribution::CarrierObserved,
                });
                let _ = inbound.send(LocalInbound::PeerAnnounced {
                    device_id: p.device_id.clone(),
                    attribution: CarrierAttribution::CarrierObserved,
                });
            }
            peers.push(PeerHandle {
                device_id: device_id.to_string(),
                inbound,
            });
        }

        // Forward outbound messages from this peer to the room.
        let inner = self.inner.clone();
        let room = room.to_string();
        let device_id_for_task = device_id.to_string();
        tokio::spawn(async move {
            while let Some(out) = outbound.recv().await {
                let routed = route_outbound(&inner, &room, &device_id_for_task, &out);
                trace!(routed, "broker fanout");
            }
            // Sender dropped → leave the room.
            let mut guard = inner.lock();
            if let Some(peers) = guard.rooms.get_mut(&room) {
                let left = device_id_for_task.clone();
                peers.retain(|p| p.device_id != left);
                let leave = LocalInbound::PeerLeft {
                    device_id: left,
                    attribution: CarrierAttribution::CarrierObserved,
                };
                for p in peers.iter() {
                    let _ = p.inbound.send(leave.clone());
                }
                if peers.is_empty() {
                    guard.rooms.remove(&room);
                }
            }
        });
    }
}

fn route_outbound(
    inner: &Arc<Mutex<BrokerInner>>,
    room: &str,
    from: &str,
    out: &LocalOutbound,
) -> usize {
    let inner = inner.lock();
    let Some(peers) = inner.rooms.get(room) else {
        return 0;
    };
    let mut delivered = 0;
    for p in peers.iter() {
        if p.device_id == from {
            continue;
        }
        let msg = match out {
            // Attributed to the registered handle that sent, not to the id
            // in the payload. The two are the same for an honest peer, and when
            // they differ the sender was naming somebody else.
            LocalOutbound::Announce { device_id: _ } => LocalInbound::PeerAnnounced {
                device_id: from.to_string(),
                attribution: CarrierAttribution::CarrierObserved,
            },
            LocalOutbound::DirectedToPeer { to, msg } => {
                if &p.device_id != to {
                    continue;
                }
                LocalInbound::Message {
                    from: from.to_string(),
                    msg: msg.clone(),
                }
            }
            LocalOutbound::Leave { device_id: _ } => LocalInbound::PeerLeft {
                device_id: from.to_string(),
                attribution: CarrierAttribution::CarrierObserved,
            },
        };
        if p.inbound.send(msg).is_ok() {
            delivered += 1;
        }
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn join_announces_existing_peers() {
        let broker = LocalBroker::new();
        let (_tx_a, mut rx_a) = broker.join("room1", "alice");
        // No peers in the room yet — alice gets nothing.
        let none = tokio::time::timeout(std::time::Duration::from_millis(50), rx_a.recv()).await;
        assert!(none.is_err(), "alice received unexpected event");

        let (_tx_b, mut rx_b) = broker.join("room1", "bob");
        // alice learns about bob; bob learns about alice.
        match tokio::time::timeout(std::time::Duration::from_millis(100), rx_a.recv())
            .await
            .unwrap()
            .unwrap()
        {
            LocalInbound::PeerAnnounced { device_id, .. } => assert_eq!(device_id, "bob"),
            other => panic!("alice expected PeerAnnounced(bob), got {other:?}"),
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), rx_b.recv())
            .await
            .unwrap()
            .unwrap()
        {
            LocalInbound::PeerAnnounced { device_id, .. } => assert_eq!(device_id, "alice"),
            other => panic!("bob expected PeerAnnounced(alice), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn directed_messages_route_to_recipient() {
        let broker = LocalBroker::new();
        let (tx_a, mut _rx_a) = broker.join("room1", "alice");
        let (_tx_b, mut rx_b) = broker.join("room1", "bob");
        // Drain announces
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), rx_b.recv()).await;

        tx_a.send(LocalOutbound::DirectedToPeer {
            to: "bob".into(),
            msg: SignalingMessage::Offer {
                peer_id: "alice".into(),
                offer_id: "o1".into(),
                sdp: "fake-sdp".into(),
            },
        })
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        match got {
            LocalInbound::Message { from, msg } => {
                assert_eq!(from, "alice");
                if let SignalingMessage::Offer { sdp, .. } = msg {
                    assert_eq!(sdp, "fake-sdp");
                } else {
                    panic!("expected Offer");
                }
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }
}
