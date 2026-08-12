//! Typed publish/subscribe channels between peers.
//!
//! Embedders register a [`Channel`] by name; both ends use the
//! same name to bind their senders to their receivers. Messages
//! are serialized as JSON on the wire (the
//! [`crate::protocol::MeshMessage::Channel`] variant carries the
//! channel name + JSON payload), so any `Serialize +
//! DeserializeOwned` type works.
//!
//! Delivery is best-effort: if no peer with the named channel is
//! connected, the send still succeeds but reaches nobody. The
//! engine's per-peer queue applies its own backpressure; the
//! channel layer never holds bytes for a peer that isn't yet up.

use std::marker::PhantomData;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::engine::state::NetworkState;
use crate::identity::DeviceId;

#[derive(thiserror::Error, Debug)]
pub enum ChannelError {
    #[error("network has been torn down")]
    NetworkDown,
    #[error("peer {0} not found in active set")]
    PeerNotFound(String),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("transport: {0}")]
    Transport(String),
    #[error("application gateway lagged by {0} accepted messages")]
    Lagged(u64),
    #[error("application gateway resource pressure: {0:?}")]
    ResourcePressure(crate::resource::ResourceUnavailable),
    #[error("application command admission: {0}")]
    Admission(String),
}

/// One inbound message on a channel, paired with the peer that
/// sent it.
pub struct ChannelMessage<T> {
    pub from: DeviceId,
    pub body: T,
    _gateway_retention: crate::resource::ResourceLease,
}

/// Typed handle to a named channel. Cheap to clone — multiple
/// holders can `subscribe` independently; each subscription owns a distinct,
/// resource-backed Application Gateway mailbox.
pub struct Channel<T> {
    pub(crate) name: Arc<String>,
    pub(crate) network: Arc<NetworkState>,
    _phantom: PhantomData<T>,
}

impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            network: self.network.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T> Channel<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Build a channel handle bound to the given network's
    /// engine state. Most embedders should use
    /// [`crate::JoinedNetwork::channel`] instead — this is the
    /// raw constructor for advanced callers that hold the
    /// engine state directly (e.g. integration tests).
    pub fn new(name: String, network: Arc<NetworkState>) -> Self {
        Self {
            name: Arc::new(name),
            network,
            _phantom: PhantomData,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Send a message to one specific peer. Returns `PeerNotFound`
    /// when the peer isn't currently in the active set —
    /// embedders that want to queue-until-available need to
    /// observe [`crate::MeshEvent::Peer`] events first.
    pub async fn send_to(&self, peer: &str, body: &T) -> Result<(), ChannelError> {
        let payload = serde_json::to_value(body)?;
        self.network
            .send_channel_frame(peer, &self.name, payload)
            .await
            .map_err(|e| match e {
                crate::error::Error::Network(msg) if msg.contains("not found") => {
                    ChannelError::PeerNotFound(peer.to_string())
                }
                crate::error::Error::ResourceMailboxAdmission(
                    crate::resource::ResourceMailboxAdmissionError::Closed,
                ) => ChannelError::NetworkDown,
                crate::error::Error::ResourceMailboxAdmission(
                    crate::resource::ResourceMailboxAdmissionError::Pressure(error),
                ) => ChannelError::ResourcePressure(error),
                crate::error::Error::ResourceMailboxAdmission(error) => {
                    ChannelError::Admission(error.to_string())
                }
                crate::error::Error::Transport(msg) => ChannelError::Transport(msg),
                other => ChannelError::Transport(other.to_string()),
            })
    }

    /// Send under the acknowledged-delivery contract: the frame is retained by
    /// the peer's live session until that peer's engine acknowledges having
    /// handed it to its application layer, and this call resolves when it does.
    ///
    /// Delivery is scoped to one session. A peer with no live session is an
    /// error rather than a reason to park, and a frame still outstanding when
    /// its session ends resolves with that fact. So a caller is always told
    /// what became of its frame, and never waits on a session that is gone.
    pub async fn send_to_acked(&self, peer: &str, body: &T) -> Result<(), ChannelError> {
        let payload = serde_json::to_value(body)?;
        self.network
            .send_channel_reliable(peer, &self.name, payload)
            .await
            .map_err(|e| match e {
                crate::error::Error::ResourceMailboxAdmission(
                    crate::resource::ResourceMailboxAdmissionError::Closed,
                ) => ChannelError::NetworkDown,
                crate::error::Error::ResourceMailboxAdmission(
                    crate::resource::ResourceMailboxAdmissionError::Pressure(error),
                ) => ChannelError::ResourcePressure(error),
                crate::error::Error::ResourceMailboxAdmission(error) => {
                    ChannelError::Admission(error.to_string())
                }
                crate::error::Error::Transport(msg) => ChannelError::Transport(msg),
                other => ChannelError::Transport(other.to_string()),
            })
    }

    /// Broadcast to every active peer. Returns the count of peers
    /// the send was dispatched to (a send-success count, not a
    /// delivery-success count — the underlying data channel is
    /// reliable but the peer may have left between dispatch and
    /// the WebRTC stack actually flushing).
    pub async fn broadcast(&self, body: &T) -> Result<usize, ChannelError> {
        let payload = serde_json::to_value(body)?;
        self.network
            .broadcast_channel_frame(&self.name, payload)
            .await
            .map_err(|error| match error {
                crate::error::Error::ResourceMailboxAdmission(
                    crate::resource::ResourceMailboxAdmissionError::Closed,
                ) => ChannelError::NetworkDown,
                crate::error::Error::ResourceMailboxAdmission(
                    crate::resource::ResourceMailboxAdmissionError::Pressure(error),
                ) => ChannelError::ResourcePressure(error),
                crate::error::Error::ResourceMailboxAdmission(error) => {
                    ChannelError::Admission(error.to_string())
                }
                other => ChannelError::Transport(other.to_string()),
            })
    }

    /// Subscribe to inbound messages on this channel. The returned receiver
    /// owns a distinct resource-backed mailbox; pressure and loss are surfaced
    /// rather than hidden behind a shared ring.
    pub fn subscribe(&self) -> Result<ChannelSubscription<T>, ChannelError> {
        let subscriber = self
            .network
            .application_gateway
            .subscribe_channel(&self.name)
            .map_err(|refusal| match refusal {
                crate::application_gateway::GatewayRefusal::Revoked => ChannelError::NetworkDown,
                crate::application_gateway::GatewayRefusal::Pressure(error) => {
                    ChannelError::ResourcePressure(error)
                }
                other => ChannelError::Transport(format!("{other:?}")),
            })?;
        Ok(ChannelSubscription {
            subscriber,
            name: Arc::clone(&self.name),
            network: Arc::clone(&self.network),
            _phantom: PhantomData,
        })
    }
}

/// Inbound side of one resource-backed Application Gateway mailbox.
pub struct ChannelSubscription<T> {
    subscriber: Arc<crate::application_gateway::ChannelSubscriber>,
    name: Arc<String>,
    network: Arc<NetworkState>,
    _phantom: PhantomData<T>,
}

impl<T> Drop for ChannelSubscription<T> {
    fn drop(&mut self) {
        self.network
            .application_gateway
            .unsubscribe_channel(&self.name, &self.subscriber);
    }
}

impl<T> ChannelSubscription<T>
where
    T: DeserializeOwned,
{
    /// Await the next message. Returns `None` if the channel has
    /// been torn down (network closed). Surfaces deserialization
    /// failures as `Err`.
    pub async fn recv(&mut self) -> Option<Result<ChannelMessage<T>, ChannelError>> {
        let delivery = match self.subscriber.recv().await {
            Ok(delivery) => delivery,
            Err(crate::application_gateway::GatewayRefusal::Revoked) => return None,
            Err(crate::application_gateway::GatewayRefusal::Lag(skipped)) => {
                return Some(Err(ChannelError::Lagged(skipped)))
            }
            Err(other) => return Some(Err(ChannelError::Transport(format!("{other:?}")))),
        };
        let (frame, retention) = delivery.into_parts();
        let body = match serde_json::from_value::<T>(frame.payload) {
            Ok(value) => value,
            Err(error) => return Some(Err(ChannelError::Serialize(error))),
        };
        Some(Ok(ChannelMessage {
            from: frame.from,
            body,
            _gateway_retention: retention,
        }))
    }
}
