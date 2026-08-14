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

#[derive(thiserror::Error, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "`Decode` is large because it structurally owns what funds it: the \
              `GatewayDelivery` the undecodable frame arrived in, and the \
              subscriber handle carrying the residual named for that frame. \
              Boxing the variant would put an allocation on the one path that \
              exists because something already went wrong, and nothing has \
              priced it; splitting the owners out would let a `serde_json::Error` \
              built from an admitted frame outlive the retention that paid for \
              the bytes it quotes. The size difference is the funding, so it \
              stays inline and is stated here rather than removed"
)]
pub enum ChannelError {
    #[error("network has been torn down")]
    NetworkDown,
    #[error("peer {0} not found in active set")]
    PeerNotFound(String),
    /// An outbound body could not be turned into JSON.
    ///
    /// Outbound only. Nothing has been admitted at this point and there is no
    /// delivery to account against, which is why this one can carry a bare
    /// error where [`Self::Decode`] cannot.
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("decode: {0}")]
    Decode(ChannelDecodeError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("application gateway lagged by {0} accepted messages")]
    Lagged(u64),
    #[error("application gateway resource pressure: {0:?}")]
    ResourcePressure(crate::resource::ResourceUnavailable),
    #[error("application command admission: {0}")]
    Admission(String),
}

/// A delivered frame that would not decode into `T`, holding the funding for
/// the bytes that describe why.
///
/// The error is not bare. `serde_json::Error` carries an owned message built
/// from the frame this failed on, so handing it back on its own would be the
/// same escape [`ChannelMessage`] closes for a successful decode: the
/// application keeps the error, drops the [`ChannelSubscription`], and an
/// allocation derived from an admitted frame outlives everything that paid for
/// it. It keeps the same two owners a decoded message keeps, and exposes the
/// error only by reference.
pub struct ChannelDecodeError {
    error: serde_json::Error,
    _delivery: crate::application_gateway::GatewayDelivery<
        crate::application_gateway::GatewayChannelFrame,
    >,
    _subscriber: crate::resource::FundedArc<crate::application_gateway::ChannelSubscriber>,
}

impl ChannelDecodeError {
    /// Why the frame would not decode.
    pub fn error(&self) -> &serde_json::Error {
        &self.error
    }
}

impl std::fmt::Display for ChannelDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::fmt::Debug for ChannelDecodeError {
    /// The error and nothing else — the two owners have nothing a reader wants
    /// and printing them would suggest they are inspectable.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ChannelDecodeError")
            .field(&self.error)
            .finish()
    }
}

impl std::error::Error for ChannelDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// One inbound message on a channel, paired with the peer that
/// sent it.
///
/// **Both fields are borrowed, never handed over.** They used to be `pub`, and
/// a public field is a way out: `std::mem::replace(&mut message.body, ..)`
/// takes the decoded value while leaving the funding behind in a husk the
/// application is free to drop, and no `Drop` impl can stop it — `Drop` runs
/// after the move, on whatever is left. [`Self::from`] and [`Self::body`]
/// borrow, so the value cannot outlive the two owners below.
///
/// Those owners are two because they pay for two different things. The
/// delivery pays for the frame this was decoded from; the subscriber handle
/// carries the residual named for the decoded graph itself, and holding it is
/// what stops dropping the [`ChannelSubscription`] from releasing that residual
/// while a `T` derived from it is still alive.
///
/// **The whole delivery is kept, not just its lease**, and that costs the raw
/// JSON body for as long as the message is held. It buys the thing the split
/// could not have: the retention funds a frame that is genuinely still there,
/// rather than being quietly re-pointed at a decoded value of a size this layer
/// never measured. `from` is read straight out of that frame, so it is not
/// copied either.
pub struct ChannelMessage<T> {
    body: T,
    delivery: crate::application_gateway::GatewayDelivery<
        crate::application_gateway::GatewayChannelFrame,
    >,
    _subscriber: crate::resource::FundedArc<crate::application_gateway::ChannelSubscriber>,
}

impl<T> ChannelMessage<T> {
    /// The peer that sent this.
    pub fn from(&self) -> &str {
        &self.delivery.value().from
    }

    /// The decoded body.
    pub fn body(&self) -> &T {
        &self.body
    }
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
    #[expect(
        clippy::result_large_err,
        reason = "one error type serves the whole channel surface, and its size \
                  comes entirely from `ChannelError::Decode`, which must keep \
                  owning the delivery and subscriber handle that fund the frame \
                  it describes. Boxing the `Err` here would charge an allocation \
                  to a path that never builds that variant and never allocates, \
                  and a second error type would let the funded one be converted \
                  away at the seam"
    )]
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
    subscriber: crate::resource::FundedArc<crate::application_gateway::ChannelSubscriber>,
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
        // Decoded from a borrow, so the delivery is never taken apart: `T` is
        // built *beside* the frame rather than out of it, and the whole
        // delivery — frame and the retention that funds it — then moves into
        // whichever value is handed back. Both outcomes carry the same two
        // owners, so neither a decoded body nor the error explaining why there
        // isn't one can outlive what paid for the bytes it came from.
        match T::deserialize(&delivery.value().payload) {
            Ok(body) => Some(Ok(ChannelMessage {
                body,
                delivery,
                _subscriber: crate::resource::FundedArc::clone(&self.subscriber),
            })),
            Err(error) => Some(Err(ChannelError::Decode(ChannelDecodeError {
                error,
                _delivery: delivery,
                _subscriber: crate::resource::FundedArc::clone(&self.subscriber),
            }))),
        }
    }
}
