//! The bounded command port consumed by the network driver.

use tokio::sync::oneshot;

use crate::config::TopologyMode;
use crate::error::Result;
use crate::events::DropReason;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::resource::{
    checked_measure_add, mailbox_measure_serialized, mailbox_retained_claim, strings_measure,
    ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceMailboxItem,
    ResourceMailboxItemError,
};

use super::peer_registry::PeerOwnerToken;

/// General engine command queue entry. Application requests and network
/// reconfiguration use this serialized path. Connector events remain on their
/// bounded per-worker runtime path and do not enter this enum.
pub enum NetworkCmd {
    ReplayCapabilities {
        owner: PeerOwnerToken,
    },
    SetTopology(TopologyMode),
    ApproveRoster {
        device_id: String,
        label: String,
        reply: oneshot::Sender<Result<()>>,
    },
    RemoveRoster {
        device_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    DropPeer {
        device_id: String,
        reason: DropReason,
    },
    DropPeerIfCurrent {
        owner: PeerOwnerToken,
        attempt: String,
        reason: DropReason,
    },
    AttemptRefused {
        owner: PeerOwnerToken,
        refusal: myownmesh_signaling::AttemptRefusal,
    },
    AttemptOutcome {
        owner: PeerOwnerToken,
        outcome: myownmesh_signaling::AttemptOutcome,
    },
    Reconnect {
        peer: Option<String>,
    },
    ConnectPeer {
        device_id: String,
        sticky: bool,
        reply: Option<super::state::ConnectWaiterRegistration>,
    },
    SendChannelReliable {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    SendChannelFrame {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    BroadcastChannelFrame {
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<usize>,
    },
    SendRpcRequest {
        peer: String,
        request: RpcRequestMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    FanoutCapabilities {
        caps: CapabilityAdvert,
    },
    ProposeTransition {
        variant: crate::network_state::TransitionVariant,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
}

impl ResourceMailboxItem for NetworkCmd {
    fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
        let measure = match self {
            Self::ReplayCapabilities { .. } => (0, 0, 0),
            Self::SetTopology(mode) => mailbox_measure_serialized(mode)?,
            Self::ApproveRoster {
                device_id, label, ..
            } => strings_measure([device_id.as_str(), label.as_str()])?,
            Self::RemoveRoster { device_id, .. } | Self::ConnectPeer { device_id, .. } => {
                strings_measure([device_id.as_str()])?
            }
            Self::DropPeer { device_id, reason } => {
                let reason = match reason {
                    DropReason::TransportError { message } => Some(message.as_str()),
                    DropReason::Denied
                    | DropReason::IceFailed
                    | DropReason::AuthFailed
                    | DropReason::UserLeft
                    | DropReason::TopologyPruned
                    | DropReason::HeartbeatTimeout => None,
                };
                strings_measure([Some(device_id.as_str()), reason].into_iter().flatten())?
            }
            Self::DropPeerIfCurrent {
                attempt, reason, ..
            } => {
                let reason = match reason {
                    DropReason::TransportError { message } => Some(message.as_str()),
                    DropReason::Denied
                    | DropReason::IceFailed
                    | DropReason::AuthFailed
                    | DropReason::UserLeft
                    | DropReason::TopologyPruned
                    | DropReason::HeartbeatTimeout => None,
                };
                strings_measure([Some(attempt.as_str()), reason].into_iter().flatten())?
            }
            Self::AttemptRefused { refusal, .. } => {
                let reason = match &refusal.refusal {
                    myownmesh_signaling::NegotiationRefusal::DuplicateLiveEvent => None,
                    myownmesh_signaling::NegotiationRefusal::Provider(reason) => {
                        Some(reason.as_str())
                    }
                };
                strings_measure(
                    [
                        Some(refusal.attempt.as_str()),
                        Some(refusal.event_id.as_str()),
                        reason,
                    ]
                    .into_iter()
                    .flatten(),
                )?
            }
            Self::AttemptOutcome { outcome, .. } => {
                let reason = match &outcome.kind {
                    myownmesh_signaling::AttemptOutcomeKind::TypedRefused(reason) => {
                        Some(reason.as_str())
                    }
                    _ => None,
                };
                strings_measure(
                    [
                        Some(outcome.attempt.as_str()),
                        Some(outcome.event_id.as_str()),
                        reason,
                    ]
                    .into_iter()
                    .flatten(),
                )?
            }
            Self::Reconnect { peer } => strings_measure(peer.iter().map(String::as_str))?,
            Self::SendChannelReliable {
                peer,
                channel,
                payload,
                ..
            }
            | Self::SendChannelFrame {
                peer,
                channel,
                payload,
                ..
            } => checked_measure_add(
                strings_measure([peer.as_str(), channel.as_str()])?,
                mailbox_measure_serialized(payload)?,
            )?,
            Self::BroadcastChannelFrame {
                channel, payload, ..
            } => checked_measure_add(
                strings_measure([channel.as_str()])?,
                mailbox_measure_serialized(payload)?,
            )?,
            Self::SendRpcRequest { peer, request, .. } => checked_measure_add(
                strings_measure([peer.as_str()])?,
                mailbox_measure_serialized(request)?,
            )?,
            Self::FanoutCapabilities { caps } => mailbox_measure_serialized(caps)?,
            Self::ProposeTransition {
                variant, mfa_code, ..
            } => checked_measure_add(
                mailbox_measure_serialized(variant)?,
                strings_measure(mfa_code.iter().map(String::as_str))?,
            )?,
        };
        let effect_allocations = match self {
            Self::ReplayCapabilities { .. } | Self::FanoutCapabilities { .. } => 0,
            Self::SetTopology(_)
            | Self::DropPeer { .. }
            | Self::DropPeerIfCurrent { .. }
            | Self::Reconnect { .. } => 0,
            Self::AttemptRefused { .. } | Self::AttemptOutcome { .. } => 1,
            Self::ConnectPeer { reply, .. } => usize::from(reply.is_some()) * 2,
            Self::ApproveRoster { .. }
            | Self::RemoveRoster { .. }
            | Self::SendChannelReliable { .. }
            | Self::SendChannelFrame { .. }
            | Self::BroadcastChannelFrame { .. }
            | Self::SendRpcRequest { .. }
            | Self::ProposeTransition { .. } => 1,
        };
        let allocations = measure.2.checked_add(effect_allocations).ok_or(
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            },
        )?;
        mailbox_retained_claim::<Self>(measure.0, measure.1, allocations)
    }
}
