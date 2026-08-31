//! The bounded command port consumed by the network driver.

use tokio::sync::oneshot;

use crate::config::TopologyMode;
use crate::error::Result;
use crate::events::DropReason;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::resource::{
    checked_measure_add, mailbox_measure_serialized, strings_measure, MailboxMeasurement,
    ResourceClaimArithmeticError, ResourceClass, ResourceMailboxItem, ResourceMailboxItemError,
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
    ProposeRoleGrant {
        target: String,
        role: crate::semantic::Role,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
    ProposeRoleRevoke {
        target: String,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
    ProposeEvict {
        target: String,
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
}

unsafe impl ResourceMailboxItem for NetworkCmd {
    fn measured_claim(
        &self,
    ) -> std::result::Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
        let measure = match self {
            Self::ReplayCapabilities { .. } => (0, 0, 0),
            Self::SetTopology(mode) => mailbox_measure_serialized(mode)?,
            Self::ConnectPeer { device_id, .. } => strings_measure([device_id.as_str()])?,
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
            Self::ProposeRoleGrant {
                target, mfa_code, ..
            }
            | Self::ProposeRoleRevoke {
                target, mfa_code, ..
            }
            | Self::ProposeEvict {
                target, mfa_code, ..
            } => strings_measure(
                [Some(target.as_str()), mfa_code.as_deref()]
                    .into_iter()
                    .flatten(),
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
            Self::SendChannelReliable { .. }
            | Self::SendChannelFrame { .. }
            | Self::BroadcastChannelFrame { .. }
            | Self::SendRpcRequest { .. }
            | Self::ProposeRoleGrant { .. }
            | Self::ProposeRoleRevoke { .. }
            | Self::ProposeEvict { .. } => 1,
        };
        let allocations = measure.2.checked_add(effect_allocations).ok_or(
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            },
        )?;
        MailboxMeasurement::from_parts(measure.0, measure.1, allocations)
    }
}
