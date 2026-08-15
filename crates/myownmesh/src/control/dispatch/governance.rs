//! Roster and governance: the two snapshots, the twelve signed-transition
//! operations, and local MFA custody.
//!
//! Two things distinguish this domain from the rest, and both are about
//! admitting work before doing it.
//!
//! The snapshots hold a lock over state whose size is not known until it is
//! walked. Both take the response owner *before* the first traversal, so the
//! walk that decides how big the answer is, is itself work the connection was
//! admitted to do. The encoded line is measured after, over the sealed reply.
//!
//! The twelve operations answer with something whose size depends on a remote
//! result — an error string, a proposal id — so each takes the right to answer
//! before the operation runs. `operation_owner` and `answered` are that pair,
//! written once here rather than twelve times.
//!
//! Every operation is its own function, called from its own arm, so a missing
//! transition is a missing arm in the connection loop's total match rather than
//! a runtime fall-through.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{funded, refused_text, unknown_network, Answer};
use crate::control::framing::FrameAdmission;
use crate::control::reply::{
    FundedDiagnostic, FundedVariableReply, GovernanceDiagnostic, OperationReplyData, PreparedReply,
    ResponseOwner,
};
use crate::control::ControlState;

/// What an operation says when the network is not joined.
///
/// Deliberately the operation reply's own error string rather than the shared
/// [`unknown_network`] refusal: these answer inside a result the caller is
/// already parsing as an operation outcome.
fn no_such_network(network: &str) -> String {
    format!("unknown network: {network}")
}

/// Take the right to answer, before the operation that will be answered.
fn operation_owner(admission: &FrameAdmission) -> Result<ResponseOwner> {
    ResponseOwner::acquire(admission)
        .context("governance/network operation result was not admitted")
}

/// Seal a finished operation result into the reply its owner funds, and fund
/// the line that reply encodes into.
fn answered(
    result: std::result::Result<OperationReplyData, String>,
    owner: ResponseOwner,
    admission: &FrameAdmission,
) -> Result<Answer> {
    funded(PreparedReply::Variable(owner.finish(result)), admission)
        .context("governance/network response line was not admitted")
}

/// The authorized-device roster, measured before it is walked.
pub(in crate::control) async fn roster_list(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("RosterList diagnostic snapshot was not admitted")?;
    funded(
        PreparedReply::Roster(FundedDiagnostic::new(joined.roster_list().await?, owner)),
        admission,
    )
    .context("RosterList response line was not admitted")
}

/// Governance state — proposals, roles, topology — measured before it is walked.
pub(in crate::control) async fn governance_state(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("GovernanceState diagnostic snapshot was not admitted")?;
    let state = joined.governance_state().await?;
    let evicted = myownmesh_core::network_state::member_log_removed(
        &state,
        &state.member_log,
        &state.network_id,
    )
    .into_iter()
    .collect();
    funded(
        PreparedReply::Governance(FundedDiagnostic::new(
            GovernanceDiagnostic { state, evicted },
            owner,
        )),
        admission,
    )
    .context("GovernanceState response line was not admitted")
}

/// Admit a device onto the roster.
pub(in crate::control) async fn roster_approve(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    device_id: String,
    label: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .roster_approve(&device_id, label.as_deref().unwrap_or(""))
            .await
            .map(|_| OperationReplyData::Approved(device_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Drop a device from the roster.
pub(in crate::control) async fn roster_remove(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    device_id: String,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .roster_remove(&device_id)
            .await
            .map(|_| OperationReplyData::Removed(device_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Set the topology directly, which a governed network refuses.
pub(in crate::control) async fn topology_set(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    topology: String,
    hub: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match super::network::parse_topology(&topology, hub.as_deref()) {
        Err(error) => Err(error),
        Ok(mode) => match state.registry.get(&network) {
            None => Err(no_such_network(&network)),
            Some(net) => {
                if net
                    .governance_state()
                    .await
                    .is_ok_and(|governance| governance.topology.is_some())
                {
                    Err("this network's topology is governed by a signed owner transition — propose a change instead (`networks topology-propose` / GovernanceProposeTopology)".to_owned())
                } else {
                    net.set_topology(mode)
                        .await
                        .map(|_| OperationReplyData::Topology(topology))
                        .map_err(|error| error.to_string())
                }
            }
        },
    };
    answered(result, owner, admission)
}

/// Propose one signed transition, whatever its variant.
///
/// The five `propose_*` operations differ only in the variant they build, so
/// they build it in their own arm's function and submit it through here.
async fn propose(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    variant: myownmesh_core::TransitionVariant,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .propose_transition(variant, mfa_code)
            .await
            .map(OperationReplyData::ProposalId)
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Propose a change to what kind of network this is.
pub(in crate::control) async fn propose_kind_change(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    to: myownmesh_core::NetworkKind,
    mfa_code: Option<String>,
) -> Result<Answer> {
    propose(
        state,
        admission,
        network,
        myownmesh_core::TransitionVariant::KindChange { to },
        mfa_code,
    )
    .await
}

/// Propose granting a role to a device.
pub(in crate::control) async fn propose_role_grant(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    role: myownmesh_core::Role,
    mfa_code: Option<String>,
) -> Result<Answer> {
    propose(
        state,
        admission,
        network,
        myownmesh_core::TransitionVariant::RoleGrant { target, role },
        mfa_code,
    )
    .await
}

/// Propose revoking a device's role.
pub(in crate::control) async fn propose_role_revoke(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    propose(
        state,
        admission,
        network,
        myownmesh_core::TransitionVariant::RoleRevoke { target },
        mfa_code,
    )
    .await
}

/// Propose evicting a device from the network.
pub(in crate::control) async fn propose_evict(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    propose(
        state,
        admission,
        network,
        myownmesh_core::TransitionVariant::Evict { target },
        mfa_code,
    )
    .await
}

/// Propose a governed topology change.
///
/// The only proposal that can be refused before it is submitted: an
/// unparseable topology never reaches the network.
pub(in crate::control) async fn propose_topology(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    topology: String,
    hub: Option<String>,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let mode = match super::network::parse_topology(&topology, hub.as_deref()) {
        Ok(mode) => mode,
        Err(error) => {
            let owner = operation_owner(admission)?;
            return answered(Err(error), owner, admission);
        }
    };
    propose(
        state,
        admission,
        network,
        myownmesh_core::TransitionVariant::TopologyChange { to: mode },
        mfa_code,
    )
    .await
}

/// Add this device's signature to a proposal.
pub(in crate::control) async fn sign(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .sign_proposal(&proposal_id, mfa_code)
            .await
            .map(|_| OperationReplyData::Signed(proposal_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Record this device's objection to a proposal.
pub(in crate::control) async fn deny(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .deny_proposal(&proposal_id)
            .await
            .map(|_| OperationReplyData::Denied(proposal_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Withdraw a proposal this device raised.
pub(in crate::control) async fn withdraw(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .withdraw_proposal(&proposal_id)
            .await
            .map(|_| OperationReplyData::Withdrawn(proposal_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Carry out an approved split, answering with the new network's id.
pub(in crate::control) async fn spawn_split(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .spawn_split(&proposal_id)
            .await
            .map(OperationReplyData::NewNetworkId)
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Enrol this device in local MFA custody for one network.
pub(in crate::control) fn mfa_enroll(
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA enrollment operation was not admitted")?;
    let result = myownmesh_core::custody::enroll(&network, &network);
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_enrollment(result, owner)),
        admission,
    )
    .context("MFA enrollment response line was not admitted")
}

/// Whether this device holds MFA custody for one network.
pub(in crate::control) fn mfa_status(
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    funded(
        PreparedReply::Bool {
            key: "enrolled",
            value: myownmesh_core::custody::is_enrolled(&network),
        },
        admission,
    )
}

/// Surrender MFA custody, which requires presenting a current code.
pub(in crate::control) fn mfa_disable(
    admission: &FrameAdmission,
    network: String,
    code: String,
) -> Result<Answer> {
    match myownmesh_core::custody::disable(&network, &code) {
        Ok(()) => funded(
            PreparedReply::Bool {
                key: "disabled",
                value: true,
            },
            admission,
        ),
        Err(error) => refused_text(error.to_string(), admission),
    }
}
