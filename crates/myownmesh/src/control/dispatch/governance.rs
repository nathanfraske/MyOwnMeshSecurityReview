//! Roster and governance: the two snapshots, the twelve signed-transition
//! operations, and local MFA custody.
//!
//! Two things distinguish this domain from the rest, and both are about
//! admitting work before doing it.
//!
//! The snapshots hold a lock over state whose size is not known until it is
//! walked. Both take a planning lease *before* the first traversal, so the
//! walk that decides how big the answer is, is itself work the connection was
//! admitted to do. The typed retention and the line ceiling follow, and only
//! then is the snapshot committed.
//!
//! The twelve operations answer with something whose size depends on a remote
//! result — an error string, a proposal id — so each admits the residual that
//! result will occupy before the operation runs. `operation_lease` and
//! `answered` are that pair, written once here rather than twelve times.
//!
//! Every operation is its own function, called from its own arm. They used to
//! share one arm that bound a whole `Request` and re-matched it, which needed
//! a `_ => unreachable!()` at the bottom: adding a thirteenth transition would
//! have compiled straight into that panic. Now it is a missing arm in the
//! connection loop's total match, which is a build failure.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use super::{funded, unknown_network, Answer};
use crate::control::framing::{AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    variable_data_reply_line_ceiling, variable_operation_claim, FundedVariableReply,
    OperationReplyData, PreparedReply, PreparedText, VariableReplySource,
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

/// Admit the residual an operation's result will occupy, before it runs.
fn operation_lease(admission: &FrameAdmission) -> Result<myownmesh_core::ResourceLease> {
    admission
        .acquire_claim(variable_operation_claim())
        .context("governance/network operation result was not admitted")
}

/// Bind a finished operation result to the lease admitted for it, and fund the
/// line the pair encodes into.
fn answered(
    result: std::result::Result<OperationReplyData, String>,
    operation: myownmesh_core::ResourceLease,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let variable = FundedVariableReply::operation(result, operation)
        .map_err(|_| anyhow!("governance/network operation lease did not match"))?;
    let output = AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, admission)
        .context("governance/network response line was not admitted")?;
    Ok((PreparedReply::Variable(variable), output))
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
    let planning = admission
        .acquire_claim(myownmesh_core::snapshot_planning_claim())
        .context("RosterList planning work was not admitted")?;
    let source = VariableReplySource::roster(
        joined
            .prepare_roster_snapshot(planning)
            .context("RosterList snapshot was not representable")?,
    );
    let typed = admission
        .acquire_claim(source.typed_claim())
        .context("RosterList typed snapshot was not admitted")?;
    let line_ceiling = variable_data_reply_line_ceiling(source.data_ceiling()?)?;
    let output = AdmittedLineOut::prepare_capacity(line_ceiling, admission)
        .context("RosterList response line was not admitted")?;
    let roster = source.commit(typed).await?;
    Ok((PreparedReply::Variable(roster), output))
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
    let planning = admission
        .acquire_claim(myownmesh_core::snapshot_planning_claim())
        .context("GovernanceState planning work was not admitted")?;
    let source = VariableReplySource::governance(
        joined
            .prepare_governance_snapshot(planning)
            .await
            .context("GovernanceState capacity could not be measured")?,
    );
    let typed = admission
        .acquire_claim(source.typed_claim())
        .context("GovernanceState typed snapshot was not admitted")?;
    let line_ceiling = variable_data_reply_line_ceiling(source.data_ceiling()?)?;
    let output = AdmittedLineOut::prepare_capacity(line_ceiling, admission)
        .context("GovernanceState response line was not admitted")?;
    let governance = source.commit(typed).await?;
    Ok((PreparedReply::Variable(governance), output))
}

/// Admit a device onto the roster.
pub(in crate::control) async fn roster_approve(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    device_id: String,
    label: Option<String>,
) -> Result<Answer> {
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .roster_approve(&device_id, label.as_deref().unwrap_or(""))
            .await
            .map(|_| OperationReplyData::Approved(device_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
}

/// Drop a device from the roster.
pub(in crate::control) async fn roster_remove(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    device_id: String,
) -> Result<Answer> {
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .roster_remove(&device_id)
            .await
            .map(|_| OperationReplyData::Removed(device_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
}

/// Set the topology directly, which a governed network refuses.
pub(in crate::control) async fn topology_set(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    topology: String,
    hub: Option<String>,
) -> Result<Answer> {
    let operation = operation_lease(admission)?;
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
    answered(result, operation, admission)
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
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .propose_transition(variant, mfa_code)
            .await
            .map(OperationReplyData::ProposalId)
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
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
            let operation = operation_lease(admission)?;
            return answered(Err(error), operation, admission);
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
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .sign_proposal(&proposal_id, mfa_code)
            .await
            .map(|_| OperationReplyData::Signed(proposal_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
}

/// Record this device's objection to a proposal.
pub(in crate::control) async fn deny(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
) -> Result<Answer> {
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .deny_proposal(&proposal_id)
            .await
            .map(|_| OperationReplyData::Denied(proposal_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
}

/// Withdraw a proposal this device raised.
pub(in crate::control) async fn withdraw(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
) -> Result<Answer> {
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .withdraw_proposal(&proposal_id)
            .await
            .map(|_| OperationReplyData::Withdrawn(proposal_id))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
}

/// Carry out an approved split, answering with the new network's id.
pub(in crate::control) async fn spawn_split(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    proposal_id: String,
) -> Result<Answer> {
    let operation = operation_lease(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .spawn_split(&proposal_id)
            .await
            .map(OperationReplyData::NewNetworkId)
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, operation, admission)
}

/// Enrol this device in local MFA custody for one network.
pub(in crate::control) fn mfa_enroll(
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let operation = admission
        .acquire_claim(variable_operation_claim())
        .context("MFA enrollment operation was not admitted")?;
    let result = myownmesh_core::custody::enroll(&network, &network);
    let variable = FundedVariableReply::mfa_enrollment(result, operation)
        .map_err(|_| anyhow!("MFA operation lease did not match"))?;
    let output = AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, admission)
        .context("MFA enrollment response line was not admitted")?;
    Ok((PreparedReply::Variable(variable), output))
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
        Err(error) => {
            let text = PreparedText::core_error(&error, admission)
                .context("MFA refusal text was not admitted")?;
            funded(PreparedReply::Error(text), admission)
        }
    }
}
