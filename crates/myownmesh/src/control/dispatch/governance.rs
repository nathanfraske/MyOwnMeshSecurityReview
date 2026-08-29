//! Roster and governance: the two snapshots, the five signed-transition
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
use crate::control::handoff::ProvisionalHandoff;
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

/// Set the local topology directly.
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
            Some(net) => net
                .set_topology(mode)
                .await
                .map(|_| OperationReplyData::Topology(topology))
                .map_err(|error| error.to_string()),
        },
    };
    answered(result, owner, admission)
}

/// Propose granting a role to a device.
pub(in crate::control) async fn propose_role_grant(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    role: myownmesh_core::network_state::Role,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .propose_role_grant(&target, role, mfa_code)
            .await
            .map(|id| OperationReplyData::ProposalId(id.to_string()))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Propose revoking a device's role.
pub(in crate::control) async fn propose_role_revoke(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .propose_role_revoke(&target, mfa_code)
            .await
            .map(|id| OperationReplyData::ProposalId(id.to_string()))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Propose evicting a device from the network.
pub(in crate::control) async fn propose_evict(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => net
            .propose_evict(&target, mfa_code)
            .await
            .map(|id| OperationReplyData::ProposalId(id.to_string()))
            .map_err(|error| error.to_string()),
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Prepare this device's local MFA custody transaction for one network.
///
/// The lock is installed before this answers, so a success response names an
/// enrollment that already exists: an install this device could not perform is
/// an error response rather than a promise, and a second client enrolling the
/// same network at the same moment is refused by the lock the first one
/// installed rather than by a check neither of them can see.
///
/// The secret and recovery codes are returned from the exact Prepared record.
/// That record remains queryable and redeliverable until the exact transaction
/// commit or abort command settles it; neither response delivery nor a socket
/// write is a durable custody decision. See [`ProvisionalHandoff`].
pub(in crate::control) fn mfa_prepare(
    admission: &FrameAdmission,
    network: String,
) -> Result<(Answer, ProvisionalHandoff)> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA enrollment operation was not admitted")?;
    let (result, transaction_id, provisional) =
        match myownmesh_core::custody::prepare_or_recover_provisional_enroll(&network, &network) {
            Ok(myownmesh_core::custody::EnrollmentPreparation::Fresh(installed)) => (
                Ok(installed.enrolled().clone()),
                Some(installed.transaction_id().to_owned()),
                ProvisionalHandoff::MfaEnrollment(installed),
            ),
            Ok(myownmesh_core::custody::EnrollmentPreparation::Existing(prepared)) => (
                Ok(prepared.enrolled().clone()),
                Some(prepared.transaction_id().to_owned()),
                ProvisionalHandoff::MfaRecovered(prepared),
            ),
            Err(error) => (Err(error), None, ProvisionalHandoff::None),
        };
    let answer = funded(
        PreparedReply::Variable(FundedVariableReply::mfa_enrollment(
            result,
            transaction_id,
            owner,
        )),
        admission,
    )
    .context("MFA enrollment response line was not admitted")?;
    Ok((answer, provisional))
}

/// Legacy enrollment remains a strict fresh-install operation. The explicit
/// Prepare command is the recovery-aware path; keeping this arm strict
/// preserves callers that use Enroll as a refusal-on-existing probe.
pub(in crate::control) fn mfa_enroll(
    admission: &FrameAdmission,
    network: String,
) -> Result<(Answer, ProvisionalHandoff)> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA enrollment operation was not admitted")?;
    let (result, transaction_id, provisional) =
        match myownmesh_core::custody::install_provisional_enroll(&network, &network) {
            Ok(installed) => (
                Ok(installed.enrolled().clone()),
                Some(installed.transaction_id().to_owned()),
                ProvisionalHandoff::MfaEnrollment(installed),
            ),
            Err(error) => (Err(error), None, ProvisionalHandoff::None),
        };
    let answer = funded(
        PreparedReply::Variable(FundedVariableReply::mfa_enrollment(
            result,
            transaction_id,
            owner,
        )),
        admission,
    )
    .context("MFA enrollment response line was not admitted")?;
    Ok((answer, provisional))
}

/// Query one exact transaction. A prepared record is deliberately not
/// consumed here; only the explicit redelivery/commit/abort commands consume
/// a recovered material handle.
pub(in crate::control) fn mfa_query(
    admission: &FrameAdmission,
    network: String,
    transaction_id: String,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA transaction query was not admitted")?;
    let (state, material) =
        match myownmesh_core::custody::enrollment_transaction(&network, &transaction_id) {
            Ok(myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared)) => {
                ("prepared", Some(prepared.enrolled().clone()))
            }
            Ok(myownmesh_core::custody::EnrollmentTransaction::Committed) => ("committed", None),
            Ok(myownmesh_core::custody::EnrollmentTransaction::Absent) => ("absent", None),
            Err(error) => return refused_text(error.to_string(), admission),
        };
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_transaction(
            network,
            transaction_id,
            state,
            material,
            owner,
        )),
        admission,
    )
}

/// Re-deliver only the exact prepared transaction named by the request.
pub(in crate::control) fn mfa_redeliver(
    admission: &FrameAdmission,
    network: String,
    transaction_id: String,
) -> Result<(Answer, ProvisionalHandoff)> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA transaction redelivery was not admitted")?;
    let prepared = match myownmesh_core::custody::enrollment_transaction(&network, &transaction_id)
    {
        Ok(myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared)) => prepared,
        Ok(myownmesh_core::custody::EnrollmentTransaction::Committed) => {
            return Ok((
                refused_text("MFA transaction is already committed".into(), admission)?,
                ProvisionalHandoff::None,
            ));
        }
        Ok(myownmesh_core::custody::EnrollmentTransaction::Absent) => {
            return Ok((
                refused_text("MFA transaction is absent".into(), admission)?,
                ProvisionalHandoff::None,
            ));
        }
        Err(error) => {
            return Ok((
                refused_text(error.to_string(), admission)?,
                ProvisionalHandoff::None,
            ));
        }
    };
    let result = Ok(prepared.enrolled().clone());
    let answer = funded(
        PreparedReply::Variable(FundedVariableReply::mfa_enrollment(
            result,
            Some(transaction_id),
            owner,
        )),
        admission,
    )?;
    Ok((answer, ProvisionalHandoff::MfaRecovered(prepared)))
}

/// Apply one exact idempotent terminal operation and report the resulting
/// durable state. A stale transaction ID never reaches a successor.
pub(in crate::control) fn mfa_commit_or_abort(
    admission: &FrameAdmission,
    network: String,
    transaction_id: String,
    commit: bool,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA transaction settlement was not admitted")?;
    let settlement =
        match myownmesh_core::custody::enrollment_transaction(&network, &transaction_id) {
            Ok(myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared)) => prepared
                .settle(if commit {
                    myownmesh_core::custody::EnrollmentSettlementRequest::Commit
                } else {
                    myownmesh_core::custody::EnrollmentSettlementRequest::Abort
                })
                .map(|result| match result {
                    myownmesh_core::custody::EnrollmentSettlementResult::Committed => "committed",
                    myownmesh_core::custody::EnrollmentSettlementResult::Absent => "absent",
                }),
            Ok(myownmesh_core::custody::EnrollmentTransaction::Committed) => Ok("committed"),
            Ok(myownmesh_core::custody::EnrollmentTransaction::Absent) => Ok("absent"),
            Err(error) => Err(error),
        };
    let state = match settlement {
        Ok(state) => state,
        Err(error) => return refused_text(error.to_string(), admission),
    };
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_transaction(
            network,
            transaction_id,
            state,
            None,
            owner,
        )),
        admission,
    )
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
