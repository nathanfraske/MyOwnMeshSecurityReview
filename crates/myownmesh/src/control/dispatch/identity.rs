//! This device's identity, and the network ids it can mint or check.
//!
//! Nothing here touches a joined network. Identity is local state and the two
//! network-id operations are pure functions over text, which is why they sit
//! apart from the governance module that decides who is *in* a network.
//!
//! The network-id pair is the clearest case in the daemon of measuring before
//! producing: `prepare_*` walks the input and reports what the answer could
//! occupy, the typed retention and the exact line are admitted together, and
//! only then is the value committed. A refusal at any of those points releases
//! what the previous one took.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use super::{funded, Answer};
use crate::control::framing::{prepare_typed_and_line_building, AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    network_id_reply_line_ceiling, variable_operation_claim, FundedVariableReply,
    OperationReplyData, PreparedReply, PreparedText,
};
use crate::control::ControlState;

/// This device's identity as the control protocol reports it.
fn current(state: &Arc<ControlState>) -> OperationReplyData {
    OperationReplyData::Identity {
        device_id: state.mesh.identity().display_id(),
        pubkey: state.mesh.identity().public_id().to_owned(),
        label: state.mesh.identity().label().to_owned(),
    }
}

/// Fund the operation residual, then answer with whatever the identity is now.
fn answered(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    outcome: std::result::Result<(), String>,
) -> Result<Answer> {
    let lease = admission
        .acquire_claim(variable_operation_claim())
        .context("identity response was not admitted")?;
    let plan = FundedVariableReply::begin_operation(lease)
        .map_err(|_| anyhow!("identity operation lease did not match"))?;
    let variable = plan.finish(outcome.map(|()| current(state)));
    let output = AdmittedLineOut::prepare_capacity(variable.exact_line_len()?, admission)
        .context("identity response line was not admitted")?;
    Ok((PreparedReply::Variable(variable), output))
}

/// Report this device's id, public key and label.
pub(in crate::control) fn show(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    answered(state, admission, Ok(()))
}

/// Rename this device, persisting the label before the in-memory identity
/// takes it.
pub(in crate::control) fn set_label(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    label: String,
) -> Result<Answer> {
    let outcome = match myownmesh_core::identity::set_label(&label) {
        Err(error) => Err(error.to_string()),
        Ok(()) => {
            state.mesh.identity().set_label(&label);
            Ok(())
        }
    };
    answered(state, admission, outcome)
}

/// Mint a fresh network id.
pub(in crate::control) fn network_id_generate(admission: &FrameAdmission) -> Result<Answer> {
    let plan = match myownmesh_core::identity::prepare_generated_network_id() {
        Ok(plan) => plan,
        Err(error) => {
            let text = PreparedText::core_error(&error, admission)
                .context("network-id generation refusal text was not admitted")?;
            return funded(PreparedReply::Error(text), admission);
        }
    };
    let line_ceiling = network_id_reply_line_ceiling(plan.encoding_ceiling())?;
    let (committed, output) = prepare_typed_and_line_building(
        plan.typed_retention_claim(),
        line_ceiling,
        admission,
        |typed| plan.commit(typed),
    )
    .context("generated network id or response line was not admitted")?;
    match committed {
        Ok(network_id) => Ok((PreparedReply::NetworkId(network_id), output)),
        Err(error) => {
            drop(output);
            let text = PreparedText::core_error(&error, admission)
                .context("network-id generation refusal text was not admitted")?;
            funded(PreparedReply::Error(text), admission)
        }
    }
}

/// Check and canonicalise a network id the caller supplied.
pub(in crate::control) fn network_id_normalize(
    admission: &FrameAdmission,
    input: String,
) -> Result<Answer> {
    let plan = match myownmesh_core::identity::prepare_normalized_network_id(&input) {
        Ok(plan) => plan,
        Err(refusal) => {
            let text = PreparedText::network_id_error(&refusal, admission)
                .context("network-id validation refusal text was not admitted")?;
            return funded(PreparedReply::Error(text), admission);
        }
    };
    let line_ceiling = network_id_reply_line_ceiling(plan.encoding_ceiling())?;
    let (committed, output) = prepare_typed_and_line_building(
        plan.typed_retention_claim(),
        line_ceiling,
        admission,
        |typed| plan.commit(typed),
    )
    .context("normalized network id or response line was not admitted")?;
    let network_id = match committed {
        Ok(network_id) => network_id,
        Err(error) => {
            drop(output);
            let text = PreparedText::core_error(&error, admission)
                .context("network-id normalization refusal text was not admitted")?;
            return funded(PreparedReply::Error(text), admission);
        }
    };
    // The caller's text is held until here because the plan borrowed it; the
    // committed id is the only thing that outlives this point.
    drop(input);
    Ok((PreparedReply::NetworkId(network_id), output))
}
