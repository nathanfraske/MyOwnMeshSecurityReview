//! Local RPC operations: handler registration, in-flight resolution, and the
//! outbound call.
//!
//! Four of these carry a `client_id` and the capability that proves it, and
//! every one of those checks it first — before a network lookup, before a
//! reply is measured, before anything is claimed. Registration is the reason
//! this matters most: a method claim is process-wide state, so an
//! unauthenticated caller must not be able to reach the point where one is
//! taken and then released.
//!
//! Like every operation module here, nothing writes. Each function answers
//! with an [`Answer`]: the reply, and the line capacity it was admitted under.
//! The connection loop encodes and writes.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{funded, refused, refused_text, unknown_network, Answer};
use crate::control::framing::{AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    prepare_reply_then, ControlOut, FundedVariableReply, PreparedReply, ResponseOwner,
};
use crate::control::{ConnectionCancel, ControlState};

/// The refusal shared by every client-scoped operation here.
const BAD_CLIENT: &str = "invalid local client authority";

/// Register a local handler for one method on one network.
///
/// The order is the whole operation: the response line is funded, then a
/// generation is taken, then the core-side handler is prepared, and only then
/// is the method claimed. Each step that fails releases the funding it has not
/// used before building its refusal, so a refused registration leaves the
/// connection holding exactly what it held before.
pub(in crate::control) async fn register(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    method: String,
    streaming: bool,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let success = PreparedReply::Bool {
        key: "registered",
        value: true,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&success), admission)
        .context("RPC-register response capacity was not admitted")?;
    let mode = if streaming {
        crate::ipc::clients::HandlerMode::Stream
    } else {
        crate::ipc::clients::HandlerMode::Single
    };
    let key = (network, method);
    let generation = state.clients.next_handler_generation();
    let prepared = match crate::ipc::bridge::prepare_handler_for_mode(
        &net.rpc(),
        &key,
        generation,
        mode,
        &state.clients,
    ) {
        Ok(prepared) => prepared,
        Err(refusal) => {
            drop(output);
            return refused_text(format!("rpc register refused: {refusal}"), admission);
        }
    };
    let previous = match state
        .clients
        .claim_method_committing_with_key(key, client_id, mode, generation, prepared)
    {
        Ok(previous) => previous,
        Err(refusal) => {
            drop(output);
            return refused_text(format!("rpc register refused: {refusal}"), admission);
        }
    };
    if let Some((previous, key)) = previous {
        crate::ipc::bridge::notify_displaced(&state.clients, previous, client_id, key.0, key.1);
    }
    Ok((success, output))
}

/// Release a method claim this client holds.
pub(in crate::control) async fn unregister(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    method: String,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    // Funded against the widest boolean the line can carry, so the real answer
    // encodes into capacity taken before the release happened.
    let ceiling = PreparedReply::Bool {
        key: "released",
        value: false,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&ceiling), admission)
        .context("RpcUnregister response capacity was not admitted")?;
    let key = (network, method);
    let release = state.clients.release_method(&key, client_id);
    let released = release.released;
    // Releasing the core registration is the local commit. Output capacity is
    // already held, and cancellation only races the later write.
    drop(release);
    Ok((
        PreparedReply::Bool {
            key: "released",
            value: released,
        },
        output,
    ))
}

/// Build the identity of one in-flight inbound request.
fn pending_key(
    network: String,
    method: String,
    peer: String,
    request_id: String,
    class: crate::ipc::clients::HandlerMode,
) -> crate::ipc::clients::PendingKey {
    crate::ipc::clients::PendingKey {
        network,
        method,
        remote_peer: peer,
        remote_request_id: request_id,
        class,
    }
}

/// Resolve one in-flight single-response request.
#[allow(clippy::too_many_arguments)]
pub(in crate::control) async fn respond(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    peer: String,
    method: String,
    request_id: String,
    operation_id: u64,
    ok: Option<serde_json::Value>,
    error: Option<String>,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let success = PreparedReply::Bool {
        key: "resolved",
        value: true,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Single,
    );
    let result = error.map_or_else(|| Ok(ok.unwrap_or(serde_json::Value::Null)), Err);
    let (resolved, output) = prepare_reply_then(&success, admission, || {
        state
            .clients
            .resolve_exact_single(&key, client_id, operation_id, result)
    })
    .context("RPC-resolve response capacity was not admitted")?;
    if resolved {
        return Ok((success, output));
    }
    drop(output);
    refused_text(
        format!("no in-flight inbound RPC for '{}'", key.remote_request_id),
        admission,
    )
}

/// Push one chunk onto an in-flight streaming response.
#[allow(clippy::too_many_arguments)]
pub(in crate::control) async fn stream_chunk(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    peer: String,
    method: String,
    request_id: String,
    operation_id: u64,
    payload: serde_json::Value,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let success = PreparedReply::Bool {
        key: "delivered",
        value: true,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Stream,
    );
    let (accepted, output) = prepare_reply_then(&success, admission, || {
        state
            .clients
            .push_exact_stream(&key, client_id, operation_id, payload)
    })
    .context("stream-chunk response capacity was not admitted")?;
    if accepted {
        return Ok((success, output));
    }
    drop(output);
    refused_text(
        format!(
            "no in-flight inbound stream for '{}'",
            key.remote_request_id
        ),
        admission,
    )
}

/// Close an in-flight streaming response, cleanly or with an error.
///
/// Unlike the chunk push, "there was no such stream" is not a refusal here: a
/// close that finds nothing to close answers `closed: false`. The line is
/// funded against the widest boolean before the close is attempted, so both
/// answers encode into the same admitted capacity.
#[allow(clippy::too_many_arguments)]
pub(in crate::control) async fn stream_end(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    peer: String,
    method: String,
    request_id: String,
    operation_id: u64,
    error: Option<String>,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let ceiling = PreparedReply::Bool {
        key: "closed",
        value: false,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Stream,
    );
    let (closed, output) = prepare_reply_then(&ceiling, admission, || {
        state
            .clients
            .close_exact_stream(&key, client_id, operation_id, error)
    })
    .context("stream-close response capacity was not admitted")?;
    Ok((
        PreparedReply::Bool {
            key: "closed",
            value: closed,
        },
        output,
    ))
}

/// Call a method on a remote peer and answer with whatever came back.
///
/// This is the one operation here that can end the connection rather than
/// answer it, and the `Option` says so in the type: a call cancelled by the
/// connection draining has no reply, because the daemon never learned what the
/// answer would have been. Every other outcome — including a remote error — is
/// a reply. Returning `Answer` and inventing a refusal for the cancelled case
/// would claim a result that was never obtained.
pub(in crate::control) async fn call(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    cancel: &ConnectionCancel,
    network: String,
    peer: String,
    method: String,
    payload: serde_json::Value,
) -> Result<Option<Answer>> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission).map(Some);
    };
    // The result's size is not known until it arrives, so the right to answer is
    // taken before the call is made rather than after it returns.
    let owner =
        ResponseOwner::acquire(admission).context("RpcCall result operation was not admitted")?;
    let rpc = joined.rpc();
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(None),
        result = rpc.call_funded(&peer, &method, payload) => result,
    };
    funded(
        PreparedReply::Variable(FundedVariableReply::rpc_call(result, owner)),
        admission,
    )
    .context("RpcCall response line was not admitted")
    .map(Some)
}
