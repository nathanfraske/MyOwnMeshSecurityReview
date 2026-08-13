//! Wire frames the daemon writes to a duplex (post-
//! `EventsSubscribe`) client connection. Every line is exactly
//! one of these variants, tagged via the `kind` field so a
//! client can dispatch on it without trying to guess from
//! shape.
//!
//! Backward compat: `Event` / `Lagged` were the only `kind`s
//! the original event stream emitted, and new variants land
//! additively without breaking the existing MyOwnMesh GUI
//! client. That tolerance is real, but it is not where this
//! comment used to say it was — there is no `kind` match in
//! `gui/src-tauri/src/main.rs::run_event_pump` to have a
//! default arm. That pump never inspects a frame at all: it
//! relays each line to the frontend verbatim as a
//! `mesh://event`. The dispatch lives one layer further out,
//! in `gui/src/mesh-client.svelte.ts`, which branches on the
//! `kind` it recognises and renders anything else generically.
//! A client that must act on a new variant still has to learn
//! it; what is guaranteed is that not knowing one is not an
//! error.

use serde::Serialize;
use serde_json::Value;

use myownmesh_core::events::MeshEvent;
use myownmesh_core::{ResourceClaim, ResourceMailboxItemError};

/// Server → client wire frame on a duplex event socket.
///
/// Pre-`EventsSubscribe`, the daemon emits the untagged
/// [`crate::control::Response`] shape so the one-shot
/// request/response clients keep working. Untagged rather than
/// legacy: it carries no `kind` because it does not need one —
/// a response is the answer to the request on the same
/// connection, and there is nothing to discriminate. After
/// `EventsSubscribe` the connection stops being
/// request/response, so every server-initiated line is a tagged
/// `ServerOut` JSON object.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerOut {
    /// Live mesh event (peer state, phase, diag).
    Event { event: MeshEvent },
    /// Subscriber was too slow; some events were dropped.
    /// `skipped` is the number lost since the last successful
    /// receive.
    Lagged { skipped: u64 },
    /// Inbound RPC request arrived from a peer for a method
    /// this client has claimed. The client must respond with
    /// either a single `rpc_respond` (single-shot) or a
    /// sequence of `rpc_stream_chunk` lines terminated by
    /// `rpc_stream_end` (streaming).
    RpcInbound {
        network: String,
        from: String,
        request_id: String,
        operation_id: u64,
        method: String,
        payload: Value,
        /// `true` if the peer asked for a streaming response.
        /// Determined by the wire frame's `streaming` flag, not
        /// by the local handler's mode — clients should
        /// respect the peer's intent.
        streaming: bool,
    },
    /// Chunk of a streaming response to an outbound RPC call
    /// the client made via `RpcCallStream`. Multiple chunks may
    /// arrive before `RpcCallStreamEnd`.
    RpcCallStreamChunk { request_id: String, payload: Value },
    /// End-of-stream marker for an outbound `RpcCallStream`.
    /// `error` is set if the peer terminated the stream with
    /// an error rather than a clean close.
    RpcCallStreamEnd {
        request_id: String,
        error: Option<String>,
    },
    /// Inbound typed-channel message for a channel this client
    /// has subscribed to.
    ChannelInbound {
        network: String,
        from: String,
        channel: String,
        payload: Value,
    },
    // This socket carries nothing about realtime flows: units ride a binary
    // `realtime_pipe`, and every flow operation answers on the connection that
    // requested it. See [`crate::control::Request::RealtimePipe`].
    /// A more-recent client claimed a method this client had
    /// previously registered. The displaced client should stop
    /// expecting `RpcInbound` events for `method`; the displaced claim's
    /// in-flight calls are cancelled and truthfully failed.
    HandlerDisplaced {
        network: String,
        method: String,
        /// Best-effort short id of the displacing client; the
        /// daemon does not surface socket addresses.
        by: String,
    },
}

/// A borrowed mirror of [`ServerOut::RpcInbound`], for measuring a frame that
/// does not exist yet.
///
/// The mailbox prices an item by serializing it, and an inbound RPC frame is
/// assembled from a call whose payload a remote peer chose the size of. Building
/// it in order to ask whether it can be admitted is the admission arriving after
/// the allocation it was about, so the question is asked of this instead: the
/// same tag, the same field names, the same order, every field a borrow.
///
/// **It must serialize byte-for-byte as the variant it mirrors.** That is the
/// whole of its contract and the only reason it is here rather than in `bridge`,
/// where the builder that uses it lives: a mirror kept beside the thing it
/// mirrors is one a change to either has to walk past. `v4_r2_daemon_a_measured_\
/// inbound_frame_matches_the_frame_it_becomes` is what checks it, and it checks
/// the encoded bytes rather than the fields, because equal fields that encode
/// differently is exactly the failure a hand-written mirror has.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ServerOutView<'a> {
    RpcInbound {
        network: &'a str,
        from: &'a str,
        request_id: &'a str,
        operation_id: u64,
        method: &'a str,
        payload: &'a Value,
        streaming: bool,
    },
}

/// Off-node retention owned by one queued outbound frame.
///
/// Every variant is pure serializable data — no oneshot, sender, or socket
/// handle rides in one — so one measurement over the whole frame is exact where
/// a per-variant match would only restate it, and core's shared costing for a
/// serializable value answers it completely. That is not true of every mailbox
/// item: `NetworkCmd` carries reply handles serialization cannot see, which is
/// why its implementation enumerates variants and adds a `SocketOrHandle` term.
/// There is nothing here for such a term to count.
///
/// Delegated rather than derived. This used to restate core's JSON-tree
/// costing, which meant one question — what does a JSON-shaped value retain —
/// had two answers in two crates that could drift apart independently. There is
/// one answer now, and it lives with the trait it serves.
impl myownmesh_core::ResourceMailboxItem for ServerOut {
    fn retained_claim(&self) -> Result<ResourceClaim, ResourceMailboxItemError> {
        myownmesh_core::serialized_mailbox_item_claim(self)
    }
}
