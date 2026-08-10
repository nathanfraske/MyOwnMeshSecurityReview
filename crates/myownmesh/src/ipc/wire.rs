//! Wire frames the daemon writes to a duplex (post-
//! `EventsSubscribe`) client connection. Every line is exactly
//! one of these variants, tagged via the `kind` field so a
//! client can dispatch on it without trying to guess from
//! shape.
//!
//! Backward compat: `Event` / `Lagged` were the only `kind`s
//! the original event stream emitted, and the existing
//! MyOwnMesh GUI client already ignores unknown kinds via its
//! `match _ => {}` default in
//! `gui/src-tauri/src/main.rs::run_event_pump`. New variants
//! land additively without breaking it.

use serde::Serialize;
use serde_json::Value;

use myownmesh_core::events::MeshEvent;

/// Server → client wire frame on a duplex event socket.
///
/// Pre-`EventsSubscribe`, the daemon emits the legacy
/// [`crate::control::Response`] shape (no `kind` tag) so the
/// existing one-shot request/response clients keep working.
/// After `EventsSubscribe`, every server-initiated line is a
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
    // ---- realtime flows ------------------------------------------------
    //
    // Control-plane only. Realtime *units* never appear here: they ride an
    // inbound `realtime_pipe`, which is binary and unframed by JSON. Carrying
    // units as base64 on this socket would put low-latency media on the
    // reliable JSON path, which is the one thing the realtime protocol exists
    // to avoid — a parse and a 33% inflation per unit, on the latency-critical
    // path. There is deliberately no `realtime_inbound` variant.
    // There is deliberately no `realtime_flow_opened`.
    //
    // Peer-unilateral flow creation is not supported: a flow exists because this
    // node's own application asked for one, so the only open that can be
    // announced is one the caller already knows about. The successful response
    // to `realtime_flow_open` IS the acknowledgement, and it arrives on the same
    // connection as the request rather than out of order on an event socket.
    //
    // An event here would have been strictly worse than nothing. It could only
    // ever report local opens, so a client watching for peers opening flows
    // would see a stream that looked live and was structurally incapable of
    // carrying the case it was watching for.
    /// A realtime flow on the session with `from` ended.
    ///
    /// There is no `reason`. Core reports that the flow closed and not why, and
    /// a daemon-authored string would be a guess formatted to look like a
    /// finding.
    RealtimeFlowClosed {
        network: String,
        from: String,
        flow_label: u8,
    },
    // There is deliberately no `realtime_dead_flow`.
    //
    // It was to carry a receiver citing back a label it could no longer resolve,
    // synthesised from a refusal on the inbound path. Core now publishes real
    // flow lifecycle events and they contain no retirement signal — a stream
    // that ends means the session ended, full stop. Keeping a variant only this
    // daemon could infer would put two sources behind one fact, certain to
    // disagree eventually with no rule for which wins, and would have clients
    // writing recovery for a frame with no producer.
    /// A more-recent client claimed a method this client had
    /// previously registered. The displaced client should stop
    /// expecting `RpcInbound` events for `method`; any
    /// in-flight calls are left to resolve naturally (the
    /// displaced client can still answer them).
    HandlerDisplaced {
        network: String,
        method: String,
        /// Best-effort short id of the displacing client; the
        /// daemon does not surface socket addresses.
        by: String,
    },
}
