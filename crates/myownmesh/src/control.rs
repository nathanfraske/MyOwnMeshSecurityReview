//! Daemon control protocol — line-delimited JSON over a local
//! interprocess socket (unix-domain socket on Unix, named pipe on
//! Windows). `myownmesh ctl …` clients and the GUI both talk to the
//! running daemon via this socket.
//!
//! Wire shape: one JSON object per line. Requests have `op` plus
//! op-specific fields; responses have `ok` (bool) plus
//! op-specific payload, or `error: string` on failure.
//!
//! Most ops are single-shot request → response. The exception is
//! [`Request::EventsSubscribe`], which converts the connection into a
//! one-way server-push stream: the daemon writes one JSON event per
//! line until the client disconnects. The GUI's Tauri backend uses
//! this to forward live mesh events into the frontend.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions,
};
use myownmesh_core::realtime as core_realtime;
use myownmesh_core::transport as core_webrtc;
use myownmesh_core::{MeshConfig, MeshHandle, NetworkConfig, ServicesConfig, TopologyMode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::registry::{NetworkRegistry, RemoveResult};
use crate::services::ServiceManager;

/// Default control socket name (Unix abstract or Windows named-pipe
/// segment). Overridable via `config.daemon.control_socket`.
#[allow(dead_code)]
pub fn default_socket_name() -> String {
    "myownmesh.sock".to_string()
}

/// Which way units flow on a [`Request::RealtimePipe`] connection.
///
/// One request covers both directions because only the direction differed
/// between the two pipes this replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimePipeDirection {
    /// Client writes units; the daemon routes each to its flow.
    Outbound,
    /// Daemon writes units the client's subscriptions cover.
    Inbound,
}

// A flow's direction and RTP kind are not redeclared here either.
// `Request::RealtimeFlowOpen` carries `RealtimeFlowDirection` and
// `WebRtcRtpKind` directly, so the value a client sends is the value handed to
// core with no daemon-side mapping in between. A local pair of enums with the
// same two variants would read as harmless and would be the place a translation
// bug eventually lives — one `match` arm crossed, and every outbound flow
// becomes an inbound one.
//
// The two come from different layers on purpose. Direction is basal: which way
// units travel is true of any flow and names no media, so it lives in the
// generic vocabulary. RTP kind is a WebRTC fact — it exists because RTP
// allocates a transceiver per kind — so it is spelled `WebRtcRtpKind` and lives
// at the provider edge. A client naming it is unambiguously naming a WebRTC
// thing, which is what stops a fixed audio/video taxonomy leaking back into the
// layer that is supposed to know nothing about media.
//
// [`RealtimePipeDirection`] stays local because it is not the same thing: it
// names a socket's role, and there are no pipes in core.

// Refusal codes are not redeclared here. `myownmesh_core::realtime::
// RealtimeRefusal::code()` is the one source of the stable strings
// (`session_not_current`, `label_in_use`, `flow_refused`,
// `provider_configuration_invalid`),
// and the daemon forwards what it is given. A daemon-side copy of the enum
// would be a second place to add a variant and a silent way to drop one: a new
// core variant would fall through a local `match` to some default string,
// where forwarding `code()` makes the same change a compile error here.
//
// Note the absent `label_space_exhausted`. The caller supplies an exact name
// and the connector claims that one — it never allocates — and there is no
// enumerable space of names to exhaust, so a name is free or in use and nothing
// can be "full" from a request's point of view. How many flows may be open at
// once is a separate question, answered by `flow_refused` from admission.

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    NetworksList,
    PeersList {
        network: String,
    },
    RosterList {
        network: String,
    },
    RosterApprove {
        network: String,
        device_id: String,
        label: Option<String>,
    },
    RosterRemove {
        network: String,
        device_id: String,
    },
    TopologySet {
        network: String,
        topology: String,
        hub: Option<String>,
    },
    IdentityShow,
    /// Update the device label. Persists to the on-disk identity
    /// anchor and updates the running daemon's in-memory copy so the
    /// next handshake advertises the new label immediately (no
    /// restart needed). Free-form string; empty clears it.
    IdentitySetLabel {
        label: String,
    },
    /// Generate a fresh random Network ID — base36, 8 chars by
    /// default. Stateless utility; the GUI's "Generate" button on
    /// the AddNetworkModal calls this so we don't replicate the
    /// alphabet / RNG choice in JS.
    NetworkIdGenerate,
    /// Canonicalise a user-typed Network ID. Trims, lowercases,
    /// and validates length / charset; returns the normalised
    /// form. Errors flow through the standard `Response::err`
    /// path so the GUI shows them inline.
    NetworkIdNormalize {
        input: String,
    },
    /// Return the full on-disk `MeshConfig`. Used by the GUI's
    /// import/export flow to surface saved networks (and read-only
    /// fields the registry summary doesn't carry — signaling
    /// relays, STUN/TURN servers, auto-approve).
    ConfigShow,
    /// Add a network: persist to config.json, join via the live
    /// `Mesh` handle, attach signaling, register. Returns the new
    /// network's summary. Fails if either the `id` or `network_id`
    /// already exists in the running daemon.
    NetworkAdd {
        config: NetworkConfig,
    },
    /// Remove a network: take it out of the registry, `leave()` the
    /// engine driver, drop the signaling handle, and persist the
    /// updated config.json. Idempotent — removing an unknown id is
    /// reported as success-with-warning.
    NetworkRemove {
        network: String,
        /// Also purge the network's persisted **governance state + roster** —
        /// a genuine *forget* (e.g. leaving a fleet), not just unloading the
        /// live network. Default `false` so a teardown keeps the signed state
        /// for a later rejoin; only a deliberate leave sets it. Leaving it on
        /// disk is exactly what makes a leave-then-rejoin reload a stale (and
        /// possibly forked) genesis.
        #[serde(default)]
        purge: bool,
    },
    /// Forget **every** joined network at once — a `NetworkRemove{purge:true}`
    /// for all of them: tear each out of the registry, `leave()` its driver, and
    /// delete its signed governance state + roster from disk. Keeps this device's
    /// identity. The daemon then exits (see [`schedule_daemon_exit`]) so every
    /// layer reloads from the now-clean disk instead of a stale in-memory cache
    /// that would re-persist ("resurrect") what was just removed; the GUI/service
    /// brings a fresh daemon back up.
    ForgetAllNetworks,
    /// Factory reset — wipe this device's **entire** state directory
    /// (`~/.myownmesh`, honouring `MYOWNMESH_HOME`): identity, config, and every
    /// network's roster + governance state. The device becomes a brand-new
    /// identity to every peer. Quiesces each network first (so nothing
    /// re-persists mid-wipe), then removes the tree and exits so a fresh daemon
    /// mints a new identity on empty state.
    FactoryReset,
    /// Update an already-joined network's config in place. Hot-
    /// reloadable changes (topology / label / auto_approve / roster
    /// path) are applied without dropping any peer; transport-level
    /// changes (signaling relays / STUN / TURN / network_id) rebuild
    /// the network — the ICE config is baked into each
    /// `RTCPeerConnection` at creation, so a STUN/TURN edit only takes
    /// effect on fresh connections. Either way the new config is
    /// persisted to config.json. Fails if the network isn't currently
    /// joined (use `NetworkAdd` for that). This is the path the GUI's
    /// network-settings Save takes to push an edit (a new TURN URL, say)
    /// to a network the daemon already joined on a prior launch.
    NetworkUpdate {
        config: NetworkConfig,
    },
    /// Reconnect a joined network in place — the non-destructive twin of a
    /// `NetworkRemove` + `NetworkAdd`. Redials signaling and renegotiates ICE
    /// without leaving the room or announcing a `Leave`, so peers keep their
    /// sessions and app-level state. `peer` omitted reconnects every peer on
    /// the network; `peer` set reconnects just that one (a per-node refresh).
    /// This is what a GUI "refresh / reconnect" control should call instead of
    /// the destructive remove+re-add. No-op-with-error if the network isn't
    /// currently joined.
    NetworkReconnect {
        network: String,
        #[serde(default)]
        peer: Option<String>,
    },
    /// Deliberately dial exactly one signaling-discovered peer on a joined
    /// network, opening the WebRTC session on demand — the control-socket
    /// surface for [`myownmesh_core::JoinedNetwork::connect_peer`]. This is how
    /// a `Silent` network (which never auto-dials on presence) ever opens a
    /// connection: a daemon-client embedder (e.g. a remote-support node) that
    /// matched a peer's Support ID sends this to dial exactly that one peer.
    /// The local side dials as the offerer, so a Silent peer is reached by the
    /// offer and answers. No-op-with-error if the network isn't currently
    /// joined; `Ok` means the dial was queued, not that the peer connected —
    /// watch the event stream for the outcome.
    NetworkConnectPeer {
        network: String,
        peer: String,
        /// Record a standing dial: the engine redials this peer on
        /// every announce (even on a Silent network) and holds a
        /// never-expiring reconnect intent, persisted with the network
        /// config. The shape a support session needs to survive the
        /// far end sleeping or rebooting.
        #[serde(default)]
        pin: bool,
        /// When > 0, wait up to this long for the peer to reach
        /// ACTIVE and report the real outcome, instead of returning
        /// as soon as the dial is queued.
        #[serde(default)]
        wait_ms: u64,
    },
    /// Snapshot which infrastructure services this device hosts
    /// (signaling / STUN / TURN): live runtime status plus the
    /// persisted config. The GUI's Services settings section reads this
    /// to render toggles and listen addresses.
    ServicesStatus,
    /// Replace the device's services config wholesale: persist it to
    /// config.json and reconcile the running services (start newly
    /// enabled ones, stop disabled ones, restart reconfigured ones).
    /// Returns the resulting status. The GUI sends the full edited
    /// `ServicesConfig`; the CLI reads the current one, flips a field,
    /// and sends it back.
    ServicesSet {
        services: ServicesConfig,
    },

    /// Subscribe to the live event stream. The connection becomes a
    /// one-way server-push channel after this op; the daemon writes
    /// one JSON-encoded `MeshEvent` (or framing wrapper) per line
    /// until the client closes. Used by the GUI to render live peer
    /// state changes without polling.
    EventsSubscribe,

    /// Subscribe to one network's connection-state transition trace.
    /// Like [`EventsSubscribe`](Request::EventsSubscribe) the
    /// connection becomes a one-way push stream after this op, but it
    /// carries only [`myownmesh_core::ConnTrace`] records — one compact
    /// JSON object per line — for `ctl trace`. Subscribing is what
    /// turns the engine's connection tracer on (it's a no-op while
    /// nobody watches), so this is the Phase-0 debugging entry point.
    TraceSubscribe {
        network: String,
    },

    // ---- closed-network governance --------------------------------
    /// Snapshot the per-network signed governance state — kind,
    /// roles, transition log, pending proposals, splits. The GUI
    /// polls this to render its Governance tab + per-network kind
    /// badge.
    GovernanceState {
        network: String,
    },
    /// Float a kind-change proposal (`open → closed` or
    /// `closed → open`). Engine signs with the local identity,
    /// broadcasts to peers, attempts immediate ratification if the
    /// quorum is already met. Returns the new proposal id.
    GovernanceProposeKindChange {
        network: String,
        /// Target kind. Must differ from the current one.
        to: myownmesh_core::NetworkKind,
        /// Per-device custody second factor, if this device enrolled one for
        /// the network (see the `GovernanceMfa*` ops). Omitted otherwise.
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float a role-grant proposal.
    GovernanceProposeRoleGrant {
        network: String,
        target: String,
        role: myownmesh_core::Role,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float a role-revoke proposal.
    GovernanceProposeRoleRevoke {
        network: String,
        target: String,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float an evict proposal — remove a peer from the closed network's
    /// roster entirely (the propagating lost/stolen-device kick).
    GovernanceProposeEvict {
        network: String,
        target: String,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Float a topology-change proposal: the owner-signed, network-wide
    /// shape (mode, hub set, spoke redundancy) in one transition. Once
    /// ratified it outranks every device's local config topology and
    /// converges through the signed log exactly like roles do — this is
    /// how a node is made an infra hub for the whole network. Closed
    /// networks only; open/silent ones keep the per-device `TopologySet`.
    GovernanceProposeTopology {
        network: String,
        /// Same encoding `TopologySet` takes: `ring`, `star`, `hubs`,
        /// or `full_mesh`.
        topology: String,
        /// Hub spec for `star` (`<device_id>`) / `hubs`
        /// (`id1,id2[,…][:spoke_redundancy]`).
        #[serde(default)]
        hub: Option<String>,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Sign a pending proposal.
    GovernanceSign {
        network: String,
        proposal_id: String,
        #[serde(default)]
        mfa_code: Option<String>,
    },
    /// Deny a pending proposal. Single-shot kill switch.
    GovernanceDeny {
        network: String,
        proposal_id: String,
    },
    /// Withdraw a proposal the local device floated.
    GovernanceWithdraw {
        network: String,
        proposal_id: String,
    },
    /// Spawn a proposer-initiated split. Returns the derived
    /// network id of the new closed network.
    GovernanceSpawnSplit {
        network: String,
        proposal_id: String,
    },
    /// Enroll a per-device TOTP custody lock for `network` on this daemon.
    /// Returns the secret (base32 + `otpauth://` URI for a QR) and the
    /// one-time recovery codes — shown to the user exactly once. Fails if an
    /// enrollment already exists (disable it first).
    GovernanceMfaEnroll {
        network: String,
    },
    /// Whether this device holds a custody enrollment for `network`.
    GovernanceMfaStatus {
        network: String,
    },
    /// Remove the custody lock for `network` — requires a valid code, so the
    /// lock can't be lifted by someone who can't already satisfy it.
    GovernanceMfaDisable {
        network: String,
        code: String,
    },

    // ---- typed-channel + RPC IPC (post-EventsSubscribe) ----------
    //
    // The variants below require the client to have first sent
    // `EventsSubscribe` first. That connection becomes server-push-only and
    // returns an unguessable capability; later command connections must present
    // both it and the numeric routing coordinate.
    /// Claim a method name on a network. Subsequent peer RPC
    /// calls matching the method are forwarded to the client
    /// identified by `client_id` as `RpcInbound` events on its
    /// event socket. Last-claim-wins: a later register evicts
    /// the previous owner with a `HandlerDisplaced` event.
    /// `streaming = true` installs a streaming handler (chunks
    /// via `RpcStreamChunk` + `RpcStreamEnd`); `false` is
    /// single-shot (`RpcRespond`).
    RpcRegister {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        method: String,
        streaming: bool,
    },
    /// Release a method claim. No-op if not currently held by
    /// this client.
    RpcUnregister {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        method: String,
    },
    /// Resolve an in-flight inbound RPC (single-shot). The exact remote
    /// coordinates, response class, local owner capability and private
    /// operation id must all match. Either `ok` or `error` should be set; if
    /// both, `error` wins.
    RpcRespond {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ok: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Push one chunk to an in-flight streaming inbound RPC.
    RpcStreamChunk {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        payload: serde_json::Value,
    },
    /// Close an in-flight streaming inbound RPC. After this the
    /// request id is no longer routable; further chunks are
    /// silently dropped. Optional `error` propagates to the
    /// peer as the stream-end's failure reason.
    RpcStreamEnd {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Make an outbound single-shot RPC. Blocks the daemon's
    /// command socket response on the peer's reply — same shape
    /// as `Rpc::call`.
    RpcCall {
        network: String,
        peer: String,
        method: String,
        payload: serde_json::Value,
    },
    /// Make an outbound streaming RPC. Returns immediately with
    /// the engine-assigned `request_id`; subsequent
    /// `RpcCallStreamChunk` / `RpcCallStreamEnd` events deliver
    /// the chunks on the client's event socket. The `client_id`
    /// identifies which event socket receives the chunks.
    RpcCallStream {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        payload: serde_json::Value,
    },
    /// Subscribe to a typed channel by name. Inbound channel
    /// frames are forwarded as `ChannelInbound` events on the
    /// `client_id`'s event socket. Multiple clients can
    /// subscribe to the same channel; each gets a copy of every
    /// frame.
    ChannelSubscribe {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        channel: String,
    },
    /// Release a channel subscription. No-op if not currently
    /// subscribed.
    ChannelUnsubscribe {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        network: String,
        channel: String,
    },
    /// Send one frame on a typed channel to a specific peer.
    /// Doesn't require a subscription — sends and subscriptions
    /// are independent.
    ChannelSendTo {
        network: String,
        channel: String,
        peer: String,
        payload: serde_json::Value,
    },
    /// Send a frame on a typed channel under the acknowledged-delivery
    /// contract: resolved when the peer's engine has delivered it, or with an
    /// error. The primitive that replaces application-level retransmit loops.
    ///
    /// The contract is **within one live session**, and that bounds every part
    /// of it. Submission acquires the peer's current session or is refused, so
    /// a frame is never accepted for a peer this node cannot currently reach;
    /// the frame is retained under that session's own lease; and session
    /// replacement, policy revocation, connector replacement or restart resolve
    /// the caller with an error naming what happened rather than carrying the
    /// frame into a session that did not accept it.
    ///
    /// There is therefore no expiry to state and none to configure. A frame
    /// outlives neither its session nor the caller's own await, so the two
    /// things a deadline used to protect against — an undeliverable frame
    /// retained forever, and a caller left waiting on one — cannot happen.
    /// Backpressure is the resource provider refusing the frame's own lease,
    /// which is a real bound rather than a fixed queue depth.
    ChannelSendReliable {
        network: String,
        channel: String,
        peer: String,
        payload: serde_json::Value,
    },
    /// Broadcast a frame on a typed channel to every active
    /// peer. Returns the number of peers the send was
    /// dispatched to.
    ChannelSendAll {
        network: String,
        channel: String,
        payload: serde_json::Value,
    },
    /// Replace the network's advertised capabilities. Triggers
    /// a `capabilities_update` broadcast to peers on the next
    /// engine tick.
    CapabilitiesSet {
        network: String,
        capabilities: myownmesh_core::protocol::CapabilityAdvert,
    },

    // ---- realtime flows -------------------------------------------------
    //
    // One codec-opaque protocol replaces the separate video and audio lane
    // surfaces. The daemon carries `mime` and `clock_rate` and parses neither;
    // there is no video/audio distinction anywhere below this point, and no
    // fixed per-kind lane pool.
    //
    // There is deliberately no unit-carrying request here. Units ride a binary
    // `RealtimePipe`; putting them in a JSON request would route low-latency
    // media through the reliable path, costing a parse and 33% base64
    // inflation per unit. `VideoSend`/`AudioSend` had no successor for exactly
    // that reason — the pipe is the media path, in both directions.
    /// Declare a realtime flow to `peer` under `flow_label`.
    ///
    /// `flow_label` is a name the caller chose, opaque to the daemon and to
    /// core: it is compared for equality against that session's own table and
    /// never parsed, ordered, or ranged over. The daemon names nothing and
    /// holds no label state. The connector claims that exact name and never
    /// picks another, so the only name failure is `label_in_use`.
    ///
    /// It is scoped to one session and freely reusable after close. There is no
    /// label space and therefore no exhaustion: what bounds a name is its size,
    /// 1..=255 bytes, because the binary pipe length-prefixes it with one byte.
    /// How many may exist at once is admission's question, answered by the
    /// connector's flow policy and the provider's leases.
    ///
    /// Carried here as a string, which is the JSON-representable half of the
    /// byte name core holds. The binary pipe carries the same name as raw bytes.
    ///
    /// `rtp_kind`, `mime`, `clock_rate` and `channels` together select an
    /// encoding *family* among the ones the application-supplied profile
    /// registered — not one registration tuple. Deployed H.264 is five
    /// payload-type/fmtp variants sharing all four values; every one of them is
    /// registered on the `MediaEngine`, and which the connection uses is
    /// settled by SDP negotiation with the peer. A request that named one exact
    /// tuple would therefore fail against any peer that picked a different
    /// variant, which is four of the five.
    ///
    /// All four fields are still needed, because a family is what they jointly
    /// name: a lookup on `mime` alone would fold Opus's channel counts and any
    /// two clock rates into one. `clock_rate` is additionally what makes an
    /// inbound unit's `rtp_timestamp` interpretable, so it is a field rather
    /// than something folded into `mime` and parsed back out.
    ///
    /// **Answers a `flow_capability`, and that is what authorizes everything
    /// afterwards.** The daemon keeps the move-only core flow handle behind it,
    /// owned by the authenticated client. `network`, `peer` and `flow_label`
    /// are what this request *resolves*; none of them is presented again. The
    /// pair they replace was re-resolvable — a client whose session had been
    /// replaced kept writing under `peer + flow_label` and its units were taken
    /// by the successor's flow of the same name, silently, because nothing on a
    /// realtime path is acknowledged per unit.
    ///
    /// `client_id` and `client_capability` are required for the same reason:
    /// the flow has to be owned by somebody, and the owner must be the same
    /// client across the several connections it will use — the flow is opened
    /// here and written on a separate `realtime_pipe`.
    RealtimeFlowOpen {
        network: String,
        peer: String,
        flow_label: String,
        /// The client's `EventsSubscribe` id — a routing coordinate.
        client_id: crate::ipc::ClientId,
        /// Authority minted for that event-stream connection. Possession of
        /// this, not the id beside it, is what owns the flow.
        client_capability: String,
        /// Which way this node carries units on this flow. Stated by the caller
        /// rather than inferred: a flow this node sends on and one it receives
        /// on need different transceiver directions, and inferring from later
        /// traffic would let the first unit decide.
        direction: core_realtime::RealtimeFlowDirection,
        /// A connector primitive, not a codec name: RTP distinguishes audio from
        /// video when allocating a transceiver, independently of which codec
        /// occupies it. Carrying it explicitly is what lets the connector pick a
        /// transceiver without parsing `mime`, so `video/H264` and `video/VP8`
        /// are the same decision here and core never learns either name.
        ///
        /// The JSON spelling stays `"audio"` / `"video"`. Moving this type to
        /// the provider edge changed which Rust module owns it and deliberately
        /// changed nothing a client sends.
        rtp_kind: core_webrtc::WebRtcRtpKind,
        mime: String,
        clock_rate: u32,
        /// 0 for video, 2 for stereo Opus. Part of the family key, not
        /// decoration: two registered families can differ only here.
        channels: u16,
    },
    /// Release a realtime flow and its label. No-op if not open.
    ///
    /// The response is the acknowledgement, and it follows the retirement of the
    /// flow's native half rather than the release of its label. A caller may
    /// therefore close a label and reopen it immediately, knowing the previous
    /// occupant is gone. That ordering is the whole point: acking on the label
    /// release would let a reopen land while the old transceiver or sender was
    /// still alive, which is the one case a caller would have needed the
    /// guarantee for.
    ///
    /// Which is also why a label must stay reserved until this answers. Freeing
    /// it on send and reusing it before the ack reintroduces exactly the ABA
    /// this ordering removes: the peer cannot tell the new flow from the old one
    /// it has not finished tearing down. On a refusal the label stays reserved
    /// too — a close that did not happen has retired nothing.
    ///
    /// Names the flow by the capability `RealtimeFlowOpen` issued, never by
    /// `peer + flow_label`. The coordinate pair is what made a close as
    /// dangerous as a send: a client whose session had been replaced would have
    /// torn down the *successor's* flow of the same name, and the successor
    /// belongs to somebody else. The capability closes the flow it was issued
    /// for or nothing at all.
    ///
    /// The daemon's stored handle is **consumed**, so a second close with the
    /// same capability finds nothing rather than reaching core twice.
    RealtimeFlowClose {
        client_id: crate::ipc::ClientId,
        client_capability: String,
        flow_capability: String,
    },
    /// Convert this connection into a dedicated **binary realtime pipe**:
    /// after the ack it carries only length-prefixed frames
    /// (`[u32 len][body]`, see [`decode_realtime_send_unit`] and
    /// [`encode_realtime_recv_unit`]) and no JSON.
    ///
    /// `Outbound` reads units from the client and writes each to its flow;
    /// `Inbound` pushes every unit arriving on the bound session, whichever
    /// flow it arrived on — the frame carries the name, so no subscription
    /// selects which flows are delivered.
    ///
    /// **The two directions are bound differently, and the asymmetry is the
    /// point.**
    ///
    /// `Outbound` names its flow by `flow_capability` — the value
    /// `RealtimeFlowOpen` issued — and nothing else. It carries no `peer`,
    /// because a peer selector here would be re-resolved for every unit, which
    /// is precisely the defect: labels are session-scoped and freely reused, so
    /// a pipe that outlived its session went on writing `screen` into whatever
    /// the successor called `screen`, with nothing anywhere acknowledging a unit
    /// and therefore nothing to notice. `network` remains because closing and
    /// sending happen *through* a joined network, not because it selects
    /// anything: the capability already names one exact flow on one exact
    /// session.
    ///
    /// The frame body still carries a `flow_label`, and it still grants nothing.
    /// It is checked against the flow this pipe is bound to and refused if it
    /// disagrees, so a client that muddles its own names hears about it rather
    /// than having units silently rerouted.
    ///
    /// `Inbound` is bound by `network` + `peer`, and that is a different
    /// question: it claims one *session's* whole unit stream, not one flow, and
    /// the stream reader it gets is itself the exact authority — it can only
    /// ever yield units the claiming session's own flow set put there. There is
    /// no coordinate to re-resolve after the claim.
    ///
    /// The binding is also a lifetime, and it is observed rather than
    /// signalled. There is no flow or session event on any socket: a separate
    /// signal would be a second source of truth that can disagree with the
    /// queue, and this is where the end is actually observable. Dropping the
    /// session's `PromotedSession` drops its flow set and
    /// the queued units with it, and each direction learns that from the queue
    /// it already holds:
    ///
    /// - inbound terminates when the session-owned recv queue closes;
    /// - outbound terminates on a closed queue, or on `session_not_current`
    ///   from the synchronous send.
    ///
    /// Either way the pipe ends with the session rather than outliving it,
    /// which would be a send outliving its flow one layer up. The client then
    /// reconnects and may immediately reuse the same names — a name belongs to
    /// the session that claimed it and died with it — so the binding is
    /// re-established per session and never cached per peer.
    ///
    /// Field shapes are validated strictly and a wrong-shaped request is
    /// refused rather than trimmed. `Outbound` requires `network`, `client_id`,
    /// `client_capability` and `flow_capability`, and refuses `peer`;
    /// `Inbound` requires `network`, `peer`, `client_id` and
    /// `client_capability`, and refuses `flow_capability`. Silently ignoring a
    /// field would let a client believe it had bound something the daemon never
    /// recorded — and for `peer` on an outbound pipe that belief is exactly the
    /// one this finding removes.
    RealtimePipe {
        direction: RealtimePipeDirection,
        /// Which joined network the operations run through. Not a selector for
        /// `Outbound`: the flow capability already names one exact flow.
        network: String,
        /// Required for `Inbound`, which claims that session's whole unit
        /// stream. Must be absent for `Outbound`, which names a flow rather
        /// than a peer.
        #[serde(default)]
        peer: Option<String>,
        /// The client's `EventsSubscribe` id. Required for both directions
        /// now: outbound needs it to find the client that owns the flow.
        #[serde(default)]
        client_id: Option<crate::ipc::ClientId>,
        /// Authority minted for the referenced event-stream connection.
        #[serde(default)]
        client_capability: Option<String>,
        /// Required for `Outbound` — the capability `RealtimeFlowOpen` issued
        /// for the exact flow this pipe writes to. Must be absent for
        /// `Inbound`, which is bound to a session rather than a flow.
        #[serde(default)]
        flow_capability: Option<String>,
    },

    // ---- self-update -------------------------------------------------
    /// Snapshot the updater's state — current version, channel, policy,
    /// effective release feed, last check, any staged version.
    UpdateStatus,
    /// Force a release-feed check now (ignores the interval cooldown) and
    /// stage a permitted update. Applies on the next daemon start.
    UpdateCheck,
    /// Apply a staged update to disk now (takes effect on next start).
    UpdateApply,
    /// Apply a partial updater-preferences edit (enable, channel,
    /// auto_apply, interval, or a white-label release URL). Returns the
    /// resulting status. Carried as raw JSON deserialised into the
    /// updater's `UpdatePrefs` so the daemon doesn't re-derive the shape.
    UpdateSetPrefs {
        prefs: serde_json::Value,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Turn a connector refusal into the one error shape realtime control uses.
///
/// Both halves are carried: `code` is the stable machine-readable string from
/// [`core_realtime::RealtimeRefusal::code`], and the human message goes in the
/// usual `error` field. Clients dispatch on `code` and display `error` — the
/// message is prose and is deliberately not parseable.
///
/// Note that `session_not_current` also covers an unknown or replaced peer, by
/// design on core's side: distinguishing "no such peer" would report peer
/// existence to a caller that has proved nothing about its right to know.
fn realtime_refused(refusal: core_realtime::RealtimeRefusal) -> Response {
    Response {
        ok: false,
        error: Some(refusal.to_string()),
        data: Some(serde_json::json!({ "code": refusal.code() })),
    }
}

/// Resolve the platform-appropriate listener name. On Unix this
/// is `~/.myownmesh/daemon.sock`; on Windows it's a named-pipe
/// segment under the local namespace.
fn resolve_socket(custom: Option<PathBuf>) -> Result<SocketTarget> {
    if let Some(path) = custom {
        return Ok(SocketTarget::Path(path));
    }
    #[cfg(unix)]
    {
        let path = myownmesh_core::dirs::data_dir()
            .context("data_dir")?
            .join("daemon.sock");
        Ok(SocketTarget::Path(path))
    }
    #[cfg(not(unix))]
    {
        Ok(SocketTarget::Name(default_socket_name()))
    }
}

#[derive(Debug)]
enum SocketTarget {
    Path(PathBuf),
    #[allow(dead_code)]
    Name(String),
}

/// One encoding family this daemon has registered, as published to clients.
///
/// A family, not a registration tuple. Deployed H.264 is several payload/fmtp
/// variants sharing these four fields; a flow open names the family and SDP
/// negotiation picks the variant. Publishing payload types would invite a
/// caller to name one, which is not a choice it gets to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealtimeEncoding {
    /// `audio` or `video` — which transceiver the family occupies.
    pub kind: String,
    pub mime: String,
    pub clock_rate: u32,
    /// 0 for video; 2 for stereo Opus.
    pub channels: u16,
}

/// What this daemon can carry on the realtime path.
///
/// Three facts, and no promise: whether the daemon supports the path at all,
/// which encoding families it registered, and the ceiling **only when the owner
/// explicitly selected one**. A flat capacity number would be a promise, because
/// a caller would size its concurrent flows against it — and the directional resource
/// envelopes underneath answer `flow_refused` before any aggregate is reached.
/// Feasibility is learned where it is decided, from the typed refusal on
/// `realtime_flow_open`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealtimeAdvert {
    /// False when no profile was registered: no codecs, so nothing can be
    /// carried. Stated rather than implied by an empty list, so a client can
    /// tell "this build has no realtime path" from "it has one and I could not
    /// read its encodings".
    pub supported: bool,
    /// The registered families, deduplicated. Empty when unsupported.
    pub encodings: Vec<RealtimeEncoding>,
    /// Present only when the owner selected an explicit ceiling. Absent means
    /// no ceiling was stated — not that the ceiling is zero or unbounded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_ceiling: Option<RealtimeFlowCeiling>,
}

/// The owner's explicitly selected per-peer concurrent-flow ceiling.
///
/// Reported per direction, because that is how the connector holds it and how
/// it refuses. A single combined figure would have to be invented here — the
/// sum is not a bound anything enforces, and a caller that opened against it
/// would be refused by whichever direction ran out first, which is the exact
/// failure the flat count produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RealtimeFlowCeiling {
    pub max_inbound_flows: u64,
    pub max_outbound_flows: u64,
}

impl RealtimeAdvert {
    /// A daemon that registered no realtime profile and can carry nothing.
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            encodings: Vec::new(),
            flow_ceiling: None,
        }
    }

    /// A daemon that registered `encodings`, with the owner's explicit ceiling
    /// if one was selected.
    pub fn registered(
        encodings: Vec<RealtimeEncoding>,
        flow_ceiling: Option<RealtimeFlowCeiling>,
    ) -> Self {
        Self {
            supported: true,
            encodings,
            flow_ceiling,
        }
    }
}

/// Start the control socket listener. Returns when the shutdown
/// broadcast fires.
pub async fn serve(
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    custom: Option<PathBuf>,
    realtime: RealtimeAdvert,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let stream_capacity = std::env::var("MYOWNMESH_IPC_STREAM_CAPACITY")
        .context(
            "MYOWNMESH_IPC_STREAM_CAPACITY must explicitly select the local RPC stream capacity",
        )?
        .parse::<std::num::NonZeroUsize>()
        .context("MYOWNMESH_IPC_STREAM_CAPACITY must be a nonzero integer")?;
    let json_line_bytes = explicit_nonzero_bytes("MYOWNMESH_IPC_JSON_LINE_BYTES")?;
    let realtime_frame_bytes = explicit_nonzero_bytes("MYOWNMESH_IPC_REALTIME_FRAME_BYTES")?;
    let target = resolve_socket(custom)?;
    let listener = bind_listener(&target)?;
    info!(?target, "control socket listening");
    let state = Arc::new(ControlState {
        mesh,
        registry,
        services,
        clients: crate::ipc::ClientRegistry::with_stream_capacity(stream_capacity),
        json_line_bytes,
        realtime_frame_bytes,
        realtime,
    });

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                info!("control socket shutting down");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok(stream) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, state).await {
                                debug!("control client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept failed: {e}");
                    }
                }
            }
        }
    }

    // Every client's flows are closed through their own networks before this
    // returns. Dropping the handles would release nothing — a flow handle owns
    // no part of the flow — so a daemon that shut down without this would leave
    // native transceivers and senders behind for as long as their sessions
    // lived.
    for client in state.clients.shutdown() {
        close_owned_realtime_flows(&state, &client).await;
    }

    Ok(())
}

fn bind_listener(target: &SocketTarget) -> Result<LocalSocketListener> {
    use interprocess::local_socket::Name;
    let name: Name = match target {
        SocketTarget::Path(p) => {
            #[cfg(unix)]
            prepare_owner_only_socket_parent(p)?;
            // Remove stale socket if present so re-binds succeed.
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(p);
            }
            p.as_path()
                .to_fs_name::<GenericFilePath>()
                .context("control socket path → fs_name")?
        }
        SocketTarget::Name(n) => n
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .context("control socket name → ns_name")?,
    };
    let options = ListenerOptions::new().name(name);
    #[cfg(unix)]
    let options = {
        use interprocess::os::unix::local_socket::ListenerOptionsExt;
        options.mode(0o600)
    };
    #[cfg(windows)]
    let options = {
        use interprocess::os::windows::{
            local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
        };
        // Protected DACL naming the current token's user SID exactly. Owner
        // Rights (`OW`) is not equivalent: an elevated token's default owner
        // may be an administrator group.
        let sddl = current_user_pipe_sddl()?;
        let descriptor = SecurityDescriptor::deserialize(&sddl)
            .context("create current-owner pipe security descriptor")?;
        options.security_descriptor(descriptor)
    };
    let listener = options.create_tokio().context("create_tokio")?;
    #[cfg(unix)]
    if let SocketTarget::Path(path) = target {
        verify_owner_only_socket_path(path)?;
    }
    Ok(listener)
}

#[cfg(windows)]
fn current_user_pipe_sddl() -> Result<widestring::U16CString> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token: HANDLE = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "open current process token: {}",
        std::io::Error::last_os_error()
    );
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = Token(token);
    let mut needed = 0_u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    anyhow::ensure!(needed != 0, "measure current token user SID");
    let word = std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; (needed as usize).div_ceil(word)];
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0,
        "read current token user SID: {}",
        std::io::Error::last_os_error()
    );
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) } != 0,
        "format current token user SID: {}",
        std::io::Error::last_os_error()
    );
    struct LocalString(windows_sys::core::PWSTR);
    impl Drop for LocalString {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
    let sid_text = LocalString(sid_text);
    let sid = unsafe { widestring::U16CStr::from_ptr_str(sid_text.0) }.to_string_lossy();
    widestring::U16CString::from_str(format!("D:P(A;;GA;;;{sid})"))
        .context("encode current-user pipe DACL")
}

#[cfg(unix)]
fn prepare_owner_only_socket_parent(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let parent = path
        .parent()
        .context("control socket has no parent directory")?;
    if !parent.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("create owner-only control directory {}", parent.display()))?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "control socket parent is not a directory"
    );
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "control socket parent is not owned by the daemon user"
    );
    if metadata.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("make control directory owner-only: {}", parent.display()))?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "control socket parent must be owner-only"
    );
    Ok(())
}

#[cfg(unix)]
fn verify_owner_only_socket_path(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect control socket {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_socket(),
        "control endpoint is not a socket"
    );
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "control socket is not owned by the daemon user"
    );
    anyhow::ensure!(
        metadata.mode() & 0o777 == 0o600,
        "control socket must have exact owner-only mode 0600"
    );
    Ok(())
}

#[cfg(unix)]
fn verify_local_peer(stream: &LocalSocketStream) -> Result<()> {
    let credentials = stream
        .peer_creds()
        .context("read control peer credentials")?;
    let peer = credentials
        .euid()
        .context("control transport did not provide peer euid")?;
    anyhow::ensure!(
        peer == unsafe { libc::geteuid() },
        "control peer is not the daemon user"
    );
    Ok(())
}

#[cfg(not(unix))]
fn verify_local_peer(_stream: &LocalSocketStream) -> Result<()> {
    Ok(())
}

struct ControlState {
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    services: Arc<ServiceManager>,
    clients: crate::ipc::ClientRegistry,
    realtime: RealtimeAdvert,
    json_line_bytes: usize,
    realtime_frame_bytes: usize,
}

fn explicit_nonzero_bytes(name: &str) -> Result<usize> {
    std::env::var(name)
        .with_context(|| format!("{name} must explicitly select a local IPC byte ceiling"))?
        .parse::<std::num::NonZeroUsize>()
        .with_context(|| format!("{name} must be a nonzero integer"))
        .map(std::num::NonZeroUsize::get)
}

// The daemon keeps no realtime flow state of its own, and deliberately holds
// nothing keyed by label. `recv_webrtc_realtime_any` delivers the label with the
// unit, so a local index of open flows would be a second answer to a question
// core already answers — and the failure mode of a stale mirror on this path is
// units routed to a flow that closed.

async fn handle_client(stream: LocalSocketStream, state: Arc<ControlState>) -> Result<()> {
    verify_local_peer(&stream)?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    while let Some(line) = read_bounded_json_line(&mut reader, state.json_line_bytes).await? {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("parse: {e}"));
                let line = serde_json::to_string(&resp)? + "\n";
                writer.write_all(line.as_bytes()).await?;
                continue;
            }
        };
        // EventsSubscribe converts the connection into a server-
        // push channel: the daemon writes mesh events plus any
        // IPC-routed frames (RpcInbound, ChannelInbound, ...)
        // until the client disconnects. Allocate a ClientId so
        // subsequent RPC/channel-management requests on OTHER
        // command sockets can target this connection.
        if matches!(request, Request::EventsSubscribe) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let client = state.clients.register(tx);
            let client_id = client.id;
            // Ack carries the client_id so the caller knows what
            // to pass back on subsequent `client_id`-bearing ops.
            let ack = Response::ok(serde_json::json!({
                "subscribed": true,
                "client_id": client_id.to_string(),
                "client_capability": state.clients.capability(&client),
            }));
            let line = serde_json::to_string(&ack)? + "\n";
            writer.write_all(line.as_bytes()).await?;
            let result = run_events_stream(&state, &mut writer, rx).await;
            // Clean up the client's claims regardless of how
            // the stream ended.
            state.clients.unregister(client_id);
            // And its realtime flows, which have to be *closed* rather than
            // dropped: a flow handle owns nothing, so dropping one leaves the
            // label claimed and the native half up until the session itself
            // ends. This is the one place that knows both the flows and the
            // networks to close them through.
            close_owned_realtime_flows(&state, &client).await;
            result?;
            break;
        }
        // TraceSubscribe is the same server-push pattern as
        // EventsSubscribe but carries only ConnTrace records and needs
        // no ClientId (it routes nothing back in). An unknown network
        // is reported as a plain error response and the connection
        // stays open for another request.
        if let Request::TraceSubscribe { network } = &request {
            let network = network.clone();
            match state.registry.get(&network) {
                Some(net) => {
                    let ack = Response::ok(serde_json::json!({
                        "subscribed": true,
                        "stream": "conn_trace",
                        "network": network,
                    }));
                    let line = serde_json::to_string(&ack)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    let rx = net.state().subscribe_conn_trace();
                    let result = run_trace_stream(&mut writer, rx).await;
                    result?;
                    break;
                }
                None => {
                    let resp = Response::err(format!("unknown network: {network}"));
                    let line = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(line.as_bytes()).await?;
                    continue;
                }
            }
        }
        // RealtimePipe converts the connection into a one-way binary stream of
        // realtime units, the EventsSubscribe pattern in whichever direction was
        // asked for. After the ack the connection speaks only length-prefixed
        // binary frames — no per-frame JSON, no base64.
        if let Request::RealtimePipe {
            direction,
            network,
            peer,
            client_id,
            client_capability,
            flow_capability,
        } = &request
        {
            // Field shapes are checked before the ack, and extras are refused
            // rather than ignored. A pipe that acked and then behaved as though
            // a field had not been sent would be indistinguishable, from the
            // client's side, from one that honoured it.
            let bound = match realtime_pipe_binding(
                *direction,
                network,
                peer.as_deref(),
                flow_capability.as_deref(),
            ) {
                Ok(bound) => bound,
                Err(message) => {
                    let resp = Response::err(message);
                    writer
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                    continue;
                }
            };
            // Both directions are owned now. Inbound has always needed an owner
            // to end with; outbound needs one because the flow it writes to
            // belongs to a client, and the client capability is what proves this
            // connection is that client.
            let pipe_owner = {
                let (Some(client_id), Some(capability)) =
                    (*client_id, client_capability.as_deref())
                else {
                    let resp = Response::err(
                        "realtime_pipe requires client_id and client_capability: a pipe \
                         is owned by the client that opened its flow, and possession of \
                         the capability is what proves this connection is that client",
                    );
                    writer
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                    continue;
                };
                let Some(owner) = state.clients.authenticate(client_id, capability) else {
                    let resp = Response::err("invalid local client authority");
                    writer
                        .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                        .await?;
                    continue;
                };
                owner
            };
            let bound_network = match &bound {
                RealtimePipeBinding::Outbound { network, .. }
                | RealtimePipeBinding::Inbound { network, .. } => network.clone(),
            };
            let Some(net) = state.registry.get(&bound_network) else {
                let resp = Response::err(format!("unknown network: {bound_network}"));
                writer
                    .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                    .await?;
                continue;
            };
            // An inbound pipe claims the session's unit stream BEFORE the ack.
            // The claim is once per session, so it can legitimately fail — a
            // second pipe for the same peer, or a session that is already gone —
            // and those must be refusals, not an ack followed by a connection
            // that silently never delivers anything.
            //
            // The claim is an exclusive lease, and the reader IS the lease:
            // dropping it returns it. So when this pipe ends — cleanly, or
            // because the client crashed and its socket died — the next pipe for
            // the same session claims successfully and resumes. Nothing is lost
            // in the gap, because units accumulate on the session's own queue
            // and never in the reader.
            //
            // Which is why the daemon caches nothing here. Holding a reader
            // across reconnects, or remembering which sessions were claimed,
            // would give the daemon a lease to release correctly and a mirror to
            // keep in step. The lease already releases itself, and the queue it
            // guards belongs to the session.
            //
            // A refusal therefore means what it says: the session is gone, or a
            // pipe for it is live right now. Neither is a lingering claim from a
            // pipe that has already died.
            //
            // An outbound pipe proves its flow before the ack for the mirror
            // reason: a client that acked and then found every unit refused
            // would have to discover from silence that its capability was wrong.
            let inbound_stream = match &bound {
                RealtimePipeBinding::Inbound { peer, .. } => match net.realtime_inbound(peer) {
                    Some(stream) => Some(stream),
                    None => {
                        let resp = Response::err(format!(
                            "no inbound realtime stream for {peer}: the session is not \
                                 current, or a live pipe already holds it — one inbound pipe \
                                 per session, and the lease returns when that pipe ends"
                        ));
                        writer
                            .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                            .await?;
                        continue;
                    }
                },
                RealtimePipeBinding::Outbound {
                    network,
                    flow_capability,
                } => {
                    if pipe_owner
                        .with_realtime_flow(flow_capability, network, |_flow| ())
                        .is_none()
                    {
                        let resp = Response::err(
                            "unknown flow_capability on this network: it was never issued \
                             to this client, or the flow it named has already been closed",
                        );
                        writer
                            .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                            .await?;
                        continue;
                    }
                    None
                }
            };
            let ack = Response::ok(serde_json::json!({ "realtime_pipe": true }));
            writer
                .write_all((serde_json::to_string(&ack)? + "\n").as_bytes())
                .await?;
            writer.flush().await?;
            // Recover the buffered reader — it may already hold the first frame.
            let pipe = async {
                match (inbound_stream, &bound) {
                    (
                        None,
                        RealtimePipeBinding::Outbound {
                            network,
                            flow_capability,
                        },
                    ) => {
                        run_realtime_outbound_pipe(
                            &net,
                            &pipe_owner,
                            flow_capability,
                            network,
                            reader,
                            state.realtime_frame_bytes,
                        )
                        .await
                    }
                    (Some(stream), RealtimePipeBinding::Inbound { peer, .. }) => {
                        run_realtime_inbound_pipe(
                            &net,
                            peer,
                            &stream,
                            reader,
                            &mut writer,
                            state.realtime_frame_bytes,
                        )
                        .await
                    }
                    // Unreachable by construction — the claim above is taken on
                    // exactly the inbound arm — and spelled as a refusal rather
                    // than a panic, because a control connection failing closed
                    // is always preferable to a daemon that stops.
                    _ => Ok(()),
                }
            };
            let result = tokio::select! {
                result = pipe => result,
                () = pipe_owner.wait_disconnected() => Ok(()),
            };
            result?;
            break;
        }
        let resp = dispatch(&state, request).await;
        let line = serde_json::to_string(&resp)? + "\n";
        writer.write_all(line.as_bytes()).await?;
    }
    Ok(())
}

async fn read_bounded_json_line<R>(reader: &mut R, ceiling: usize) -> Result<Option<String>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(bytes)
                .map(Some)
                .context("control request is not UTF-8");
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |at| at + 1);
        anyhow::ensure!(
            take <= ceiling.saturating_sub(bytes.len()),
            "control request exceeds owner-selected byte ceiling"
        );
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return String::from_utf8(bytes)
                .map(Some)
                .context("control request is not UTF-8");
        }
    }
}

/// What one realtime pipe is bound to, once its fields have been checked
/// against its direction.
///
/// The two directions carry different bindings because they are bound to
/// different things: an outbound pipe to one exact flow, an inbound pipe to one
/// session's whole unit stream. A single struct with optional fields would make
/// "which of these is authority here" a question every reader has to re-derive.
enum RealtimePipeBinding {
    /// Writes to the one flow `flow_capability` names, on the client that owns
    /// it. No peer: there is nothing left to resolve.
    Outbound {
        network: String,
        flow_capability: String,
    },
    /// Claims the whole inbound unit stream of the session `peer` currently
    /// resolves to. The claim is the authority and it is taken once.
    Inbound { network: String, peer: String },
}

/// Validate a [`Request::RealtimePipe`]'s fields against its direction.
///
/// Every field is required or refused; none is accepted and ignored. A pipe
/// that took a field and dropped it would read, from the client's side, exactly
/// like one that honoured it — and for `peer` on an outbound pipe that
/// misreading is the finding itself, a client believing its units are bound to
/// a peer when what actually binds them is a flow.
fn realtime_pipe_binding(
    direction: RealtimePipeDirection,
    network: &str,
    peer: Option<&str>,
    flow_capability: Option<&str>,
) -> std::result::Result<RealtimePipeBinding, String> {
    if network.trim().is_empty() {
        return Err("realtime_pipe requires a network".to_string());
    }
    match direction {
        RealtimePipeDirection::Outbound => {
            if peer.is_some() {
                return Err(
                    "realtime_pipe outbound takes no peer: it writes to the exact flow \
                     its flow_capability names, and a peer selector here would be \
                     re-resolved per unit — which is how a pipe outliving its session \
                     ended up writing into the replacement's flow of the same name"
                        .to_string(),
                );
            }
            let Some(flow_capability) = flow_capability else {
                return Err(
                    "realtime_pipe outbound requires a flow_capability: the value \
                     realtime_flow_open issued is the only thing that authorizes a write"
                        .to_string(),
                );
            };
            Ok(RealtimePipeBinding::Outbound {
                network: network.to_string(),
                flow_capability: flow_capability.to_string(),
            })
        }
        RealtimePipeDirection::Inbound => {
            if flow_capability.is_some() {
                return Err(
                    "realtime_pipe inbound takes no flow_capability: it claims a \
                     session's whole unit stream rather than one flow, and every unit \
                     carries the name of the flow it arrived on"
                        .to_string(),
                );
            }
            let Some(peer) = peer.filter(|peer| !peer.trim().is_empty()) else {
                return Err(
                    "realtime_pipe inbound requires a peer: the stream it claims \
                     belongs to one session"
                        .to_string(),
                );
            };
            Ok(RealtimePipeBinding::Inbound {
                network: network.to_string(),
                peer: peer.to_string(),
            })
        }
    }
}

/// Read length-prefixed units off an outbound [`Request::RealtimePipe`] and hand
/// each to the **one flow this pipe is bound to**.
///
/// Sends nothing back per unit: errors are logged rather than answered, which is
/// the whole latency win — a per-unit acknowledgement would put a round trip on
/// the media path. Returns when the client disconnects.
///
/// **Nothing here resolves a selector, and nothing here re-resolves anything.**
/// The pipe holds a flow capability, the capability names one move-only handle
/// the owning client stored at open, and that handle names one exact session and
/// one exact flow record. This is the correction: the version this replaces kept
/// `network + peer` and re-resolved them for every unit, so a pipe whose session
/// had ended went on writing until the peer's next session came up and then
/// delivered into *that* one, under labels chosen for a session that no longer
/// existed — with nothing to notice, because nothing on this path is
/// acknowledged.
///
/// The frame's `flow_label` survives as a wire coordinate and is checked, not
/// obeyed: a unit naming a different flow than this pipe is bound to is dropped
/// rather than rerouted. A client with two flows open has two pipes.
async fn run_realtime_outbound_pipe<R>(
    net: &myownmesh_core::JoinedNetwork,
    owner: &crate::ipc::ClientHandle,
    flow_capability: &str,
    network: &str,
    mut reader: R,
    frame_ceiling: usize,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    loop {
        let mut len_buf = [0u8; 4];
        // A clean EOF (the client closed the pipe) ends the loop; a short read
        // is a torn frame and ends it too — the stream is no longer framed, so
        // nothing after this point can be trusted to be a unit boundary.
        if reader.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if !realtime_frame_length_admitted(len, frame_ceiling) {
            warn!("realtime frame too large ({len} bytes) — dropping pipe");
            return Ok(());
        }
        let mut body = vec![0u8; len];
        if reader.read_exact(&mut body).await.is_err() {
            return Ok(());
        }
        let Some(unit) = decode_realtime_send_unit(&body) else {
            warn!("malformed realtime send unit ({len} bytes) — skipped");
            continue;
        };
        // Two forms of the same name, and only one of them is authority: the
        // bytes go to core, and the lossy rendering exists solely so a refusal
        // can name the flow in a log line. A label is opaque application bytes,
        // so it has no guaranteed text form and none is invented for the wire.
        let logged = label_for_log(&unit.flow_label);
        let label = unit.flow_label;
        // No marker: an outbound unit does not carry one, at any layer. The
        // marker bit states something about packetization that the flow's
        // framing policy decides and the packetizer alone is positioned to get
        // right, so a value supplied from here could only contradict it. The
        // wire byte that would have held it is reserved zero and refused
        // otherwise, which is what stops a client from believing it still has a
        // say.
        let outbound = core_webrtc::WebRtcRealtimeOutboundUnit {
            duration: std::time::Duration::from_micros(u64::from(unit.duration_us)),
            data: unit.payload.into(),
        };
        // Lent for exactly this unit and never held: the borrow ends with the
        // closure, so the daemon's stored handle stays the only one and a close
        // arriving on another connection is not racing a copy.
        //
        // Synchronous by design: the unit is authorized against the session and
        // enqueued before this returns, so a refusal is attributable to the unit
        // that caused it rather than surfacing later against an unrelated one.
        let sent = owner.with_realtime_flow(flow_capability, network, |flow| {
            // The label is compared, not resolved. It grants nothing — the flow
            // is already chosen — so a mismatch is a client naming one of its
            // own flows on the wrong pipe, which is worth telling it about and
            // is never worth guessing at.
            if flow.label() != label.as_slice() {
                return Err(None);
            }
            net.send_webrtc_realtime(flow, outbound).map_err(Some)
        });
        let Some(sent) = sent else {
            // The flow was closed while this pipe was running — by this client
            // on another connection, or by its disconnect drain. There is
            // nothing left to write to, and the pipe ends rather than idling
            // against a capability that will never resolve again.
            debug!(
                label = %logged,
                "realtime outbound pipe closing: its flow is no longer held by this client"
            );
            return Ok(());
        };
        match sent {
            Ok(()) => {}
            Err(None) => {
                debug!(
                    label = %logged,
                    "realtime unit names a different flow than this pipe is bound to — dropped"
                );
            }
            // `SessionNotCurrent` ENDS THE PIPE. Every other refusal is about
            // one unit and the next one may well succeed, but this one says the
            // session this pipe's flow belonged to is gone — and because the
            // flow handle is exact, that is now the *only* thing it can mean.
            // It can no longer be a peer that has been replaced under a name
            // this pipe kept resolving.
            //
            // Closing hands the failure to the one party that can resolve it:
            // the client sees its pipe drop, and reopening a flow forces a
            // fresh binding against whatever session is current now.
            Err(Some(refusal)) => {
                if matches!(refusal, core_realtime::RealtimeRefusal::SessionNotCurrent) {
                    warn!(
                        label = %logged,
                        code = refusal.code(),
                        "realtime outbound pipe closing: its session is no longer current"
                    );
                    return Ok(());
                }
                debug!(label = %logged, code = refusal.code(), "realtime send refused");
            }
        }
    }
}

fn realtime_frame_length_admitted(length: usize, ceiling: usize) -> bool {
    length <= ceiling
}

/// Close every realtime flow one client still owns, through the network each
/// was opened on.
///
/// Called when that client's event stream ends, however it ended. Dropping the
/// handles would be silent and wrong: a handle is non-owning by design, so
/// dropping one releases neither the label nor the transceiver or sender behind
/// it, and a client that crashed would leave both held until its session
/// happened to end.
///
/// Each flow is taken out of the client's table before its close runs, so a
/// close racing this drain reaches core at most once for a given flow.
/// Refusals are ignored rather than reported: there is nobody left to report to,
/// and every refusal this can produce means the flow was already gone.
async fn close_owned_realtime_flows(state: &ControlState, client: &crate::ipc::ClientHandle) {
    for (network, flow) in client.drain_realtime_flows() {
        let Some(net) = state.registry.get(&network) else {
            continue;
        };
        let _ = net.close_realtime(flow).await;
    }
}

/// Render a flow label for a log line, and for nothing else.
///
/// A label is opaque application bytes with no guaranteed text form, so this is
/// lossy by construction and its output must never reach the wire, a response,
/// or a lookup: two distinct labels can render identically, which is harmless in
/// a diagnostic and would be a routing bug anywhere else.
fn label_for_log(label: &[u8]) -> String {
    String::from_utf8_lossy(label).into_owned()
}

/// Push units for the bound session's inbound flows to a client's binary pipe.
///
/// One-way (daemon → client) apart from EOF, which ends the loop. Each unit goes
/// out as `[u32 len][body]`, and the body's `flow_label` — delivered alongside
/// the unit rather than looked up — names which flow it belongs to. The session
/// is already fixed by the pipe's binding, which is what lets the body stay
/// this small.
///
/// The two exits are the only two things that can happen: the client leaves, or
/// the session ends. `None` from the stream is terminal and means the latter;
/// there is no retirement flag to check and nothing to distinguish, because a
/// session that ended has taken every flow with it.
async fn run_realtime_inbound_pipe<R, W>(
    net: &myownmesh_core::JoinedNetwork,
    peer: &str,
    inbound: &core_realtime::RealtimeInboundStream,
    mut reader: R,
    writer: &mut W,
    frame_ceiling: usize,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut probe = [0u8; 1];
    loop {
        let arrival = tokio::select! {
            biased;
            // The client never writes on an inbound pipe, so any completed read
            // — a stray byte, or normally EOF — means it is gone. Biased first
            // so a departure is noticed on the same poll rather than waiting out
            // an idle session that may never produce another unit.
            _ = reader.read(&mut probe) => return Ok(()),
            arrival = net.recv_webrtc_realtime_any(inbound) => arrival,
        };
        let Some(arrival) = arrival else {
            debug!(%peer, "realtime inbound stream ended (session over)");
            return Ok(());
        };
        let admitted_len = REALTIME_FRAME_HEADER
            .checked_add(arrival.label.len())
            .and_then(|length| length.checked_add(arrival.unit.data.len()))
            .filter(|length| realtime_frame_length_admitted(*length, frame_ceiling));
        if admitted_len.is_none() {
            warn!(%peer, bytes = arrival.unit.data.len(), "realtime unit exceeds owner-selected frame ceiling — dropped");
            continue;
        }
        let unit = RealtimeRecvUnit {
            flow_label: arrival.label,
            marker: arrival.unit.marker,
            rtp_timestamp: arrival.unit.rtp_timestamp,
            payload: arrival.unit.data.to_vec(),
        };
        let Some(body) = encode_realtime_recv_unit_with_ceiling(&unit, frame_ceiling) else {
            // Larger than the framing can express. Dropped here, and the pipe
            // continues: the alternative is writing a frame whose length prefix
            // or inner length is wrong, which the client cannot interpret and
            // cannot resynchronise from — one unit it could not have used
            // becomes every unit after it. One flow's oversized unit is not a
            // reason to take down a session's whole inbound path.
            warn!(
                %peer,
                label = %label_for_log(&unit.flow_label),
                bytes = unit.payload.len(),
                "realtime unit too large to frame — dropped"
            );
            continue;
        };
        // Cannot truncate: `encode_realtime_recv_unit` returned `Some`, so the
        // body is within the owner-selected ceiling and the u32 wire length.
        let len = (body.len() as u32).to_le_bytes();
        if writer.write_all(&len).await.is_err()
            || writer.write_all(&body).await.is_err()
            || writer.flush().await.is_err()
        {
            return Ok(());
        }
    }
}

async fn dispatch(state: &Arc<ControlState>, req: Request) -> Response {
    match req {
        Request::Status => {
            let status = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "device_id": state.mesh.identity().display_id(),
                "joined_networks": state.registry.summaries()
                    .into_iter()
                    .map(|summary| summary.network_id)
                    .collect::<Vec<String>>(),
                // Always present: `supported: false` is a definite answer, and
                // an absent object would be indistinguishable from a client
                // that failed to read it.
                "realtime": state.realtime,
            });
            Response::ok(status)
        }
        Request::IdentityShow => Response::ok(serde_json::json!({
            "device_id": state.mesh.identity().display_id(),
            "pubkey": state.mesh.identity().public_id(),
            "label": state.mesh.identity().label(),
        })),
        Request::IdentitySetLabel { label } => {
            // Persist first; if the disk write fails we want the
            // in-memory copy to still reflect the on-disk reality, so
            // we don't update the live `Identity` on error.
            if let Err(e) = myownmesh_core::identity::set_label(&label) {
                return Response::err(e.to_string());
            }
            state.mesh.identity().set_label(&label);
            Response::ok(serde_json::json!({
                "device_id": state.mesh.identity().display_id(),
                "pubkey": state.mesh.identity().public_id(),
                "label": state.mesh.identity().label(),
            }))
        }
        Request::NetworksList => {
            // Enriched payload: each network includes its phase,
            // topology, and labelling info. The CLI prints whatever
            // it gets; the GUI binds rich fields directly.
            let summaries = state.registry.summaries();
            Response::ok(serde_json::json!({ "networks": summaries }))
        }
        Request::PeersList { network } => match state.registry.get(&network) {
            Some(net) => Response::ok(serde_json::json!({ "peers": net.peers() })),
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterList { network } => match state.registry.get(&network) {
            Some(net) => match net.roster_list().await {
                Ok(list) => Response::ok(serde_json::json!({ "roster": list })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterApprove {
            network,
            device_id,
            label,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .roster_approve(&device_id, label.as_deref().unwrap_or(""))
                .await
            {
                Ok(_) => Response::ok(serde_json::json!({ "approved": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterRemove { network, device_id } => match state.registry.get(&network) {
            Some(net) => match net.roster_remove(&device_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "removed": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::TopologySet {
            network,
            topology,
            hub,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => {
                    // A ratified TopologyChange owns the shape network-wide;
                    // a local set would silently fork this device off it
                    // (the engine ignores the command as a backstop — the
                    // refusal belongs here where the caller can see it).
                    if let Ok(gov) = net.governance_state().await {
                        if gov.topology.is_some() {
                            return Response::err(
                                "this network's topology is governed by a signed \
                                 owner transition — propose a change instead \
                                 (`networks topology-propose` / GovernanceProposeTopology)"
                                    .to_string(),
                            );
                        }
                    }
                    match net.set_topology(mode).await {
                        Ok(_) => Response::ok(serde_json::json!({ "topology": topology })),
                        Err(e) => Response::err(e.to_string()),
                    }
                }
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::NetworkIdGenerate => Response::ok(serde_json::json!({
            "network_id": myownmesh_core::identity::generate_network_id(),
        })),
        Request::NetworkIdNormalize { input } => {
            match myownmesh_core::identity::normalize_network_id(&input) {
                Ok(n) => Response::ok(serde_json::json!({ "network_id": n })),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::ConfigShow => match MeshConfig::load() {
            Ok(cfg) => Response::ok(serde_json::json!({ "config": cfg })),
            Err(e) => Response::err(e.to_string()),
        },
        Request::NetworkAdd { config } => {
            info!(network = %config.network_id, config_id = %config.id, "control: network_add");
            network_add(state, config).await
        }
        Request::NetworkRemove { network, purge } => {
            info!(%network, purge, "control: network_remove");
            network_remove(state, &network, purge).await
        }
        Request::ForgetAllNetworks => {
            info!("control: forget_all_networks");
            forget_all_networks(state).await
        }
        Request::FactoryReset => {
            info!("control: factory_reset");
            factory_reset(state).await
        }
        Request::NetworkUpdate { config } => {
            info!(network = %config.network_id, config_id = %config.id, "control: network_update");
            network_update(state, config).await
        }
        Request::NetworkReconnect { network, peer } => {
            info!(%network, ?peer, "control: network_reconnect");
            network_reconnect(state, &network, peer)
        }
        Request::NetworkConnectPeer {
            network,
            peer,
            pin,
            wait_ms,
        } => {
            info!(%network, %peer, pin, wait_ms, "control: network_connect_peer");
            network_connect_peer(state, &network, &peer, pin, wait_ms).await
        }

        // ---- realtime flows ----
        Request::RealtimeFlowOpen {
            network,
            peer,
            flow_label,
            direction,
            rtp_kind,
            mime,
            clock_rate,
            channels,
            client_id,
            client_capability,
        } => {
            // Authenticated before anything is opened, because the flow the
            // open produces has to be *owned*, and a flow opened for nobody
            // would have to be dropped — which releases nothing — or filed
            // under a coordinate, which is what this finding removes.
            let Some(owner) = state.clients.authenticate(client_id, &client_capability) else {
                return Response::err("invalid local client authority");
            };
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            // The name crosses as bytes; the string is only how JSON carries
            // it. Bounds are core's to enforce — an empty or over-long name is
            // refused there, in the one place that also owns the frame width it
            // is bounded by, rather than re-checked here against a copy of the
            // rule that could drift.
            let chosen = flow_label.clone();
            let open = core_webrtc::WebRtcRealtimeFlowOpen {
                label: flow_label.into_bytes(),
                direction,
                kind: rtp_kind,
                mime,
                clock_rate,
                channels,
            };
            // Synchronous: the label is claimed or refused before this returns,
            // so a client that gets `ok` may start writing units immediately and
            // one that gets a refusal knows the label is still its own to reuse.
            // Awaits: opening a flow brings its native half up with it — a
            // receive transceiver inbound, a sender and pump outbound. Still one
            // call and still all-or-nothing from here, so a refusal has released
            // both the label and the native object and leaves nothing behind.
            match net.open_webrtc_realtime(&peer, open).await {
                // The handle is stored, never returned. What the client gets is
                // the capability naming it: unguessable, minted here, and the
                // only thing that will authorize a write or a close. Core's
                // handle is move-only and not serializable, so there is nothing
                // to hand across the socket even if it were wanted.
                //
                // `flow_label` is echoed beside it because the client still
                // needs the name for its own control messages — and because it
                // is the caller's own string, so echoing cannot disagree with
                // what core holds. It authorizes nothing.
                Ok(flow) => match state.clients.install_realtime_flow(&owner, network, flow) {
                    Ok(capability) => Response::ok(serde_json::json!({
                        "flow_label": chosen,
                        "flow_capability": capability.expose(),
                    })),
                    Err(flow) => {
                        // Disconnect won the registry mutation race. This
                        // completed open was never installed, so this branch is
                        // its sole close owner.
                        let _ = net.close_realtime(flow).await;
                        Response::err("local client disconnected before realtime flow installation")
                    }
                },
                Err(refusal) => realtime_refused(refusal),
            }
        }
        Request::RealtimeFlowClose {
            client_id,
            client_capability,
            flow_capability,
        } => {
            let Some(owner) = state.clients.authenticate(client_id, &client_capability) else {
                return Response::err("invalid local client authority");
            };
            // Taken out before the close runs, and taken by value. Two
            // concurrent closes therefore cannot both reach core with the same
            // flow — the second finds nothing — and a client cannot send on a
            // flow it has asked to close, because there is no longer an entry
            // for its pipe to borrow.
            let Some((network, flow)) = owner.take_realtime_flow(&flow_capability) else {
                return Response::err(
                    "unknown flow_capability: it was never issued to this client, or the \
                     flow it named has already been closed",
                );
            };
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            // Awaits, and the wait is the guarantee. Closing retires the flow's
            // native half — a transceiver inbound, a sender outbound — and the
            // ack follows that retirement rather than the label release. So a
            // client that closes a label and immediately reopens it can rely on
            // the previous occupant being gone; acking on the release would make
            // that false in precisely the case where it matters.
            //
            // The handle is consumed here. A refusal therefore does not hand it
            // back, and that is right rather than merely convenient: every
            // refusal this can produce means the flow is already gone — its
            // session was replaced, or the label was closed with it — so
            // returning the capability would be re-issuing authority over
            // nothing.
            match net.close_realtime(flow).await {
                Ok(()) => Response::ok(serde_json::json!({ "closed": true })),
                Err(refusal) => realtime_refused(refusal),
            }
        }

        // ---- self-update ----
        Request::UpdateStatus => match myownmesh_updater::status() {
            Ok(s) => Response::ok(serde_json::to_value(s).unwrap_or(serde_json::Value::Null)),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateCheck => match myownmesh_updater::check_now(true).await {
            Ok(o) => Response::ok(serde_json::to_value(o).unwrap_or(serde_json::Value::Null)),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateApply => match myownmesh_updater::apply_now() {
            Ok(applied) => Response::ok(serde_json::json!({ "applied": applied })),
            Err(e) => Response::err(e.to_string()),
        },
        Request::UpdateSetPrefs { prefs } => {
            match serde_json::from_value::<myownmesh_updater::UpdatePrefs>(prefs) {
                Ok(p) => match myownmesh_updater::set_prefs(p) {
                    Ok(s) => {
                        Response::ok(serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
                    }
                    Err(e) => Response::err(e.to_string()),
                },
                Err(e) => Response::err(format!("bad update prefs: {e}")),
            }
        }
        Request::ServicesStatus => {
            let status = state.services.status().await;
            let config = state.services.current_config().await;
            Response::ok(serde_json::json!({ "status": status, "config": config }))
        }
        Request::ServicesSet { services } => services_set(state, services).await,
        Request::EventsSubscribe => {
            // Handled by `handle_client` before reaching dispatch.
            // If we somehow get here, surface the bug.
            Response::err("events_subscribe must be handled upstream")
        }
        Request::TraceSubscribe { .. } => {
            // Handled by `handle_client` before reaching dispatch, like
            // events_subscribe.
            Response::err("trace_subscribe must be handled upstream")
        }

        // ---- governance ----
        Request::GovernanceState { network } => match state.registry.get(&network) {
            Some(net) => match net.governance_state().await {
                Ok(s) => {
                    // The devices the signed logs have **removed** (evicted, or a
                    // member-tier revoke) — the authoritative "no longer in the
                    // fleet" set, projected from the same member log membership
                    // rides. Surfaced alongside the state so a client can prune
                    // its own local bookkeeping for a device *another* owner
                    // evicted: that eviction converges the signed roster but never
                    // touches the evicting-from-afar owner's local claimed-list,
                    // which would otherwise re-admit the device on the next
                    // re-assertion.
                    let evicted: Vec<String> = myownmesh_core::network_state::member_log_removed(
                        &s,
                        &s.member_log,
                        &network,
                    )
                    .into_iter()
                    .collect();
                    Response::ok(serde_json::json!({ "state": s, "evicted": evicted }))
                }
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeKindChange {
            network,
            to,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::KindChange { to },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeRoleGrant {
            network,
            target,
            role,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::RoleGrant { target, role },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeRoleRevoke {
            network,
            target,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::RoleRevoke { target },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeEvict {
            network,
            target,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .propose_transition(
                    myownmesh_core::TransitionVariant::Evict { target },
                    mfa_code,
                )
                .await
            {
                Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceProposeTopology {
            network,
            topology,
            hub,
            mfa_code,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => match net
                    .propose_transition(
                        myownmesh_core::TransitionVariant::TopologyChange { to: mode },
                        mfa_code,
                    )
                    .await
                {
                    Ok(id) => Response::ok(serde_json::json!({ "proposal_id": id })),
                    Err(e) => Response::err(e.to_string()),
                },
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::GovernanceSign {
            network,
            proposal_id,
            mfa_code,
        } => match state.registry.get(&network) {
            Some(net) => match net.sign_proposal(&proposal_id, mfa_code).await {
                Ok(_) => Response::ok(serde_json::json!({ "signed": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceDeny {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.deny_proposal(&proposal_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "denied": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceWithdraw {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.withdraw_proposal(&proposal_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "withdrawn": proposal_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::GovernanceSpawnSplit {
            network,
            proposal_id,
        } => match state.registry.get(&network) {
            Some(net) => match net.spawn_split(&proposal_id).await {
                Ok(new_id) => Response::ok(serde_json::json!({ "new_network_id": new_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        // ---- custody MFA (per-device, local to this daemon) ----------
        // These act on this daemon's secrets store keyed by network id; they
        // do not require the network to be live in the registry.
        Request::GovernanceMfaEnroll { network } => {
            match myownmesh_core::custody::enroll(&network, &network) {
                Ok(e) => Response::ok(serde_json::json!({
                    "secret": e.secret_b32,
                    "otpauth_uri": e.otpauth_uri,
                    "recovery_codes": e.recovery_codes,
                })),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::GovernanceMfaStatus { network } => Response::ok(serde_json::json!({
            "enrolled": myownmesh_core::custody::is_enrolled(&network),
        })),
        Request::GovernanceMfaDisable { network, code } => {
            match myownmesh_core::custody::disable(&network, &code) {
                Ok(()) => Response::ok(serde_json::json!({ "disabled": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        // ---- RPC handler claims --------------------------------------
        Request::RpcRegister {
            client_id,
            client_capability,
            network,
            method,
            streaming,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let mode = if streaming {
                crate::ipc::clients::HandlerMode::Stream
            } else {
                crate::ipc::clients::HandlerMode::Single
            };
            let key = (network.clone(), method.clone());
            let prev = state.clients.claim_method(key.clone(), client_id, mode);
            crate::ipc::bridge::install_handler_for_mode(
                &net,
                network.clone(),
                method.clone(),
                mode,
                state.clients.clone(),
            );
            if let Some(prev_owner) = prev {
                crate::ipc::bridge::notify_displaced(
                    &state.clients,
                    prev_owner,
                    client_id,
                    network,
                    method,
                );
            }
            Response::ok(serde_json::json!({ "registered": true }))
        }

        Request::RpcUnregister {
            client_id,
            client_capability,
            network,
            method,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            let key = (network, method);
            let released = state.clients.release_method(&key, client_id);
            Response::ok(serde_json::json!({ "released": released }))
        }

        // ---- inbound-RPC responses (from IPC handler back to daemon)
        Request::RpcRespond {
            client_id,
            client_capability,
            network,
            peer,
            method,
            request_id,
            operation_id,
            ok,
            error,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            let key = crate::ipc::clients::PendingKey {
                network,
                method,
                remote_peer: peer,
                remote_request_id: request_id.clone(),
                class: crate::ipc::clients::HandlerMode::Single,
            };
            let result = error.map_or_else(|| Ok(ok.unwrap_or(serde_json::Value::Null)), Err);
            let resolved =
                state
                    .clients
                    .resolve_exact_single(&key, client_id, operation_id, result);
            if resolved {
                Response::ok(serde_json::json!({ "resolved": true }))
            } else {
                Response::err(format!("no in-flight inbound RPC for '{request_id}'"))
            }
        }

        Request::RpcStreamChunk {
            client_id,
            client_capability,
            network,
            peer,
            method,
            request_id,
            operation_id,
            payload,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            let key = crate::ipc::clients::PendingKey {
                network,
                method,
                remote_peer: peer,
                remote_request_id: request_id.clone(),
                class: crate::ipc::clients::HandlerMode::Stream,
            };
            let accepted = state
                .clients
                .push_exact_stream(&key, client_id, operation_id, payload)
                .await;
            if accepted {
                Response::ok(serde_json::json!({ "delivered": true }))
            } else {
                Response::err(format!("no in-flight inbound stream for '{request_id}'"))
            }
        }

        Request::RpcStreamEnd {
            client_id,
            client_capability,
            network,
            peer,
            method,
            request_id,
            operation_id,
            error,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            // The typed terminal item preserves clean versus failed closure;
            // disappearing without either is treated as failure by core.
            let key = crate::ipc::clients::PendingKey {
                network,
                method,
                remote_peer: peer,
                remote_request_id: request_id.clone(),
                class: crate::ipc::clients::HandlerMode::Stream,
            };
            let closed = state
                .clients
                .close_exact_stream(&key, client_id, operation_id, error)
                .await;
            Response::ok(serde_json::json!({ "closed": closed }))
        }

        // ---- outbound RPC --------------------------------------------
        Request::RpcCall {
            network,
            peer,
            method,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            match net.rpc().call(&peer, &method, payload).await {
                Ok(resp) => Response::ok(serde_json::json!({ "response": resp.body })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::RpcCallStream {
            client_id,
            client_capability,
            network,
            peer,
            method,
            payload,
        } => {
            let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
                return Response::err("invalid local client authority");
            };
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            // The lib's `call_stream` allocates a request_id
            // internally but doesn't expose it; we mirror its
            // shape and tag chunks on the wire with a fresh
            // daemon-side id so the IPC client can correlate
            // its in-flight calls.
            let request_id = format!("ipc-stream-{}", state.clients.next_call_stream_id());
            let rx = match net.rpc().call_stream(&peer, &method, payload).await {
                Ok(rx) => rx,
                Err(e) => return Response::err(e.to_string()),
            };
            let writer_tx = client.writer_tx.clone();
            let stream_owner = client.clone();
            let req_id_for_task = request_id.clone();
            tokio::spawn(async move {
                let mut rx = rx;
                loop {
                    let chunk = tokio::select! {
                        () = stream_owner.wait_disconnected() => return,
                        chunk = rx.recv() => chunk,
                    };
                    let Some(chunk) = chunk else { break };
                    match chunk {
                        Ok(payload) => {
                            let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamChunk {
                                request_id: req_id_for_task.clone(),
                                payload: payload.into_value(),
                            });
                        }
                        Err(err) => {
                            let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                                request_id: req_id_for_task.clone(),
                                error: Some(err),
                            });
                            return;
                        }
                    }
                }
                let _ = writer_tx.send(crate::ipc::ServerOut::RpcCallStreamEnd {
                    request_id: req_id_for_task,
                    error: None,
                });
            });
            Response::ok(serde_json::json!({ "request_id": request_id }))
        }

        // ---- typed channels ------------------------------------------
        Request::ChannelSubscribe {
            client_id,
            client_capability,
            network,
            channel,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let key = (network.clone(), channel.clone());
            let first = state.clients.subscribe_channel(key.clone(), client_id);
            if first {
                crate::ipc::bridge::spawn_channel_pump(
                    &net,
                    network,
                    channel,
                    state.clients.clone(),
                );
            }
            Response::ok(serde_json::json!({ "subscribed": true }))
        }

        Request::ChannelUnsubscribe {
            client_id,
            client_capability,
            network,
            channel,
        } => {
            if state
                .clients
                .authenticate(client_id, &client_capability)
                .is_none()
            {
                return Response::err("invalid local client authority");
            }
            let key = (network, channel);
            state.clients.unsubscribe_channel(&key, client_id);
            // We don't actively tear the pump down — it exits
            // on its next iteration when it sees an empty
            // subscriber list. Keeps the unsubscribe synchronous
            // and free of cross-task signaling.
            Response::ok(serde_json::json!({ "unsubscribed": true }))
        }

        Request::ChannelSendTo {
            network,
            channel,
            peer,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let chan = net.channel::<serde_json::Value>(&channel);
            match chan.send_to(&peer, &payload).await {
                Ok(()) => Response::ok(serde_json::json!({ "sent": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::ChannelSendReliable {
            network,
            channel,
            peer,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            match net.send_reliable(&peer, &channel, payload).await {
                Ok(()) => Response::ok(serde_json::json!({ "delivered": true })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::ChannelSendAll {
            network,
            channel,
            payload,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            let chan = net.channel::<serde_json::Value>(&channel);
            match chan.broadcast(&payload).await {
                Ok(count) => Response::ok(serde_json::json!({ "dispatched_to": count })),
                Err(e) => Response::err(e.to_string()),
            }
        }

        Request::CapabilitiesSet {
            network,
            capabilities,
        } => {
            let Some(net) = state.registry.get(&network) else {
                return Response::err(format!("unknown network: {network}"));
            };
            net.advertise(capabilities);
            Response::ok(serde_json::json!({ "advertised": true }))
        }

        // Handled in `handle_client` (it converts the whole connection); never
        // reaches the per-request dispatcher.
        Request::RealtimePipe { .. } => Response::err("realtime_pipe must open its own connection"),
    }
}

/// Join a fresh network through the live mesh, attach signaling,
/// register the result, and persist the new config to disk. Each
/// step that mutates daemon-visible state is reversible up to the
/// last point we touch the on-disk config — config.json is updated
/// after the join + attach succeeds so a failed join leaves the
/// saved config untouched.
async fn network_add(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // Reject duplicates against the running registry. We rely on
    // the registry's two-key indexing — checking both the local
    // config id and the wire-level network id covers the user
    // trying to add the same network twice (under any alias).
    if state.registry.contains(&config.id) {
        return Response::err(format!("config id '{}' already in use", config.id));
    }
    if state.registry.contains(&config.network_id) {
        return Response::err(format!(
            "network id '{}' already joined under a different config",
            config.network_id
        ));
    }

    // Join the live mesh first — if the engine refuses (bad
    // network id, etc.) we want to know before we touch disk.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => return Response::err(format!("join: {e}")),
    };

    // Take a summary BEFORE handing ownership to the registry so we
    // can return it in the response payload without re-locking.
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "label": joined.label(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });

    // Attach the signaling driver(s) the network's config selects
    // (Nostr and/or mDNS). A `None` here means the bridge declined
    // (outbound receiver already taken, e.g. by an in-process test
    // driver); the network still works for those.
    let drivers = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_signaling(&net_state)
    };
    if drivers.is_none() {
        warn!(network = %config.network_id, "signaling attach returned no handle");
    }
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        drop(refused.drivers);
        let _ = refused.joined.shutdown().await;
        return Response::err(format!(
            "network id is held by a runtime in {refusal_state:?} state"
        ));
    }

    // Refresh the service-role advert so the new network advertises what
    // this device hosts.
    state.services.on_network_added(&config.id).await;

    // Persist to disk. We re-load the config rather than rely on
    // the in-memory copy from startup so concurrent edits (a user
    // hand-editing config.json) survive — we append to whatever's
    // on disk now. Best-effort: if save fails, the network is live
    // but won't re-join on next daemon restart. Surface the disk
    // error to the caller so the GUI can show it.
    if let Err(e) = persist_network_add(&config) {
        return Response::err(format!("network joined but config.json save failed: {e}"));
    }

    Response::ok(serde_json::json!({ "added": summary }))
}

/// Leave a live network and remove it from the on-disk config. The registry
/// owns signaling and engine teardown through completion and reports its exact
/// outcome.
/// Drop a network's persisted **governance state + roster** — the on-disk half
/// of forgetting a network. Best-effort + logged: a leave that can't delete the
/// files isn't worth failing the request over, but leaving them is precisely
/// what made a rejoin reload a stale/forked genesis, so we try.
fn purge_network_state(network_id: &str) {
    if let Err(e) = myownmesh_core::network_state::delete(network_id) {
        warn!(%network_id, "purge: network_state delete failed: {e:#}");
    }
    if let Err(e) = myownmesh_core::roster::delete(network_id) {
        warn!(%network_id, "purge: roster delete failed: {e:#}");
    }
}

async fn network_remove(state: &Arc<ControlState>, key: &str, purge: bool) -> Response {
    let key_owned = key.to_string();
    let ids = if let Some(joined) = state.registry.get(key) {
        let ids = (
            joined.config_id().to_string(),
            joined.network_id().to_string(),
        );
        joined.announce_leave().await;
        Some(ids)
    } else {
        None
    };
    match state.registry.remove(key).await {
        RemoveResult::Removed(outcome) => {
            let (config_id, network_id) =
                ids.unwrap_or_else(|| (key_owned.clone(), key_owned.clone()));
            state.services.on_network_removed(&config_id).await;
            if let Err(e) = persist_network_remove(&config_id, &network_id) {
                return Response::err(format!("network left but config.json save failed: {e}"));
            }
            if purge {
                purge_network_state(&network_id);
            }
            match outcome {
                Ok(()) => Response::ok(serde_json::json!({ "removed": config_id })),
                Err(error) => Response::err(format!(
                    "network removed but runtime teardown reported failure: {error}"
                )),
            }
        }
        RemoveResult::AlreadyClosing(runtime) => Response::err(format!(
            "network teardown already in progress ({runtime:?})"
        )),
        RemoveResult::NotFound => Response::err(format!("unknown network: {key_owned}")),
    }
}

/// Forget every joined network at once — the bulk `NetworkRemove{purge:true}`.
/// Each network is torn down live and its signed state + roster deleted from
/// disk; the device identity is kept. Snapshots the set first so removing as we
/// go can't skip an entry. Schedules a daemon exit ([`schedule_daemon_exit`]) so
/// every layer reloads clean around the wipe.
async fn forget_all_networks(state: &Arc<ControlState>) -> Response {
    let mut forgotten = Vec::new();
    for n in state.registry.summaries() {
        // `network_remove` resolves either alias; the config id is stable.
        let _ = network_remove(state, &n.config_id, true).await;
        forgotten.push(n.config_id);
    }
    schedule_daemon_exit();
    Response::ok(serde_json::json!({ "forgotten": forgotten, "restarting": true }))
}

/// Factory reset — return this device to a brand-new state. First quiesce every
/// network (tear it down + purge its files) so nothing re-persists mid-wipe,
/// then remove the whole state directory (identity, config, and any leftovers),
/// and finally exit so a fresh daemon mints a new identity on empty state. The
/// live control socket + log file descriptors stay valid until exit; the
/// supervising service, or the GUI's `ensure_daemon_running` on relaunch, brings
/// the daemon back. Best-effort per step — we always schedule the exit so a
/// partial failure still ends in a clean restart rather than a half-wiped daemon
/// re-persisting stale caches.
async fn factory_reset(state: &Arc<ControlState>) -> Response {
    // Quiesce writers first: tearing each network down stops its engine driver
    // from writing a roster/state file back out while we're deleting the tree.
    for n in state.registry.summaries() {
        let _ = network_remove(state, &n.config_id, true).await;
    }
    let dir = match myownmesh_core::dirs::data_dir() {
        Ok(d) => d,
        Err(e) => {
            // Can't find the dir to wipe — still restart so we don't leave the
            // caller hanging on a half-done reset.
            schedule_daemon_exit();
            return Response::err(format!("factory reset: resolve state dir: {e}"));
        }
    };
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        // A missing dir already reads as reset; anything else is worth logging,
        // but we still exit so caches can't resurrect what did get deleted.
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(dir = %dir.display(), "factory reset: remove_dir_all: {e:#}");
        }
    }
    schedule_daemon_exit();
    Response::ok(serde_json::json!({ "reset": true, "restarting": true }))
}

/// Exit the daemon shortly after the current response flushes, so a fresh
/// instance reloads from the now-clean disk. The reset commands use this: the
/// only reliable way to drop every in-memory cache — which would otherwise
/// re-persist and "resurrect" the state we just deleted — is a clean process
/// restart. The short delay lets the JSON response reach the client first; the
/// supervising service (Restart=always) or the GUI's `ensure_daemon_running` on
/// relaunch starts a fresh daemon.
fn schedule_daemon_exit() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        info!("reset complete — exiting so a fresh daemon reloads clean state");
        std::process::exit(0);
    });
}

/// Reconnect a joined network in place — the non-destructive twin of
/// [`network_remove`] + [`network_add`]. Hands the live `JoinedNetwork` a
/// reconnect request (redial signaling + renegotiate ICE) without leaving the
/// room, so peers keep their sessions and app-level state. `peer` omitted
/// reconnects every peer; `peer` set reconnects just that one (a per-node
/// refresh). Fire-and-forget — the engine driver runs the reconnect, so this
/// returns as soon as the request is queued.
fn network_reconnect(state: &Arc<ControlState>, key: &str, peer: Option<String>) -> Response {
    match state.registry.get(key) {
        Some(joined) => {
            joined.reconnect(peer);
            Response::ok(serde_json::json!({ "reconnecting": key }))
        }
        None => Response::err(format!("unknown network: {key}")),
    }
}

/// Deliberately dial one peer on a joined network — the control-socket wrapper
/// around [`myownmesh_core::JoinedNetwork::connect_peer`]. Single-shot: queues
/// the offerer-side dial on the engine and returns at once (the outcome rides
/// the event stream), so a daemon client on a `Silent` network can open exactly
/// one connection after matching a peer's Support ID.
async fn network_connect_peer(
    state: &Arc<ControlState>,
    key: &str,
    peer: &str,
    pin: bool,
    wait_ms: u64,
) -> Response {
    let Some(joined) = state.registry.get(key) else {
        return Response::err(format!("unknown network: {key}"));
    };
    let result = if pin || wait_ms > 0 {
        // Waited/pinned dial: resolves on ACTIVE (or the deadline). A
        // pin with no wait still uses the waiting path with a minimal
        // deadline so the sticky flag is recorded engine-side; the
        // dial itself keeps going either way.
        let deadline = std::time::Duration::from_millis(wait_ms.max(1));
        match joined.connect_peer_wait(peer, pin, deadline).await {
            Ok(()) => Ok(true),
            Err(e) if wait_ms == 0 => {
                // Caller didn't ask to wait — a deadline miss is not
                // an error, just "still connecting".
                let msg = e.to_string();
                if msg.contains("still pending") {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    } else {
        joined.connect_peer(peer).await.map(|_| false)
    };
    match result {
        Ok(active) => Response::ok(serde_json::json!({
            "connecting": peer,
            "network": key,
            "pinned": pin,
            "active": active,
        })),
        Err(e) => Response::err(e.to_string()),
    }
}

/// Update an already-joined network in place. Hot-reloadable edits
/// (topology / label / auto_approve / roster path) apply without
/// touching live sessions; transport edits (signaling / STUN / TURN /
/// network_id) tear the network down and rejoin under the new config,
/// because the ICE server set is baked into each `RTCPeerConnection`
/// when it's created — there's no way to retrofit a new TURN server
/// onto an existing connection. Either way config.json is rewritten so
/// the change survives a daemon restart.
async fn network_update(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // This is update, not add: the network must already be joined.
    let joined = match state
        .registry
        .get(&config.id)
        .or_else(|| state.registry.get(&config.network_id))
    {
        Some(j) => j,
        None => {
            return Response::err(format!(
                "unknown network '{}' — join it with network_add first",
                config.id
            ))
        }
    };

    // Compare the incoming config against the engine's live config to
    // decide hot-apply vs. transport restart.
    let net_state = joined.state();
    let (needs_restart, signaling_changed, network_id_changed) = {
        let current = net_state.config.read().clone();
        (
            myownmesh_core::engine::reconcile::requires_restart(&current, &config),
            current.signaling != config.signaling,
            current.network_id != config.network_id,
        )
    };
    // Name the path taken so a config-driven flap is greppable: a hot-apply
    // keeps every live peer; a restart drops them. Only network_id/signaling
    // force the restart now (STUN/TURN are hot — see `reconcile`).
    info!(
        network = %config.network_id,
        needs_restart,
        signaling_changed,
        network_id_changed,
        "network_update: {}",
        if needs_restart { "transport restart (drops live peers)" } else { "hot-applied in place" }
    );

    if !needs_restart {
        // STUN/TURN / topology / label / auto_approve / roster — apply in
        // place, no peers dropped. ICE servers are read fresh on the next
        // connect, so a credential rotation reaches new connections without
        // tearing down the live ones (see `reconcile::apply_hot`).
        if let Err(e) = myownmesh_core::engine::reconcile::apply_hot(&net_state, config.clone()) {
            return Response::err(format!("apply config: {e}"));
        }
        drop(net_state);
        drop(joined);
        if let Err(e) = persist_network_update(&config) {
            return Response::err(format!("config applied but config.json save failed: {e}"));
        }
        return Response::ok(serde_json::json!({ "updated": config.id, "restarted": false }));
    }

    // Transport restart path. Snapshot the live config FIRST so that if
    // the rejoin under the new config is rejected (a bad TURN URL the
    // daemon won't parse, say) we can restore the network exactly as it
    // was rather than leaving the user with nothing — the roster file
    // survives on disk regardless, but a vanished network with no
    // recovery surface is a footgun. Then release our Arc clones so the
    // registry can begin its single owned teardown.
    let old_config = net_state.config.read().clone();
    // Same graceful-departure courtesy as network_remove: peers drop our
    // session now rather than waiting out the heartbeat timeout, so the
    // rebuild under the new transport reconnects promptly instead of
    // racing the stale-session recovery path. Emitted while the signaling
    // driver is still live (before the registry remove below drops it).
    joined.announce_leave().await;
    drop(net_state);
    drop(joined);

    match state.registry.remove(&config.id).await {
        RemoveResult::Removed(Ok(())) => {}
        RemoveResult::Removed(Err(error)) => {
            return Response::err(format!("old runtime teardown failed: {error}"));
        }
        RemoveResult::AlreadyClosing(runtime) => {
            return Response::err(format!(
                "network update refused while teardown is already in progress ({runtime:?})"
            ));
        }
        RemoveResult::NotFound => {
            if let Some(runtime) = state.registry.state(&config.id) {
                return Response::err(format!(
                    "network update refused while prior runtime is {runtime:?}"
                ));
            }
        }
    }

    // Re-join under the new transport config. If the daemon rejects it,
    // roll back to the snapshot so the network (and its live session) is
    // restored instead of silently disappearing.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => {
            let rollback = match state.mesh.join(old_config).await {
                Ok(restored) => {
                    let drivers = {
                        let net_state = restored.state();
                        myownmesh_core::engine::attach_signaling(&net_state)
                    };
                    match state.registry.insert(restored, drivers).into_refusal() {
                        None => {
                            state.services.on_network_added(&config.id).await;
                            " — restored the previous config".to_string()
                        }
                        Some(refused) => {
                            let refusal_state = refused.state;
                            drop(refused.drivers);
                            let _ = refused.joined.shutdown().await;
                            format!(" — rollback join was refused by a {refusal_state:?} runtime")
                        }
                    }
                }
                Err(re) => {
                    warn!(network = %config.id, "network update rollback failed: {re:#}");
                    " — AND rollback failed; re-add it from the Networks tab".to_string()
                }
            };
            return Response::err(format!("rejoin with new config: {e}{rollback}"));
        }
    };
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "label": joined.label(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });
    let drivers = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_signaling(&net_state)
    };
    if drivers.is_none() {
        warn!(network = %config.network_id, "signaling attach returned no handle after update");
    }
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        drop(refused.drivers);
        let _ = refused.joined.shutdown().await;
        return Response::err(format!(
            "replacement runtime refused while predecessor is {refusal_state:?}"
        ));
    }

    // The old network was torn down and a fresh one registered under the
    // same id; re-run both hooks so the advert tracks the replacement.
    state.services.on_network_removed(&config.id).await;
    state.services.on_network_added(&config.id).await;

    if let Err(e) = persist_network_update(&config) {
        return Response::err(format!("network updated but config.json save failed: {e}"));
    }
    Response::ok(serde_json::json!({ "updated": summary, "restarted": true }))
}

/// Replace the device services config: persist it, then reconcile the
/// running services. Persist first so a daemon restart re-applies the
/// same config even if the live reconcile partly fails (a failed service
/// start is logged inside `apply`, not surfaced as an error here).
async fn services_set(state: &Arc<ControlState>, services: ServicesConfig) -> Response {
    // Validate against the live daemon before persistence. In particular, an
    // infrastructure-only runtime must not save node participation as enabled
    // when it has no connector resource owner capable of admitting that state.
    if let Err(e) = state.services.validate_config_for_runtime(&services) {
        return Response::err(format!("services policy rejected: {e}"));
    }
    if let Err(e) = persist_services(&services) {
        return Response::err(format!("services config save failed: {e}"));
    }
    let status = match state.services.apply(services).await {
        Ok(status) => status,
        Err(e) => return Response::err(format!("services policy rejected: {e}")),
    };
    Response::ok(serde_json::json!({ "status": status }))
}

fn persist_services(services: &ServicesConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    cfg.services = services.clone();
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_add(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    // Append only if not already present — covers the case where
    // the user edited config.json by hand between daemon start and
    // this add, and added the same network there too.
    if !cfg
        .networks
        .iter()
        .any(|n| n.id == net.id || n.network_id == net.network_id)
    {
        cfg.networks.push(net.clone());
    }
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_remove(config_id: &str, network_id: &str) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    let before = cfg.networks.len();
    cfg.networks
        .retain(|n| n.id != config_id && n.network_id != network_id);
    if cfg.networks.len() != before {
        cfg.save().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn persist_network_update(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    // Replace the matching record in place (by either alias). If it's
    // somehow absent — e.g. the user hand-deleted it between join and
    // this update — append so the on-disk config still agrees with the
    // now-running engine rather than silently dropping it.
    if let Some(slot) = cfg
        .networks
        .iter_mut()
        .find(|n| n.id == net.id || n.network_id == net.network_id)
    {
        *slot = net.clone();
    } else {
        cfg.networks.push(net.clone());
    }
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn parse_topology(name: &str, hub: Option<&str>) -> std::result::Result<TopologyMode, String> {
    match name {
        "ring" => Ok(TopologyMode::Ring { n_preferred: None }),
        "star" => {
            let hub = hub.ok_or_else(|| "star topology requires --hub <device_id>".to_string())?;
            Ok(TopologyMode::Star {
                hub: hub.to_string(),
            })
        }
        "full_mesh" | "fullmesh" => Ok(TopologyMode::FullMesh),
        "hubs" => {
            let list = hub.ok_or_else(|| {
                "hubs topology requires --hub <id[,id…][:redundancy]>".to_string()
            })?;
            let (ids, redundancy) = match list.rsplit_once(':') {
                Some((ids, r)) => (
                    ids,
                    Some(r.parse::<u32>().map_err(|_| {
                        format!("invalid spoke redundancy '{r}' — expected a number")
                    })?),
                ),
                None => (list, None),
            };
            let hubs: Vec<String> = ids
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if hubs.is_empty() {
                return Err("hubs topology requires at least one hub id".into());
            }
            Ok(TopologyMode::Hubs {
                hubs,
                spoke_redundancy: redundancy,
            })
        }
        other => Err(format!(
            "unknown topology '{other}' — expected ring | star | hubs | full_mesh"
        )),
    }
}

/// Stream events to one connected subscriber. Drains two
/// sources concurrently:
///
/// 1. The mesh-wide [`MeshHandle::events`] broadcast — peer /
///    phase / diag entries the engine emits.
/// 2. The per-client mpsc — `ServerOut` frames the IPC bridge
///    (RPC inbound, channel inbound, handler-displaced
///    notifications) pushes for this specific client.
///
/// Returns when the writer breaks (client gone) or both source
/// streams close. Source 1 closes only on daemon shutdown;
/// source 2 closes when the client's `unregister` drops the
/// last sender, which the caller invokes after this function
/// returns.
async fn run_events_stream<W>(
    state: &Arc<ControlState>,
    writer: &mut W,
    mut client_rx: tokio::sync::mpsc::UnboundedReceiver<crate::ipc::ServerOut>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut mesh_rx = state.mesh.events();
    loop {
        tokio::select! {
            biased;
            // Per-client frames first — drains IPC-routed
            // RpcInbound / ChannelInbound / etc.
            maybe_frame = client_rx.recv() => {
                let Some(frame) = maybe_frame else {
                    // Sender dropped — only happens after the
                    // outer handle_client called `unregister`,
                    // which only fires after this returns. In
                    // practice this branch never fires while
                    // the connection is live; treat as benign
                    // shutdown.
                    return Ok(());
                };
                let line = serde_json::to_string(&frame)? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            recv = mesh_rx.recv() => match recv {
                Ok(event) => {
                    let frame = crate::ipc::ServerOut::Event { event };
                    let line = serde_json::to_string(&frame)? + "\n";
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                    if writer.flush().await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let frame = crate::ipc::ServerOut::Lagged { skipped: n };
                    let line = serde_json::to_string(&frame)? + "\n";
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        }
    }
}

/// Stream one network's connection-state transitions to a connected
/// `ctl trace` client. Writes each [`myownmesh_core::ConnTrace`] as a
/// compact JSON object on its own line (clean JSONL for
/// `scripts/merge-traces.py` and `jq`). On broadcast lag — a
/// transition storm outran a slow reader — emits a `{"lagged":N}`
/// marker rather than silently skipping, so a gap in the timeline is
/// always explicit. Returns when the client disconnects or the network
/// shuts down.
async fn run_trace_stream<W>(
    writer: &mut W,
    mut rx: broadcast::Receiver<myownmesh_core::ConnTrace>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        match rx.recv().await {
            Ok(trace) => {
                let line = serde_json::to_string(&trace)? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let line = serde_json::to_string(&serde_json::json!({ "lagged": n }))? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Single shared `MeshHandle` storage for the ctl client. Mostly a
/// future-proofing hook so a follow-up can attach per-network
/// state without changing the protocol.
#[allow(dead_code)]
static CTL_STATE: Mutex<Option<Arc<ControlState>>> = parking_lot::const_mutex(None);

// ---- binary realtime pipe frame codec ---------------------------------------
//
// The frames a [`Request::RealtimePipe`] connection carries. Each frame on the
// wire is `[u32 len LE][body]`; `body` is what these encode and parse.
// Round-trip tested below.
//
// This codec is defined here and answers to nothing outside this crate. An
// earlier version of this comment instructed maintainers to keep it
// byte-for-byte identical to a client application's codec, which had it exactly
// backwards — a client's encoder is a consumer of this format, not its
// specification — and was in any case untrue, since that layout leads with a
// kind byte this one does not have. Clients are held to this wire; it is not
// held to theirs.

/// Defensive cap on one frame body — a corrupt length never allocates more.
#[cfg(test)]
const TEST_REALTIME_FRAME_CEILING: usize = 64 * 1024 * 1024;

/// Fixed prefix width of a realtime frame body, identical in both directions:
/// the label's length, a one-byte slot, a four-byte slot, and the payload
/// length. The label's bytes and then the payload's follow it, in that order.
///
/// Both slots are named by direction rather than here, because both mean
/// different things each way: the one-byte slot is the marker inbound and
/// reserved zero outbound, and the four-byte slot is an absolute timestamp
/// inbound and a duration outbound. Equal width is what lets the two encoders be
/// read against each other; it is not a shared meaning.
///
/// The leading byte is a *length*, not a label. A label is opaque bytes chosen
/// by the application, so it cannot be a fixed-width field, and length-prefixing
/// it with one byte is what makes [`MAX_REALTIME_FLOW_LABEL_BYTES`] 255 —
/// the bound is the field's width, not a policy. Both variable-length runs are
/// counted, so a body's total width is fully determined by its prefix, and a
/// body whose bytes disagree with its own prefix is refused rather than
/// resolved.
const REALTIME_FRAME_HEADER: usize = 1 + 1 + 4 + 4;

/// The longest label the frame above can carry, and therefore the longest core
/// will accept.
///
/// Re-exported rather than restated. The bound is a representation fact about
/// the single length byte in this frame, and the frame encoder here, the
/// provider edge that refuses an over-long open, and the name constructor in the
/// connector all have to agree on it — so there is one constant, in the basal
/// vocabulary, and this is a second spelling of that one value rather than a
/// second value.
pub use myownmesh_core::realtime::MAX_REALTIME_FLOW_LABEL_BYTES;

/// One unit read off an **outbound** pipe, on its way to a flow.
///
/// The pipe is bound to a session, so the body carries no network, peer, or
/// codec — only which flow of that session, and what the connector needs to
/// pace it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeSendUnit {
    /// The flow's opaque name, exactly as the application chose it. Never
    /// parsed, ordered, or ranged over here; it is carried to core, which
    /// resolves it by equality against one session's own table. Empty is
    /// refused rather than accepted as a degenerate name, so the binary and
    /// JSON paths cannot disagree about what an absent label means.
    pub flow_label: Vec<u8>,
    /// Presentation duration of this unit. Paces the flow clock on the way
    /// out; it is *not* a timestamp, and deliberately does not share a type
    /// with one.
    pub duration_us: u32,
    pub payload: Vec<u8>,
}

// There is no `marker` on an outbound unit, and the byte that would hold it is
// reserved zero on the wire.
//
// It was never the application's to set. Under `AnnexB` framing the app hands
// over whole access units and the transport library sets the RTP marker on the
// last packet of each — the unit boundary IS the marker, so a field here would
// be an input nothing reads. Keeping it would have been an invitation to set it
// and to reason about what it did.
//
// The byte stays so both directions keep one header width, which is what lets
// the two encoders be reviewed against each other. It is reserved rather than
// free: a sender that writes anything but zero is refused, because a nonzero
// value there means either a client that believes it is setting something or a
// body from an encoder whose second byte means something else.

/// One unit written to an **inbound** pipe, as received from a flow.
///
/// Deliberately a distinct type from [`RealtimeSendUnit`] even though the two
/// bodies are the same width. The 4-byte slot means different things in each
/// direction — a duration going out, an absolute timestamp coming in — and one
/// shared `timestamp` field would let a value from one direction be used as
/// the other with nothing to catch it. The layout is shared; the meaning is
/// not, so the types are not either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeRecvUnit {
    /// The flow's opaque name, as core reported it on arrival. A copy of the
    /// bytes, not a handle: it grants nothing and outlives nothing.
    pub flow_label: Vec<u8>,
    pub marker: bool,
    /// Absolute, at the flow's declared `clock_rate`. Uninterpretable without
    /// it, which is why that is a field on the flow rather than a codec detail.
    pub rtp_timestamp: u32,
    pub payload: Vec<u8>,
}

/// Parse an outbound unit body (the bytes after the `u32` length prefix).
///
/// Returns `None` on any truncation or a payload length that disagrees with
/// the frame — a malformed frame is dropped, never panics, and never trusts a
/// length it did not check against the bytes actually present.
pub fn decode_realtime_send_unit(body: &[u8]) -> Option<RealtimeSendUnit> {
    let header = body.get(..REALTIME_FRAME_HEADER)?;
    let label_len = header[0] as usize;
    // Zero is refused rather than read as "no label". A flow is always named,
    // and a body that named nothing could only be resolved by guessing which
    // flow it meant.
    if label_len == 0 {
        return None;
    }
    let payload_len = u32::from_le_bytes(header[6..10].try_into().ok()?) as usize;
    // Byte 1 is reserved and must be zero. Every other value is refused, which
    // is the strongest check available at this offset: the encoders
    // neighbouring this one put a stream index, a payload type or a keyframe
    // flag here, and those are usually nonzero, so a body that arrived from the
    // wrong encoder fails on its second byte rather than being interpreted.
    //
    // It also refuses a client that writes a marker it believes in. Nothing
    // downstream would read it, and accepting the byte would let that belief
    // survive indefinitely without ever being contradicted.
    if header[1] != 0 {
        return None;
    }
    // The two counted runs must account for the body exactly. Not `>=`: a body
    // longer than its own prefix describes is as malformed as a short one, and
    // accepting the excess would let a trailing tail ride along unread. This is
    // also the check a one-byte-shifted body from a neighbouring encoder cannot
    // survive, which is why it is arithmetic on both lengths rather than a
    // bounds test on one.
    let rest = body.get(REALTIME_FRAME_HEADER..)?;
    if rest.len() != label_len.checked_add(payload_len)? {
        return None;
    }
    let (label, payload) = rest.split_at(label_len);
    Some(RealtimeSendUnit {
        flow_label: label.to_vec(),
        duration_us: u32::from_le_bytes(header[2..6].try_into().ok()?),
        payload: payload.to_vec(),
    })
}

/// Serialize an inbound unit body (no length prefix).
///
/// Layout, integers little-endian:
/// `label_len u8 · marker u8 · rtp_timestamp u32 · payload_len u32 · label… ·
/// payload…`
///
/// Both lengths are redundant with the frame's own `u32` prefix and both are
/// kept anyway, because the redundancy is the check. Every neighbouring encoder
/// in the tree starts with a `kind u8` this one does not have, so a sender that
/// reaches for the wrong one produces a body shifted by exactly one byte —
/// where `label_len` reads a kind, `marker` reads a stream index, and every
/// field is plausible. The two counted runs are what cannot survive that shift:
/// they must account for the body exactly, and a shifted body's do not. Five
/// bytes a unit is cheap for turning a silent misinterpretation into a refusal.
///
/// See `a_neighbouring_encoders_frame_is_refused_not_reinterpreted`.
pub fn encode_realtime_recv_unit_with_ceiling(
    unit: &RealtimeRecvUnit,
    frame_ceiling: usize,
) -> Option<Vec<u8>> {
    // Every check happens before anything is allocated, and every one is
    // checked rather than cast. `payload.len() as u32` would truncate a payload
    // past 4 GiB and produce a body whose inner length disagreed with its own
    // contents — the exact malformation the decoder on the other side refuses,
    // manufactured by us. A frame that cannot be encoded correctly must not be
    // half-encoded.
    //
    // The label bound is the same rule the decoder enforces, applied here so a
    // name that could not be framed is never half-written: empty is refused,
    // and so is anything the one-byte length prefix could not count.
    if unit.flow_label.is_empty() || unit.flow_label.len() > MAX_REALTIME_FLOW_LABEL_BYTES {
        return None;
    }
    let label_len = u8::try_from(unit.flow_label.len()).ok()?;
    let payload_len = u32::try_from(unit.payload.len()).ok()?;
    let total = REALTIME_FRAME_HEADER
        .checked_add(unit.flow_label.len())?
        .checked_add(unit.payload.len())?;
    if total > frame_ceiling || total > u32::MAX as usize {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.push(label_len);
    out.push(unit.marker as u8);
    out.extend_from_slice(&unit.rtp_timestamp.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&unit.flow_label);
    out.extend_from_slice(&unit.payload);
    Some(out)
}

#[cfg(test)]
fn encode_realtime_recv_unit(unit: &RealtimeRecvUnit) -> Option<Vec<u8>> {
    encode_realtime_recv_unit_with_ceiling(unit, TEST_REALTIME_FRAME_CEILING)
}

#[cfg(test)]
mod realtime_control_tests {
    use super::*;

    /// Kept as a wire literal rather than a Rust variant, because what this
    /// control proves is that the *operation* is gone from the socket — not
    /// merely that a variant was renamed. A client still sending base64 units
    /// must be refused outright; there is no compatibility arm to catch it.
    const LEGACY_VIDEO_SEND: &str = r#"{
        "op":"video_send",
        "network":"test-network",
        "peer":"test-peer",
        "stream":0,
        "duration_us":1,
        "data":"AA=="
    }"#;

    #[test]
    fn base64_unit_operations_are_gone_from_the_wire() {
        assert!(
            serde_json::from_str::<Request>(LEGACY_VIDEO_SEND).is_err(),
            "video_send carried units as base64 over the reliable JSON path and \
             has no successor: the binary pipe is the only media path"
        );
    }

    /// A label of two or more bytes, used everywhere a fixture needs one.
    ///
    /// Deliberately not one byte. A single-byte label makes the length prefix
    /// and the label indistinguishable in width, so a body built by hand would
    /// pass several of the checks below by coincidence — the shift control in
    /// particular would stop testing what it exists to test. It is also not
    /// valid UTF-8, because the binary path carries bytes and must not quietly
    /// acquire a text assumption from the JSON path that happens to sit beside
    /// it.
    const LABEL: &[u8] = &[b's', b'c', b'r', 0xff];

    /// A pipe is refused unless it is bound to the thing its direction is
    /// actually bound to — a flow outbound, a session inbound.
    ///
    /// Parsing and binding are separate steps here, and the assertions follow
    /// that split rather than blurring it: `network` is the only field the
    /// request type itself requires, because everything else is
    /// direction-dependent and a serde-level `Option` cannot express "required
    /// for one variant of a sibling field". The direction-dependent rules are
    /// [`realtime_pipe_binding`]'s, and are asserted against it.
    ///
    /// The outbound case is the finding: a pipe that accepted a `peer` would be
    /// carrying a selector it re-resolves per unit, which is how a pipe whose
    /// session had ended went on writing into the replacement's flow of the
    /// same name.
    #[test]
    fn a_realtime_pipe_will_not_parse_without_its_session() {
        let unbound = r#"{"op":"realtime_pipe","direction":"outbound"}"#;
        assert!(
            serde_json::from_str::<Request>(unbound).is_err(),
            "a pipe with no network names nothing to operate through"
        );

        assert!(
            realtime_pipe_binding(RealtimePipeDirection::Outbound, "home", None, Some("cap"))
                .is_ok(),
            "non-vacuity: an outbound pipe bound to a flow capability is accepted"
        );
        assert!(
            realtime_pipe_binding(
                RealtimePipeDirection::Outbound,
                "home",
                Some("peerpub"),
                Some("cap"),
            )
            .is_err(),
            "an outbound pipe must not carry a peer: that selector is what gets \
             re-resolved into a replacement session"
        );
        assert!(
            realtime_pipe_binding(RealtimePipeDirection::Outbound, "home", None, None).is_err(),
            "and it must carry the capability, which is the only thing that \
             authorizes a write"
        );

        assert!(
            realtime_pipe_binding(
                RealtimePipeDirection::Inbound,
                "home",
                Some("peerpub"),
                None
            )
            .is_ok(),
            "non-vacuity: an inbound pipe bound to a session is accepted"
        );
        assert!(
            realtime_pipe_binding(RealtimePipeDirection::Inbound, "home", None, None).is_err(),
            "an inbound pipe claims one session's stream and must name it"
        );
        assert!(
            realtime_pipe_binding(
                RealtimePipeDirection::Inbound,
                "home",
                Some("peerpub"),
                Some("cap"),
            )
            .is_err(),
            "and it is bound to a session rather than a flow, so a flow \
             capability here is refused rather than ignored"
        );
    }

    /// A frame from a *neighbouring* encoder must be refused, never reinterpreted.
    ///
    /// The hazard is structural rather than particular to any one client. A
    /// layout of `kind u8 · stream u8 · key u8 · timestamp u32 · len u32 ·
    /// payload` — our fixed prefix behind one extra leading byte — is a shape
    /// encoders in this problem space converge on, and a sender that reaches for
    /// one produces a body shifted by exactly one byte where every field stays
    /// plausible: `label_len` reads a kind (1 or 2, both perfectly good label
    /// lengths), the reserved byte reads a stream index, and the u32 slots read
    /// a keyframe flag glued to three bytes of timestamp and then a length
    /// glued to a byte of its own.
    ///
    /// Nothing is acknowledged per unit, so if this were interpreted rather than
    /// refused the failure would be one hundred percent of media going nowhere
    /// with no signal on the sending side. The two counted runs are what make
    /// that impossible: `label_len + payload_len` must account for the body
    /// exactly, and a shifted body's cannot.
    #[test]
    fn a_neighbouring_encoders_frame_is_refused_not_reinterpreted() {
        let payload = [7u8, 7, 7, 7, 7, 7];
        // The shifted layout: our prefix plus one leading `kind` byte.
        //
        // `kind` is 1 and `stream` is 0, and neither choice is incidental.
        // After the shift `kind` lands in `label_len`, so it must be nonzero or
        // the empty-label check rejects the body before the arithmetic runs;
        // `stream` lands in the reserved byte, which accepts only zero, so a
        // nonzero stream index would be refused there instead. Both are the
        // commonest values a real sender writes, and both are chosen here so the
        // body reaches the one check this control exists to prove.
        let mut foreign = Vec::new();
        foreign.push(1u8); // kind
        foreign.push(0u8); // stream
        foreign.push(1u8); // key
        foreign.extend_from_slice(&90_000u32.to_le_bytes()); // timestamp
        foreign.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        foreign.extend_from_slice(&payload);

        assert_eq!(
            foreign.len(),
            REALTIME_FRAME_HEADER + 1 + payload.len(),
            "the foreign body is our prefix plus exactly one leading byte — if \
             this ever stops holding, the shift this test protects against has \
             changed shape and the assertion below is no longer testing it"
        );
        assert!(
            decode_realtime_send_unit(&foreign).is_none(),
            "a one-byte-shifted body must be refused: with the reserved byte \
             zeroed and the label length nonzero, the counted-run arithmetic is \
             the only thing standing between it and silently misrouted media"
        );
        // Non-vacuity, both halves. Neither cheap check may be what rejected
        // this body, or the control would keep passing after the arithmetic it
        // exists to protect was deleted.
        assert_ne!(
            foreign[0], 0,
            "the shifted body must reach the length arithmetic, not stop at the \
             empty-label check"
        );
        assert_eq!(
            foreign[1], 0,
            "the shifted body must reach the length arithmetic, not stop at the \
             reserved byte"
        );
        // And the arithmetic really is what disagrees: the shifted body claims
        // one label byte plus six payload bytes, and carries eleven after the
        // prefix.
        let shifted_claim = foreign[0] as usize
            + u32::from_le_bytes(foreign[6..10].try_into().expect("ten bytes present")) as usize;
        assert_ne!(
            shifted_claim,
            foreign.len() - REALTIME_FRAME_HEADER,
            "if a shifted body's counted runs ever add up, this control proves \
             nothing and the layout must be reconsidered"
        );
    }

    /// Local copy of the client's writer, so the round-trip is asserted
    /// against the exact layout the client produces rather than against our
    /// own decoder's assumptions.
    ///
    /// `reserved` is a raw byte rather than a `bool`, because the field it
    /// occupies is reserved zero and the interesting cases are the values a
    /// correct client never writes. `label_len` is taken separately from
    /// `label` so a fixture can state a length its bytes do not back, which is
    /// the malformation the decoder has to refuse.
    fn encode_send_unit_parts(
        label_len: u8,
        label: &[u8],
        reserved: u8,
        duration_us: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(REALTIME_FRAME_HEADER + label.len() + payload.len());
        out.push(label_len);
        out.push(reserved);
        out.extend_from_slice(&duration_us.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(payload);
        out
    }

    /// The well-formed case: the stated length is the label's own.
    fn encode_send_unit(label: &[u8], reserved: u8, duration_us: u32, payload: &[u8]) -> Vec<u8> {
        encode_send_unit_parts(
            u8::try_from(label.len()).expect("a fixture label is within the prefix width"),
            label,
            reserved,
            duration_us,
            payload,
        )
    }

    #[test]
    fn send_units_round_trip_without_naming_a_codec() {
        let body = encode_send_unit(LABEL, 0, 33_333, &[1, 2, 3, 9]);
        let unit = decode_realtime_send_unit(&body).expect("decode");
        // Exact opaque bytes, not a rendering of them: the label is four bytes
        // and the last is not valid UTF-8, so anything that went through a
        // string on the way here would come back changed.
        assert_eq!(unit.flow_label, LABEL.to_vec());
        assert_eq!(unit.duration_us, 33_333);
        assert_eq!(unit.payload, vec![1, 2, 3, 9]);

        // An empty payload is a legitimate unit, and the same decode path. An
        // empty *label* is not — see `a_frame_naming_no_flow_is_refused`.
        let empty = decode_realtime_send_unit(&encode_send_unit(LABEL, 0, 20_000, &[]))
            .expect("decode empty");
        assert!(empty.payload.is_empty());
        assert_eq!(empty.flow_label, LABEL.to_vec());

        // The longest label the prefix can count still round-trips whole.
        let longest = vec![0xab; MAX_REALTIME_FLOW_LABEL_BYTES];
        let long = decode_realtime_send_unit(&encode_send_unit(&longest, 0, 1, &[4]))
            .expect("a 255-byte label is within the prefix width");
        assert_eq!(long.flow_label, longest);
    }

    /// A body that names no flow is refused rather than read as naming none.
    ///
    /// Zero is the one label length that would otherwise decode into something
    /// — a unit with an empty name, which core could only resolve by guessing.
    /// Refusing it here is also what keeps the binary path and the JSON path
    /// agreeing: neither has a spelling for "a flow with no name".
    #[test]
    fn a_frame_naming_no_flow_is_refused() {
        let body = encode_send_unit_parts(0, &[], 0, 1, &[7, 7, 7]);
        assert!(
            decode_realtime_send_unit(&body).is_none(),
            "a zero-length label must be refused, not read as an absent one"
        );
        // Non-vacuity: with a real label of the same shape the body decodes, so
        // it is the zero that was rejected and not the rest of the frame.
        let ok = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        assert!(decode_realtime_send_unit(&ok).is_some());
    }

    #[test]
    fn truncation_is_none_not_panic() {
        let body = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        for cut in 0..body.len() {
            assert!(
                decode_realtime_send_unit(&body[..cut]).is_none(),
                "short {cut}"
            );
        }
    }

    /// The two counted runs are redundant with the frame's own prefix, which is
    /// exactly why a disagreement between them must be refused rather than
    /// resolved: silently trusting any one of them lets a corrupt frame hand a
    /// truncated or over-long payload — or a label sliced out of a payload — to
    /// a decoder as if it were whole.
    #[test]
    fn a_length_that_disagrees_with_the_frame_is_refused() {
        // A payload length larger than the bytes present.
        let mut body = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        body[6] = 9;
        assert!(decode_realtime_send_unit(&body).is_none());

        // A body longer than its own counted runs describe. The excess is not
        // ignored: accepting it would let a trailing tail ride along unread.
        let mut over = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        over.push(0);
        assert!(decode_realtime_send_unit(&over).is_none());

        // A label length longer than the label actually written. Every field
        // after the prefix stays plausible — the decoder would simply take
        // payload bytes as name bytes — so only the total can catch it.
        let overlong_label = encode_send_unit_parts(
            u8::try_from(LABEL.len() + 1).expect("fits"),
            LABEL,
            0,
            1,
            &[7, 7, 7],
        );
        assert!(
            decode_realtime_send_unit(&overlong_label).is_none(),
            "a label length its bytes do not back must be refused, not filled \
             from the payload"
        );

        // And shorter, which would otherwise silently rename the flow and
        // prepend the leftover byte to its payload.
        let short_label = encode_send_unit_parts(
            u8::try_from(LABEL.len() - 1).expect("fits"),
            LABEL,
            0,
            1,
            &[7, 7, 7],
        );
        assert!(
            decode_realtime_send_unit(&short_label).is_none(),
            "a label length shorter than its bytes must be refused, not read as \
             a different flow"
        );
    }

    /// Byte 1 of an outbound body is reserved: zero decodes, everything else is
    /// refused.
    ///
    /// Not pedantry about an unused field. The byte is the one position where a
    /// body from a neighbouring encoder differs most reliably — a stream index,
    /// a payload type or a keyframe flag lands here after the one-byte shift,
    /// and those are usually nonzero. Requiring zero turns that offset into a
    /// check rather than a place to store a value nothing reads.
    ///
    /// It also refuses a client that writes a marker it believes in. Under
    /// `AnnexB` framing the transport library sets the RTP marker from the unit
    /// boundary, so an application-supplied one was never an input; accepting
    /// the byte would let that belief survive without ever being contradicted.
    #[test]
    fn a_nonzero_reserved_byte_is_refused() {
        let ok = encode_send_unit(LABEL, 0, 1, &[7]);
        let unit = decode_realtime_send_unit(&ok).expect("a zeroed reserved byte decodes");
        assert_eq!(unit.flow_label, LABEL.to_vec());
        assert_eq!(unit.payload, vec![7]);

        // Every nonzero value, not a sample. 1 is the important one — it is
        // what a client that still thinks it is sending a marker would write,
        // and the value most likely to be waved through by a `!= 0` reading.
        for byte in 1u8..=255 {
            let body = encode_send_unit(LABEL, byte, 1, &[7]);
            assert!(
                decode_realtime_send_unit(&body).is_none(),
                "reserved byte {byte} must be refused"
            );
        }
    }

    /// A unit too large to frame yields `None` rather than a malformed body.
    ///
    /// The failure this prevents is not the loss of one unit. An encoder that
    /// cast the length would write an inner length disagreeing with its own
    /// contents — precisely what the decoder at the far end refuses — so the
    /// client could neither use that frame nor resynchronise after it, and one
    /// unusable unit would cost every unit behind it.
    #[test]
    fn a_unit_too_large_to_frame_is_not_half_encoded() {
        let ok = encode_realtime_recv_unit(&RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: true,
            rtp_timestamp: 90_000,
            payload: vec![1, 2, 3],
        })
        .expect("an ordinary unit encodes");
        assert_eq!(ok.len(), REALTIME_FRAME_HEADER + LABEL.len() + 3);

        // One byte past what the framing may carry. The label counts toward the
        // ceiling too, which is why it is subtracted here: a bound that only
        // considered the payload would emit bodies a byte over. Allocated rather
        // than faked, so the bound under test is the real one.
        let headroom = TEST_REALTIME_FRAME_CEILING - REALTIME_FRAME_HEADER - LABEL.len();
        let oversize = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![0u8; headroom + 1],
        };
        assert!(
            encode_realtime_recv_unit(&oversize).is_none(),
            "a body over the selected frame ceiling must not be encoded at all"
        );

        // The largest unit that still fits is accepted — the check is a ceiling,
        // not an off-by-one that also rejects the boundary.
        let exact = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![0u8; headroom],
        };
        assert_eq!(
            encode_realtime_recv_unit(&exact).map(|body| body.len()),
            Some(TEST_REALTIME_FRAME_CEILING)
        );
    }

    /// A label the framing cannot express is refused outright, not truncated.
    ///
    /// Both ends of the rule, because both are reachable: an empty name would
    /// produce a body the decoder must refuse, and a name past the one-byte
    /// prefix would have its length silently wrapped into a different, valid
    /// number — which is worse than a dropped unit, since it names a real flow
    /// that is not this one.
    #[test]
    fn a_label_the_frame_cannot_carry_is_not_half_encoded() {
        let unnamed = RealtimeRecvUnit {
            flow_label: Vec::new(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&unnamed).is_none());

        let overlong = RealtimeRecvUnit {
            flow_label: vec![b'x'; MAX_REALTIME_FLOW_LABEL_BYTES + 1],
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&overlong).is_none());

        // The boundary itself encodes, so the rule is a ceiling and not an
        // off-by-one that also rejects the longest usable name.
        let longest = RealtimeRecvUnit {
            flow_label: vec![b'x'; MAX_REALTIME_FLOW_LABEL_BYTES],
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&longest).is_some());
    }

    /// The `network_connect_peer` op is what a daemon-client embedder sends to
    /// dial one peer on a Silent network. Pin its wire tag + shape: it must
    /// decode from the exact JSON a client writes, and round-trip.
    #[test]
    fn network_connect_peer_request_round_trips() {
        let json = r#"{"op":"network_connect_peer","network":"test-network","peer":"peerpubkey"}"#;
        let req: Request = serde_json::from_str(json).expect("decode network_connect_peer");
        match &req {
            Request::NetworkConnectPeer {
                network,
                peer,
                pin,
                wait_ms,
            } => {
                assert_eq!(network, "test-network");
                assert_eq!(peer, "peerpubkey");
                // Wire-additive: an old client's op decodes with the
                // defaults — no pin, no wait.
                assert!(!pin);
                assert_eq!(*wait_ms, 0);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // The `op` tag is the load-bearing discriminator; pin it on re-encode.
        let value = serde_json::to_value(&req).expect("encode");
        assert_eq!(value["op"], "network_connect_peer");
        assert_eq!(value["peer"], "peerpubkey");
        let back: Request = serde_json::from_value(value).expect("re-decode");
        assert!(matches!(back, Request::NetworkConnectPeer { .. }));
    }

    /// Pins the exact bytes, because this body is shared with the
    /// applications' decoder: a silent layout change here desynchronises the
    /// two ends rather than failing a build. Note there is no peer and no
    /// codec on the wire — the pipe's session binding supplies the first and
    /// the flow's declared encoding the second.
    #[test]
    fn recv_unit_layout_is_pinned() {
        let body = encode_realtime_recv_unit(&RealtimeRecvUnit {
            flow_label: vec![b'a', b'b', 0xff],
            marker: true,
            rtp_timestamp: 0x0001_0203,
            payload: vec![9, 8],
        })
        .expect("a two-byte payload is within the frame ceiling");
        assert_eq!(
            body,
            vec![
                3, // label_len
                1, // marker
                0x03, 0x02, 0x01, 0x00, // rtp_timestamp LE
                2, 0, 0, 0, // payload len LE
                b'a', b'b', 0xff, // label, verbatim and not text
                9, 8, // payload
            ]
        );
    }

    /// Demonstrates the hazard the type split exists to remove: the two
    /// directions share a body width, so an inbound unit's bytes can parse as an
    /// outbound one, with the absolute timestamp landing silently in the
    /// duration field. That is exactly why `RealtimeSendUnit` and
    /// `RealtimeRecvUnit` are distinct types with distinct functions, so the
    /// compiler catches what the bytes cannot. If they are ever merged back into
    /// one type with a shared `timestamp`, this misreading becomes expressible
    /// in ordinary code.
    ///
    /// The reserved outbound byte narrows this without closing it. An inbound
    /// unit carrying a real marker has 1 where an outbound body must have 0, so
    /// that half is now caught — which is a side benefit of the reserved rule
    /// and not a reason to rely on it. Unmarked units are the ordinary case,
    /// and they still cross undetected, as the second half of this asserts.
    #[test]
    fn wire_bytes_alone_cannot_distinguish_the_two_directions() {
        // A marked inbound unit is now refused: its marker byte is 1 where the
        // outbound reserved byte must be 0.
        let marked = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: true,
            rtp_timestamp: 90_000,
            payload: vec![1],
        };
        let marked_body = encode_realtime_recv_unit(&marked).expect("encodes");
        assert!(
            decode_realtime_send_unit(&marked_body).is_none(),
            "the reserved byte catches a marked inbound unit read as outbound"
        );

        // An unmarked one still crosses silently, which is the case the type
        // split has to cover, because no byte distinguishes it.
        let recv = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 90_000,
            payload: vec![1],
        };
        let body = encode_realtime_recv_unit(&recv).expect("a one-byte payload encodes");
        let decoded = decode_realtime_send_unit(&body).expect("same width, so the bytes parse");
        assert_eq!(decoded.flow_label, recv.flow_label);
        assert_eq!(
            decoded.duration_us, recv.rtp_timestamp,
            "a 90 kHz timestamp read as a 90-millisecond duration, undetectably"
        );
    }

    #[tokio::test]
    async fn json_reader_refuses_before_crossing_selected_ceiling() {
        let input = b"123456789\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let error = read_bounded_json_line(&mut reader, 8)
            .await
            .expect_err("nine bytes exceed eight");
        assert!(error.to_string().contains("owner-selected byte ceiling"));
    }

    #[tokio::test]
    async fn json_reader_accepts_exact_ceiling_without_hidden_slack() {
        let input = b"12345678\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        assert_eq!(
            read_bounded_json_line(&mut reader, 9).await.unwrap(),
            Some("12345678".into())
        );
    }

    #[test]
    fn realtime_length_refusal_is_checked_before_body_allocation() {
        assert!(realtime_frame_length_admitted(8, 8));
        assert!(!realtime_frame_length_admitted(9, 8));
    }

    #[cfg(unix)]
    #[test]
    fn unix_control_endpoint_is_verified_as_exact_owner_only_socket() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let directory = tempfile::tempdir().expect("temporary control directory");
        let path = directory.path().join("control.sock");
        let listener = bind_listener(&SocketTarget::Path(path.clone())).expect("bind control");
        let metadata = std::fs::symlink_metadata(&path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o777, 0o600);
        drop(listener);
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_dacl_names_current_token_user_not_owner_rights() {
        let sddl = current_user_pipe_sddl()
            .expect("current user DACL")
            .to_string_lossy();
        assert!(sddl.starts_with("D:P(A;;GA;;;S-1-"));
        assert!(!sddl.contains(";;;OW)"));
    }
}
