//! MyOwnMesh — peer-to-peer mesh networking runtime.
//!
//! `myownmesh-core` is the only crate embedding apps need to depend on.
//! It exposes everything from identity through the connection engine
//! and the high-level [`Mesh`] / [`MeshHandle`] / [`JoinedNetwork`]
//! facade.
//!
//! # Quick tour
//!
//! ```no_run
//! # async fn _ex(connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy) -> Result<(), Box<dyn std::error::Error>> {
//! use myownmesh_core::{Mesh, MeshConfig, NetworkConfig, TopologyMode};
//!
//! // The process owner supplies the reviewed connector policy explicitly.
//! let mesh = Mesh::open_connector_capable(
//!     MeshConfig::default(),
//!     connector_policy,
//! ).await?;
//! println!("device id: {}", mesh.identity().display_id());
//!
//! // Join a named network. Returns a per-network handle.
//! let net = mesh.join(NetworkConfig {
//!     id: "home".into(),
//!     network_id: "my-mesh".into(),
//!     label: "Home".into(),
//!     kind: Default::default(),                            // Open (default)
//!     topology: TopologyMode::default(),
//!     signaling: Default::default(),
//!     stun_servers: Default::default(),
//!     turn_servers: Default::default(),
//!     roster_path: None,
//!     pinned_peers: Vec::new(),
//!     auto_approve: false,
//! }).await?;
//!
//! // Attach a signaling driver.
//! let _nostr = myownmesh_core::engine::attach_nostr(&net.state());
//!
//! // Subscribe to events.
//! let mut events = mesh.events();
//! while let Ok(event) = events.recv().await {
//!     println!("{event:?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What's in this crate
//!
//! - [`Identity`] — long-lived ed25519 device identity persisted at
//!   `~/.myownmesh/.secrets/identity.json` (mode 0600 on Unix). The
//!   public key is the Device ID surfaced on the wire.
//! - [`Roster`] — per-network list of approved peer Device IDs.
//!   Reconnects from rostered peers auto-allow without re-prompting
//!   the user.
//! - [`protocol`] — wire format: `hello` / `auth_response` / `approve`
//!   / `deny` / `ping` / `pong` / `shelve` / `unshelve` /
//!   `capabilities_update` / generic RPC frames. See `docs/PROTOCOL.md`.
//! - [`topology`] selectors — Ring (default), Star, FullMesh.
//! - [`transport`] — webrtc-rs wrapper; one [`PeerSession`](transport::PeerSession)
//!   per peer with an event mpsc the engine drains.
//! - [`engine`] — connection engine: hello state machine, heartbeat,
//!   recovery from reliable transport signals (in-place ICE restart
//!   confirmed by inbound traffic, clean rebuild on failure), topology
//!   shelving. See `CONNECTION-ENGINE-FIELD-NOTES.md`.
//! - [`Channel<T>`] — typed publish/subscribe between peers.
//! - [`Rpc`] — generic request/response with streaming.
//!
//! # Trust model
//!
//! Each device owns a long-lived ed25519 keypair. Both sides send a
//! `hello` carrying an independently drawn 32-byte contribution; the
//! `auth_response` is an ed25519 signature over the endpoint-auth
//! transcript, whose fields are length-prefixed under
//! `ENDPOINT_AUTH_DOMAIN_TAG`: the mesh context, the fixed crypto
//! profile, the signer's role, both device IDs, both contributions, and
//! both endpoints' DTLS certificate fingerprints — every paired field
//! in role-canonical order, so the two sides derive identical bytes.
//! Each side verifies its own half as well as the peer's, so a proof is
//! mutual rather than one-directional.
//!
//! Domain separation prevents a signature obtained for one protocol step
//! from being replayed in another. Binding both fingerprints ties the
//! proven identity to *this* transport, so a man-in-the-middle on the
//! (unauthenticated) signaling path can't relay the handshake across two
//! DTLS legs it terminates — it would have to present its own
//! certificate to each leg.
//!
//! A certificate fingerprint is **not** a session-unique exporter,
//! though: two channels between the same pair reusing the same
//! certificates carry the same value. Replay across channels is
//! prevented by the per-attempt contributions, and transfer of an
//! already-issued capability is prevented by connector-incarnation
//! ownership — not by the fingerprints.
//!
//! This is a hard cutover. The legacy `SIGN_DOMAIN_TAG` handshake
//! payload is neither produced nor accepted on the live path, and there
//! is no feature-negotiated fallback: an older peer fails authentication
//! rather than negotiating down, so a downgrade is not attacker-selectable.
//!
//! A user-visible 6-char verification code lets a human
//! eyeball-confirm the handshake over voice/video at first-meeting
//! time; thereafter the peer's pubkey is in the roster and
//! auto-approved on reconnect.
//!
//! # Where to look next
//!
//! - `docs/QUICKSTART.md` — the narrative walkthrough.
//! - `docs/PROTOCOL.md` — every wire frame.
//! - `CONNECTION-ENGINE-FIELD-NOTES.md`: every retained tunable and edge case.
//! - `examples/` — runnable demos
//!   (`cargo run --example two_peer_chat -p myownmesh-core`,
//!   `echo_rpc`, `roster_demo`).
//! - `tests/two_peer_handshake.rs` — the end-to-end integration
//!   test doubles as an executable spec.

pub mod application_gateway;
pub mod channels;
pub mod config;
pub mod connector;
pub mod custody;
pub mod dirs;
pub mod endpoint_auth;
pub mod engine;
pub mod error;
pub mod events;
pub mod handle;
pub mod identity;
#[cfg(feature = "legacy-v1")]
pub mod legacy_v1;
pub mod network_state;
pub(crate) mod persist;
pub mod protocol;
pub mod resource;
pub mod roster;
pub mod rpc;
pub mod runtime;
pub mod services;
pub mod signing;
pub mod topology;
pub mod transport;
pub mod verification;

pub use channels::{Channel, ChannelError, ChannelMessage};
pub use config::{
    AutoUpdateConfig, MeshConfig, NetworkConfig, NodeServiceConfig, RelayServiceConfig,
    ServicesConfig, SignalingLimits, SignalingServerConfig, StunServer, StunServiceConfig,
    TopologyMode, TurnCredential, TurnServer, TurnServiceConfig,
};
pub use engine::conn_trace::ConnTrace;
pub use engine::ladder::ConnectionTier;
pub use error::{Error, Result};
pub use events::{DiagEntry, DiagLevel, MeshEvent, MeshPhase, PeerEvent};
pub use handle::{JoinedNetwork, Mesh, MeshHandle, PeerInfo};
pub use identity::{generate_network_id, normalize_network_id, DeviceId, Identity};
pub use network_state::{
    NetworkKind, NetworkState, Proposal, Role, SplitRecord, Transition, TransitionVariant,
    SIGN_DOMAIN_TAG_STATE,
};
pub use protocol::CapabilityAdvert;
pub use resource::{
    FiniteResourceProvider, ProcessResourceRoot, ReclaimResult, ResourceAuthorityClass,
    ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourcePressure,
    ResourceProvider, ResourceProviderAuthority, ResourceProviderConflict, ResourceProviderPort,
    ResourceReservationState, ResourceScope, ResourceScopeId, ResourceUnavailable,
    RESOURCE_CLASS_COUNT,
};
pub use roster::{AuthorizedPeer, Roster};
pub use rpc::{Rpc, RpcCall, RpcError, RpcResponse};
pub use runtime::attempt::{
    connector_resource_structural_claims, ConnectorCallbackMailboxCapacities,
    ConnectorCallbackPolicy, ConnectorCallbackPolicyError, ConnectorCallbackServiceWeights,
    ConnectorRealtimeByteBudgets, ConnectorRealtimeFlowCapacities, ConnectorRealtimeFlowPolicy,
    ConnectorRealtimeInboundLimits, ConnectorResourceOwnerPort, ConnectorResourceOwnerReport,
    ConnectorResourceStructuralClaims, EnabledRealtimeConnectorPolicy, MeshConnectorResourceReport,
    MeshConnectorResourceScopeIssueError, RealtimeConnectorPolicy, RealtimeQueueOverflowRule,
    WebRtcConnectorCapablePolicy,
};
pub use services::{ServiceAdvert, ServiceRole};
pub use topology::Topology;
#[cfg(feature = "transport-lab")]
pub use transport::{
    transport_lab_connector_fixture_grant, transport_lab_remote_candidate_fixture_grant,
    transport_lab_remote_description_fixture_grant,
};
#[cfg(feature = "legacy-media")]
#[allow(
    deprecated,
    reason = "these are the explicit deprecated legacy-media compatibility exports"
)]
pub use transport::{LegacyWebRtcMediaProfile, LegacyWebRtcMediaProfileError};
pub use transport::{
    PendingRemoteCandidatePolicy, WebRtcConnectorProfile, WebRtcConnectorProfileError,
};

/// Domain-separation tag prefixed to every signed handshake payload.
/// A signature obtained for one protocol step cannot be replayed in
/// another (e.g. a different version of MyOwnMesh, or any other product
/// that signs ed25519 challenges).
pub const SIGN_DOMAIN_TAG: &str = "myownmesh-mesh-auth-v1:";

/// App-id used to derive the Trystero room handle. Two MyOwnMesh peers
/// with the same `network_id` and the same app-id meet in the same
/// signaling room; peers with mismatching app-ids never see each
/// other. Overridable via the `MYOWNMESH_TRYSTERO_APP_ID` env var so
/// downstream forks can isolate their fleet.
pub const TRYSTERO_APP_ID: &str = "myownmesh-cloud-mesh-v1";

/// Wire-protocol version. Stays at 1 across additive changes (new
/// optional fields, new message kinds); a v1 receiver getting an
/// unknown message kind silently drops it. Bump only when an existing
/// message's wire shape changes incompatibly — finer-grained
/// capability negotiation happens in [`protocol::features`].
pub const PROTOCOL_VERSION: u32 = 1;
