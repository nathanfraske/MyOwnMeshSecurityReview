//! Config schema for `~/.myownmesh/config.json`. Reading & writing
//! lives here so any caller (binary, library embedder, tests) shares
//! the same parse / default behavior.
//!
//! Schema versioning uses one exact hard-alpha `version` field. This build
//! refuses any other version rather than migrating or guessing compatibility.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::DeviceId;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};

/// Flood-protection limits for the self-hosted signaling relay. Defined
/// in the signaling crate (its natural home) and re-used here so the
/// config, the daemon, and the relay all share one shape.
pub use myownmesh_signaling::server::Limits as SignalingLimits;

pub const CONFIG_VERSION: u32 = 2;

/// Topology selector for a single network. Wire-form matches the
/// JSON-tagged shape; embedders construct these directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TopologyMode {
    /// A *shaped* auto-healing ring with `n_preferred` neighbors (2
    /// immediate + (n-2) shortcuts; missing/null defaults to 3): each
    /// node dials only the union of the two sides' preferred sets,
    /// both-sides-shelved non-edges are closed, and broadcasts flood
    /// hop-by-hop with per-node dedup (see
    /// [`crate::topology::Topology::edge`]). This shapes the
    /// signaling/control fabric only — a media session dials its pair
    /// directly, on demand, regardless of mode.
    Ring {
        #[serde(default)]
        n_preferred: Option<u32>,
    },
    /// All spokes connect to a single, config-named hub — and only the
    /// hub. Spoke↔spoke frames route through it.
    Star { hub: DeviceId },
    /// A hub *tier*: the named hubs hold a full mesh among themselves,
    /// and every other member (spoke) connects to `spoke_redundancy`
    /// of them, assigned by rendezvous hashing so the mapping is
    /// deterministic on every node and stable as hubs come and go.
    /// Spoke↔spoke frames route spoke → hub (→ hub) → spoke. This is
    /// the hierarchical hub-and-spoke shape: per-spoke connection
    /// count is O(redundancy), per-hub O(spokes/hubs + hubs), and
    /// nobody pays N².
    Hubs {
        hubs: Vec<DeviceId>,
        /// How many hubs each spoke maintains a connection to
        /// (default [`TopologyMode::DEFAULT_SPOKE_REDUNDANCY`],
        /// clamped to the hub count). 1 is minimal; 2 keeps every
        /// spoke reachable through a single hub restart.
        #[serde(default)]
        spoke_redundancy: Option<u32>,
    },
    /// Full mesh — every pair connects and stays connected. The
    /// default, and the truthful name for what every pre-0.2.34
    /// network ran (the old "ring" only shelved app frames; it never
    /// shaped connections). N² cost — fine for small fleets; pick
    /// [`TopologyMode::Ring`] or [`TopologyMode::Hubs`] deliberately
    /// when a network outgrows it.
    FullMesh,
}

// `FullMesh` carries no data, so Default is derivable — but keeping it
// explicit documents that the default is a *decision* (the truthful
// name for pre-0.2.34 behavior), not an accident of variant order.
#[allow(clippy::derivable_impls)]
impl Default for TopologyMode {
    fn default() -> Self {
        TopologyMode::FullMesh
    }
}

impl TopologyMode {
    /// The default `n_preferred` for ring topology (2 immediate +
    /// 1 shortcut). Used when a Ring config omits the field.
    pub const DEFAULT_RING_N_PREFERRED: u32 = 3;

    /// Default hub count each spoke connects to under
    /// [`TopologyMode::Hubs`] — two, so one hub restarting doesn't
    /// strand its spokes.
    pub const DEFAULT_SPOKE_REDUNDANCY: u32 = 2;

    /// Resolve the effective `n_preferred` for a Ring topology,
    /// substituting the default when the field is None. Other
    /// topology modes return 0 — they don't use this value.
    pub fn effective_n_preferred(&self) -> u32 {
        match self {
            TopologyMode::Ring { n_preferred } => {
                n_preferred.unwrap_or(Self::DEFAULT_RING_N_PREFERRED)
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StunServer {
    pub urls: Vec<String>,
}

/// Built-in STUN URL applied when a deserialized `NetworkConfig` omits
/// `stun_servers`. Points at the project's reference STUN so NAT
/// reflexion works out of the box. STUN is the same program too — a
/// `myownmesh` host running `services.turn` answers STUN on the same
/// port — so run your own and point `stun_servers` at it. Opt out
/// entirely with an explicit empty array (`"stun_servers": []`);
/// `default_stun_servers` only fires when the field is absent.
pub const DEFAULT_NETWORK_STUN: &[&str] = &["stun:stun.myownmesh.com:3478"];

/// Build the default STUN server list. Exposed so embedders that
/// construct `NetworkConfig` programmatically can call
/// `default_stun_servers()` instead of repeating the URL list.
pub fn default_stun_servers() -> Vec<StunServer> {
    vec![StunServer {
        urls: DEFAULT_NETWORK_STUN
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }]
}

/// Build the default TURN server list. Relays media/data when no direct
/// path exists (symmetric NAT, CGNAT, locked-down hotspots). Points at
/// the project's reference TURN with a shared guest credential so it
/// works out of the box. That relay is bandwidth-capped per connection,
/// so for sustained throughput run your own — `services.turn` on any
/// `myownmesh` host — and point `turn_servers` at it. Opt out with an
/// explicit empty array (`"turn_servers": []`).
pub fn default_turn_servers() -> Vec<TurnServer> {
    vec![TurnServer {
        urls: vec!["turn:turn.myownmesh.com:3478".to_string()],
        username: Some("guest".to_string()),
        credential: Some("theguestpassword".to_string()),
    }]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnServer {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    /// TURN servers use the loose "credential" field name rather than
    /// "password" — keep parity with the RTC ICE config shape so
    /// users copy-pasting from Cloudflare/Metered.ca dashboards see
    /// the field name they expect.
    #[serde(default)]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignalingConfig {
    /// Which *remote* signaling strategy to use: `"nostr"` (default,
    /// relay-based) or `"none"` (no remote signaling at all — pair
    /// with `mdns` for a LAN-only network). Sibling crates can add
    /// others (BitTorrent trackers, MQTT, IPFS, Firebase) and the
    /// engine picks via this field. An unknown value attaches NO
    /// remote driver, loudly — never a silent Nostr fallback, so a
    /// privacy-motivated strategy can't quietly leak presence onto
    /// public relays.
    pub strategy: String,
    /// LAN-local mDNS/DNS-SD signaling, running alongside whatever
    /// `strategy` selects. On by default: co-located peers discover
    /// each other and exchange SDP over the local network, so a mesh
    /// keeps forming/healing even when every relay or venue is
    /// unreachable. Set `false` to stay silent on the local network.
    /// The mDNS driver ignores the relay-oriented fields below
    /// (`servers`, `redundancy`, `denylist`, `public_fallback`).
    pub mdns: bool,
    /// Explicit relay URLs. Empty = use the built-in deterministic
    /// top-N defaults filtered by the denylist.
    pub servers: Vec<String>,
    /// How many relays to keep connected at once. Default 5 — five
    /// independent forwarders are enough that no single relay can
    /// censor or stall the room, while keeping the per-peer
    /// bandwidth tax tolerable.
    pub redundancy: u32,
    /// Hostnames we never connect to even if they'd be picked by the
    /// deterministic shuffle. Used to skip relays known to rate-limit
    /// us, drop our REQs, or otherwise misbehave. Hostname-only
    /// (no scheme); match is case-insensitive.
    pub denylist: Vec<String>,
    /// Fall back to the built-in public relays when every configured /
    /// primary relay (your own and the reference one) is unreachable. On
    /// by default. The fallback is reactive — public relays are only
    /// connected while the primary set is down, and dropped again the
    /// moment one recovers — so steady state never touches public
    /// infrastructure. Set `false` to stay strictly on your own relays.
    pub public_fallback: bool,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            strategy: "nostr".to_string(),
            mdns: true,
            servers: Vec::new(),
            redundancy: DEFAULT_SIGNALING_REDUNDANCY,
            denylist: default_signaling_denylist(),
            public_fallback: true,
        }
    }
}

/// Default number of signaling relays to maintain concurrent
/// connections to. Five is the proven sweet spot from MyOwnLLM:
/// fewer means a single relay's outage can stall handshake; more
/// adds per-peer announce bandwidth without improving recovery time.
pub const DEFAULT_SIGNALING_REDUNDANCY: u32 = 5;

/// Hostnames excluded from the default relay shuffle. Known to
/// rate-limit or stall our REQs in field testing.
pub fn default_signaling_denylist() -> Vec<String> {
    vec!["relay.damus.io".to_string(), "chorus.pjv.me".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    /// Local config record id. User-chosen, unique within this
    /// device's config — distinguishes multiple saved entries for
    /// the same wire-level network (different STUN/TURN setups for
    /// the same fleet, etc.).
    pub id: String,
    /// Wire-level rendezvous handle. Normalised via
    /// [`crate::identity::normalize_network_id`] on load.
    pub network_id: String,
    /// Cosmetic display name. Empty falls back to `network_id`.
    #[serde(default)]
    pub label: String,
    /// Initial governance kind for this network. Open is the
    /// default. Closed sets up
    /// the per-network signed state log so the founder
    /// self-elects as `Owner` on first attach. Silent is Open
    /// governance plus two connection-behaviour changes — no
    /// auto-dial on presence (co-present peers surface as `Sighted`
    /// without a WebRTC session until an explicit `connect_peer` or
    /// an inbound offer) and no roster gossip — for a shared open
    /// mesh where every connection is deliberate.
    ///
    /// At runtime, the *authoritative* kind is the one in the
    /// signed [`crate::NetworkState`] log; this field is only the
    /// initial value used to bootstrap the log on first attach.
    /// Subsequent kind changes happen via signed transitions, not
    /// by editing config.json.
    #[serde(default)]
    pub kind: crate::network_state::NetworkKind,
    #[serde(default)]
    pub topology: TopologyMode,
    #[serde(default)]
    pub signaling: SignalingConfig,
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<StunServer>,
    /// TURN servers. Defaults to the project's reference TURN (shared
    /// guest credential, bandwidth-capped) so symmetric-NAT / CGNAT
    /// peers connect out of the box; run your own and point this at it
    /// for dedicated capacity. Opt out with an explicit empty array
    /// (`"turn_servers": []`) — `default_turn_servers` only fires when
    /// the field is absent. The engine surfaces an `ice-failed-no-turn`
    /// diagnostic if a topology needs TURN and none is reachable.
    #[serde(default = "default_turn_servers")]
    pub turn_servers: Vec<TurnServer>,
    /// Override the on-disk roster path. Null = use the default
    /// (`~/.myownmesh/mesh/rosters/{network_id}.json`).
    #[serde(default)]
    pub roster_path: Option<PathBuf>,
    /// Peers this node maintains a standing dial for. On a `Silent`
    /// network these are the one exception to "nothing connects until a
    /// deliberate dial": a pinned peer is (re)dialed whenever it
    /// announces, and its reconnect intent never expires — the shape a
    /// standing remote-support session needs. Populated by
    /// `connect_peer(…, sticky)` at runtime and persisted with the
    /// config so pins survive daemon restarts.
    #[serde(default)]
    pub pinned_peers: Vec<String>,
    /// When true, every authenticating peer is added to the roster
    /// automatically without user approval. Useful for headless
    /// fleet members; off by default.
    #[serde(default)]
    pub auto_approve: bool,
}

impl NetworkConfig {
    /// Build a config from just the wire-level network id, filling every
    /// other field with its default (reference STUN/TURN, open
    /// governance, default topology, no roster override, manual
    /// approval). The local `id` defaults to the network id. This backs
    /// `myownmesh ctl networks join <network_id>`, which only takes an
    /// id; richer setups go through config.json or the GUI.
    pub fn from_network_id(id: impl Into<String>, network_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            network_id: network_id.into(),
            label: String::new(),
            kind: Default::default(),
            topology: Default::default(),
            signaling: Default::default(),
            stun_servers: default_stun_servers(),
            turn_servers: default_turn_servers(),
            roster_path: None,
            pinned_peers: Vec::new(),
            auto_approve: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AutoUpdateConfig {
    pub enabled: bool,
    /// `"stable"` or `"beta"`. Beta channel pulls pre-releases; stable
    /// only takes the latest released version.
    pub channel: String,
    /// `"patch"` | `"minor"` | `"all"` | `"none"`. Controls which
    /// version bumps the updater applies without confirmation. While the
    /// project is in fast-moving alpha the default is `"all"` — every
    /// device should ride the latest release rather than stall a few
    /// versions back. The narrower policies stay selectable (and become
    /// the sensible default once the wire format settles); `"none"`
    /// stages updates but waits for an explicit "apply".
    pub auto_apply: String,
    pub check_interval_hours: u32,
    /// Override the release feed URL. Null = use the build-time
    /// `MYOWNMESH_RELEASE_URL_STABLE` env-var default.
    pub stable_url: Option<String>,
    pub beta_url: Option<String>,
}

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channel: "stable".to_string(),
            // Alpha default: take every release. See the field doc.
            auto_apply: "all".to_string(),
            check_interval_hours: 6,
            stable_url: None,
            beta_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AutoCleanupConfig {
    pub updates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub enabled: bool,
    /// Unix-domain socket path for `myownmesh ctl …` to reach the
    /// running daemon. Null = derive default
    /// (`~/.myownmesh/daemon.sock` on Unix; named pipe on Windows).
    pub control_socket: Option<PathBuf>,
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            control_socket: None,
            log_level: "info".to_string(),
        }
    }
}

/// Default WebSocket port for the self-hosted signaling relay.
/// Arbitrary high port outside the privileged range so the daemon can
/// bind it without root.
pub const DEFAULT_SIGNALING_SERVER_PORT: u16 = 4848;

/// Default UDP port for the self-hosted STUN / TURN service. 3478 is
/// the IANA-assigned STUN/TURN port (RFC 5389 / RFC 5766) — peers
/// configuring `stun:` / `turn:` URLs expect it by default.
pub const DEFAULT_STUN_TURN_PORT: u16 = 3478;

/// How this device offers infrastructure services to the rest of the
/// mesh. Device-level rather than per-network: a STUN / TURN / signaling
/// server serves every network this device participates in (and any
/// external ICE / Nostr client), so the toggles live on the device
/// config, not on an individual [`NetworkConfig`].
///
/// Everything is off by default. Turning a device into an always-on
/// signaling, STUN, or TURN host is an explicit opt-in. When a
/// service is enabled the daemon advertises the matching
/// [`crate::services::ServiceRole`] to peers so the rest of the mesh can
/// discover and adopt it, which is what makes a fully self-hosted,
/// internet-isolated network trivial to stand up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ServicesConfig {
    /// Whether this device participates as a regular mesh node. On by
    /// default; turn off for a pure-infrastructure box.
    pub node: NodeServiceConfig,
    pub signaling: SignalingServerConfig,
    pub stun: StunServiceConfig,
    pub turn: TurnServiceConfig,
}

/// Whether this device acts as a regular mesh node and joins its
/// configured networks and participates as a peer. Enabled by default;
/// disable it to run a **pure-infrastructure box** that only hosts
/// signaling / STUN / TURN (advertising itself purely as an edge /
/// ingress-egress point) without joining any network itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NodeServiceConfig {
    pub enabled: bool,
}

impl Default for NodeServiceConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Self-hosted signaling server: a minimal Nostr-compatible relay
/// (NIP-01 over WebSocket) that mesh peers can use in place of the
/// public Nostr relay pool. Point a network's `signaling.servers` at
/// `ws://this-host:port` and it interoperates with the built-in driver
/// with zero client changes — the same wire format the driver already
/// speaks to public relays.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignalingServerConfig {
    pub enabled: bool,
    /// Interface to bind. `0.0.0.0` listens on every interface;
    /// `127.0.0.1` keeps it loopback-only.
    pub bind: String,
    pub port: u16,
    /// Flood-protection limits (per-connection rates, per-IP connection
    /// caps, subscription / message-size caps). Safe defaults; loosen for
    /// a busy public relay, tighten for a locked-down private one.
    pub limits: SignalingLimits,
}

impl Default for SignalingServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: DEFAULT_SIGNALING_SERVER_PORT,
            limits: SignalingLimits::default(),
        }
    }
}

/// Self-hosted STUN server. Answers RFC 5389 Binding requests so peers
/// can discover their server-reflexive address without depending on a
/// public STUN provider. Pure reflexion — no auth, no allocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StunServiceConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}

impl Default for StunServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: DEFAULT_STUN_TURN_PORT,
        }
    }
}

/// Self-hosted TURN server (RFC 5766) for relaying media / data when no
/// direct path can be found (symmetric NAT — common on phone hotspots).
/// A TURN server also answers STUN Binding requests, so enabling TURN
/// gives STUN for free on the same port; run the standalone STUN service
/// only when you want reflexion without allocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TurnServiceConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    /// Public IP the server hands out in relay allocations. TURN can't
    /// guess its own routable address, so off-LAN clients need this set
    /// explicitly. Empty falls back to the bind address — only correct
    /// when the device already holds a public IP on the bound interface.
    pub public_ip: String,
    /// Authentication realm advertised to clients. Cosmetic but must
    /// match what peers put in their TURN URL credentials.
    pub realm: String,
    /// Static long-term credentials the server accepts. Mirror an entry
    /// into each peer's `turn_servers` config so they can allocate.
    pub credentials: Vec<TurnCredential>,
    /// Per-connection (per-allocation) relayed-bandwidth cap in bytes per
    /// second, applied independently to each direction. `0` = unlimited.
    /// A global QoS knob so one client can't saturate the relay — there's
    /// no per-user override yet, this cap applies to every allocation.
    pub max_bps_per_connection: u64,
    /// Optional fixed UDP port window the server allocates relay sockets
    /// from. `:port` above is only the control channel; every relayed
    /// allocation flows through a separate UDP port, and **all of those
    /// must be open at your firewall AND your cloud provider's security
    /// group**. Default `0` = **unbounded**: relay sockets use the OS
    /// ephemeral range (so you open that whole range — Linux:
    /// `sysctl net.ipv4.ip_local_port_range`), which never artificially
    /// caps the relay. Set both to pin a smaller, predictable window
    /// (e.g. `49152`–`65535`) and open only that. `relay_port_min == 0`
    /// means unbounded regardless of `relay_port_max`.
    pub relay_port_min: u16,
    pub relay_port_max: u16,
}

impl Default for TurnServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: DEFAULT_STUN_TURN_PORT,
            public_ip: String::new(),
            realm: "myownmesh".to_string(),
            // Ship the same shared credential the *client* default uses
            // (see `default_turn_servers`) so an enabled TURN server
            // accepts the default clients out of the box — "network in a
            // box". Deliberately NOT a secret: it's bandwidth-capped via
            // `max_bps_per_connection`, and anyone can read it, so set
            // your own before relying on it for sustained throughput.
            // Must stay in sync with `default_turn_servers`.
            credentials: vec![TurnCredential {
                username: "guest".to_string(),
                password: "theguestpassword".to_string(),
            }],
            max_bps_per_connection: 0,
            // 0 = unbounded: use the OS ephemeral range so a public relay
            // is never artificially capped out of the box (open udp 3478 +
            // that range at the firewall). Operators who want a smaller
            // firewall surface pin relay_port_min/max to a fixed window.
            relay_port_min: 0,
            relay_port_max: 0,
        }
    }
}

/// One username / password pair the TURN server accepts. Plaintext in
/// config.json — the file is already 0600-adjacent (lives in
/// `~/.myownmesh`), and long-term TURN credentials are low-value shared
/// secrets, not device identity keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnCredential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MeshConfig {
    pub version: u32,
    /// Override the identity anchor file path. Null = use the default
    /// (`~/.myownmesh/.secrets/identity.json`).
    pub identity_path: Option<PathBuf>,
    pub auto_update: AutoUpdateConfig,
    pub auto_cleanup: AutoCleanupConfig,
    pub daemon: DaemonConfig,
    /// Infrastructure services this device hosts for the mesh
    /// (relay / signaling / STUN / TURN). All off by default.
    pub services: ServicesConfig,
    pub networks: Vec<NetworkConfig>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            identity_path: None,
            auto_update: AutoUpdateConfig::default(),
            auto_cleanup: AutoCleanupConfig::default(),
            daemon: DaemonConfig::default(),
            services: ServicesConfig::default(),
            networks: Vec::new(),
        }
    }
}

fn require_current_version(cfg: MeshConfig) -> Result<MeshConfig> {
    if cfg.version != CONFIG_VERSION {
        return Err(Error::Config(format!(
            "config version {} is not the current hard-alpha version {}",
            cfg.version, CONFIG_VERSION
        )));
    }
    Ok(cfg)
}

/// A conservative upper bound on the bytes one **defaulted** config occupies,
/// both as an owned value's heap and as normalized JSON.
///
/// **A planning floor, not a measurement, and that is the point.** Missing
/// fields expand to default constructors, so an input's own length prices
/// nothing about what it becomes: `{}` is two bytes and parses to a complete
/// config with every sub-struct present. A ceiling derived only from input
/// length would therefore underfund exactly the smallest inputs. This floor is
/// added to every plan so that every absent field is paid for whether or not it
/// appeared in the file.
///
/// Not computed at runtime, because a planning figure has to exist before
/// anything is read, parsed or constructed. Held honest by
/// `the_planning_floor_covers_a_defaulted_config`, which serializes the real
/// default and fails if it ever grows past this.
///
/// **This is the root floor only.** It prices the top-level structs that a
/// completely empty document expands into. It does *not* bound repeated
/// elements — see [`CONFIG_EXPANSION_BYTES_PER_SOURCE_BYTE`], which is what
/// covers those.
const DEFAULT_CONFIG_PLANNING_FLOOR_BYTES: usize = 4096;

/// How many normalized bytes one source byte is allowed to become.
///
/// **A single root floor is not a ceiling, and this is why.** `networks` is an
/// array, and each `NetworkConfig` element omitting `stun_servers`,
/// `turn_servers`, `signaling` and `topology` expands into all four defaults.
/// The expansion is therefore *per element*, so a document of many minimal
/// `{"id":…,"network_id":…}` entries accumulates it linearly and will pass any
/// fixed global figure once there are enough of them. Bounding it needs a term
/// that grows with the input, which this is.
///
/// The bound is sound because every element costs input bytes too: an element
/// cannot appear without its two required fields, so the worst achievable ratio
/// is one element's default expansion divided by the smallest input that can
/// produce it. This constant sits comfortably above that ratio rather than at
/// it — a planning figure that is merely *exactly* right today becomes wrong
/// the first time a defaulted field is added, and being short is the one
/// direction it must never be.
///
/// Held honest by `the_plan_covers_many_minimally_specified_networks`, which
/// builds a document of repeated minimal entries and fails if either the
/// normalized encoding or the retained measurement escapes the plan.
const CONFIG_EXPANSION_BYTES_PER_SOURCE_BYTE: usize = 128;

/// How many separate allocations one source byte is allowed to become.
///
/// **Bytes are not the only thing a parsed config costs.** Every `String`,
/// `Vec` and `PathBuf` it retains is an independent allocation with its own
/// allocator residual, and one defaulted `NetworkConfig` brings roughly fifteen
/// of them — the two reference STUN/TURN entries alone contribute a vector, a
/// url vector, a url, a username and a credential each. A byte ceiling funds
/// none of that, so the residual term needs its own bound, scaling for the same
/// reason the byte term does: the count is per element.
///
/// Sound on the same argument: an element costs input bytes it cannot avoid,
/// so the worst achievable ratio is one element's allocation count over the
/// smallest input that can produce it — comfortably under one. This sits well
/// above that, because a residual is a counter rather than a byte and paying
/// for headroom here is cheap next to being short.
///
/// Counted for real by `the_plan_covers_many_minimally_specified_networks`,
/// which walks the parsed structure and tallies its actual owned allocations.
const CONFIG_ALLOCATIONS_PER_SOURCE_BYTE: usize = 4;

/// The allocation counterpart to [`DEFAULT_CONFIG_PLANNING_FLOOR_BYTES`]: what
/// the root's own defaulted sub-structs retain before any network exists.
const DEFAULT_CONFIG_ALLOCATION_FLOOR: usize = 256;

/// The one parse-and-quarantine decision, shared by [`MeshConfig::load`] and
/// [`PreparedConfigLoad::commit`].
///
/// Shared rather than duplicated so the two entry points cannot drift: the
/// quarantine, the fail-safe default and the version refusal are one behaviour
/// with two callers, and a second copy would be a second source of truth for
/// what a corrupt config means.
fn parse_or_quarantine(raw: &str, path: &std::path::Path) -> Result<MeshConfig> {
    // Corrupt config (power cut mid-write on an appliance, or a
    // hand-edit gone wrong) → quarantine + defaults, loudly. A
    // parse error here used to stop the daemon from starting at
    // all — the worst brick, since embedders (NanoKVM, AllMyStuff)
    // re-add their networks over the control socket and rewrite
    // this file on their own once the daemon is up. Defaults are
    // fail-safe: no networks joined, no services exposed.
    match serde_json::from_str::<MeshConfig>(raw) {
        Ok(cfg) => require_current_version(cfg),
        Err(e) => {
            let kept = crate::persist::quarantine(path);
            tracing::error!(
                path = %path.display(),
                quarantined = ?kept,
                "config file is corrupt ({e}) — starting from \
                 defaults; the previous contents were kept at the \
                 quarantine path for hand-recovery"
            );
            Ok(MeshConfig::default())
        }
    }
}

/// Where a prepared load will get its bytes.
enum PreparedConfigSource {
    /// No file. The plan will produce [`MeshConfig::default`] and reads
    /// nothing.
    Missing,
    /// An **already-open** handle and the length the plan was measured
    /// against. Opened during planning rather than at commit so the bytes that
    /// get read are the bytes that were measured, not whatever a later `open`
    /// would find.
    Present { file: std::fs::File, len: u64 },
}

/// A measured, funded-but-not-yet-performed config load.
///
/// **Nothing is parsed and no config exists yet.** Planning opens the file and
/// measures it; it allocates no `MeshConfig` and no raw buffer. That is what
/// lets a caller decide whether it may afford the load *before* the load
/// happens, and what makes a refusal provably free of any read, parse or
/// snapshot construction.
///
/// **Core keeps the file semantics; the caller keeps the admission decision.**
/// There is deliberately no scope or provider parameter here and no acquisition
/// inside: the caller acquires against [`Self::typed_retention_claim`] and
/// [`Self::load_work_claim`] — and against
/// whatever its own output path derives from [`Self::encoding_ceiling`] — and
/// hands the lease to [`Self::commit`]. Quarantine, the fail-safe default and
/// the version refusal stay in this crate, where they are already the one
/// source of truth.
///
/// Move-only, and there is no accessor for the handle. A plan is a single
/// permission to perform one load.
#[must_use = "a prepared load has opened the config file and must be committed or dropped"]
pub struct PreparedConfigLoad {
    source: PreparedConfigSource,
    /// Kept because quarantine needs the path, and the plan may be the only
    /// thing still holding it by the time a corrupt parse is discovered.
    path: PathBuf,
    typed_retention_claim: ResourceClaim,
    load_work_claim: ResourceClaim,
    encoding_ceiling: usize,
}

/// One config, and the funding that keeps it.
///
/// Value before lease: the config is destroyed first and its funding released
/// after, so the claim never describes memory that has already gone — nor is it
/// released while the value it pays for is still standing.
///
/// Borrowed access only. There is no method handing the `MeshConfig` out on its
/// own, because a caller holding one would have a config whose funding had been
/// released with the owner around it.
pub struct FundedMeshConfig {
    value: MeshConfig,
    _typed: ResourceLease,
}

impl FundedMeshConfig {
    pub fn get(&self) -> &MeshConfig {
        &self.value
    }
}

impl PreparedConfigLoad {
    /// What retaining the parsed config will cost, for as long as it is held.
    ///
    /// Memory only. Parse work is *not* here: the parse is over by the time
    /// this retention begins, and holding a `ParsingOrCpuWork` charge for the
    /// life of a response would tell the provider that work was in flight long
    /// after it had finished. That charge lives in
    /// [`Self::load_work_claim`] instead, and ends with the load.
    pub const fn typed_retention_claim(&self) -> ResourceClaim {
        self.typed_retention_claim
    }

    /// What performing the load costs *while it happens*, and not afterwards.
    ///
    /// The raw text and the parsed config exist at the same moment: the config
    /// is built from a buffer that is still there. A plan that priced only the
    /// result would underfund exactly that peak. This is the other half — the
    /// raw buffer's bytes, the parse work, and the plan's own path — and
    /// [`Self::commit`] releases it before returning, so the transient cost is
    /// charged for the interval it is actually incurred in.
    ///
    /// The path is here rather than in the retention because it dies with the
    /// load: nothing beyond `commit` can reach it, and the parsed config does
    /// not hold it.
    pub const fn load_work_claim(&self) -> ResourceClaim {
        self.load_work_claim
    }

    /// A conservative upper bound on the normalized JSON this config will
    /// produce.
    ///
    /// For a caller sizing an output buffer or a response line. Compact
    /// encoding: this bounds `serde_json::to_string`, not the pretty form
    /// [`MeshConfig::save`] writes.
    pub const fn encoding_ceiling(&self) -> usize {
        self.encoding_ceiling
    }

    /// Read, parse and retain, now that the retention is funded.
    ///
    /// The read is bounded by the length measured during planning, and a file
    /// that **grew** since then is refused *before* anything is parsed or
    /// quarantined — a file being rewritten underneath us is not a corrupt
    /// file, and treating it as one would quarantine a perfectly good config
    /// that simply arrived mid-write.
    ///
    /// Everything else is exactly [`MeshConfig::load`]'s behaviour, because it
    /// is literally the same function: complete-read corrupt files are
    /// quarantined and fall back to defaults, and a config whose version is not
    /// current is refused.
    /// Takes **both** leases because both costs are real at different times:
    /// `work_lease` covers the raw buffer and the parse while they exist, and
    /// is released here once the buffer is gone; `typed_lease` covers the
    /// config and travels out inside the returned owner.
    pub fn commit(
        self,
        typed_lease: ResourceLease,
        work_lease: ResourceLease,
    ) -> Result<FundedMeshConfig> {
        use std::io::Read;

        // The leases have to be *these* leases. `ResourceLease::claim` is public,
        // so without this the prepare-then-acquire discipline would be a
        // convention a caller could simply not follow: two unrelated leases, or
        // two zero ones, would buy a `FundedMeshConfig` whose funding describes
        // something else. Checked before the file is read, before anything is
        // parsed, and before a default is constructed, so a caller that gets this
        // wrong has still caused no work.
        //
        // Both leases are dropped on the way out, which returns their capacity to
        // whatever they were taken from. That is the only sound thing to do with
        // them: they are not this plan's, so they cannot be handed back as this
        // plan's, and holding them would strand capacity on a refusal.
        if typed_lease.claim() != self.typed_retention_claim {
            return Err(Error::Config(
                "config retention lease was not taken for this plan's typed retention claim"
                    .to_string(),
            ));
        }
        if work_lease.claim() != self.load_work_claim {
            return Err(Error::Config(
                "config load lease was not taken for this plan's load work claim".to_string(),
            ));
        }

        // Named rather than reached through `self`, so the path can be released
        // deliberately below rather than at the end of this call — after the
        // charge that covers it has already gone back.
        let PreparedConfigLoad {
            source,
            path,
            typed_retention_claim: _,
            load_work_claim: _,
            encoding_ceiling: _,
        } = self;

        let value = match source {
            PreparedConfigSource::Missing => MeshConfig::default(),
            PreparedConfigSource::Present { file, len } => {
                // One byte past the measurement: enough to *detect* growth,
                // never enough to read an unbounded file.
                //
                // Reserved up front, at exactly the capacity `load_work_claim`
                // priced. `String::new()` would start empty and grow
                // geometrically toward the same size, asking the allocator for
                // capacity nobody had funded — and doing so *before* the growth
                // refusal below could fire.
                let capacity = usize::try_from(len)
                    .ok()
                    .and_then(|measured| measured.checked_add(1))
                    .ok_or_else(|| {
                        Error::Config(format!("config {} is too large to read", path.display()))
                    })?;
                let mut raw = String::with_capacity(capacity);
                file.take(len.saturating_add(1))
                    .read_to_string(&mut raw)
                    .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
                if raw.len() as u64 > len {
                    return Err(Error::Config(format!(
                        "config {} grew past its measured {len} bytes while being read",
                        path.display()
                    )));
                }
                let parsed = parse_or_quarantine(&raw, &path)?;
                // The buffer's bytes go back before the charge for them does,
                // and both go back before this call returns: the peak where the
                // text and the config are both alive is exactly the interval
                // `work_lease` was acquired for.
                drop(raw);
                parsed
            }
        };
        // The plan's own path is the second allocation `load_work_claim` funds,
        // and it goes back before the charge for it does — the same order the
        // raw buffer follows above.
        drop(path);
        drop(work_lease);
        Ok(FundedMeshConfig {
            value,
            _typed: typed_lease,
        })
    }
}

impl MeshConfig {
    /// Load the config from the default location. Missing file
    /// returns [`MeshConfig::default`] — embedders should call
    /// `save()` afterward if they want the file to exist.
    ///
    /// Unfunded, and kept that way for embedders that have no resource scope.
    /// A caller that must fund the retention before it happens uses
    /// [`MeshConfig::prepare_load`] instead; both share one parse.
    pub fn load() -> Result<Self> {
        let path = crate::dirs::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        parse_or_quarantine(&raw, &path)
    }

    /// Measure a config load without performing it.
    ///
    /// Opens and stats the file — so the plan is measured against the same
    /// handle it will later read — and computes what the parsed config will
    /// cost. It allocates no config and no raw buffer, and parses nothing, so a
    /// caller that refuses on the resulting claim has provably performed no
    /// read, no parse and no construction.
    ///
    /// It does allocate one thing: the path it opened, which the plan keeps
    /// because quarantine needs it. That allocation is priced into
    /// [`PreparedConfigLoad::load_work_claim`] and released inside `commit`
    /// before that lease is. It is unfunded between here and the caller's
    /// acquisition, necessarily — the plan is what tells the caller what to
    /// acquire.
    ///
    /// Both figures include [`DEFAULT_CONFIG_PLANNING_FLOOR_BYTES`], because
    /// absent fields expand to defaults and the input's own length says nothing
    /// about that expansion.
    pub fn prepare_load() -> Result<PreparedConfigLoad> {
        let path = crate::dirs::config_path()?;
        let source = match std::fs::File::open(&path) {
            Ok(file) => {
                let len = file
                    .metadata()
                    .map_err(|e| Error::Config(format!("stat {}: {e}", path.display())))?
                    .len();
                PreparedConfigSource::Present { file, len }
            }
            // Absent is the ordinary first-run case, not a failure: the plan
            // will produce defaults, and the floor already prices them.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PreparedConfigSource::Missing,
            Err(e) => return Err(Error::Config(format!("open {}: {e}", path.display()))),
        };

        let raw_bytes = match &source {
            PreparedConfigSource::Missing => 0,
            PreparedConfigSource::Present { len, .. } => usize::try_from(*len).map_err(|_| {
                Error::Config(format!(
                    "config {} is larger than this address space",
                    path.display()
                ))
            })?,
        };
        let too_large = || Error::Config(format!("config {} is too large to plan", path.display()));
        // Every source byte may expand, and the root's own defaults expand from
        // nothing at all — so the ceiling needs both a term that scales with
        // the input and a term that does not.
        let encoding_ceiling = raw_bytes
            .checked_mul(CONFIG_EXPANSION_BYTES_PER_SOURCE_BYTE)
            .and_then(|expanded| expanded.checked_add(DEFAULT_CONFIG_PLANNING_FLOOR_BYTES))
            .ok_or_else(too_large)?;

        // What is kept: the owned value's inline shape plus the heap it can
        // reach, bounded by what it can possibly encode to. Memory only — the
        // parse is finished before this retention starts.
        let retained = std::mem::size_of::<MeshConfig>()
            .checked_add(encoding_ceiling)
            .ok_or_else(too_large)?;
        // Every retained String, Vec and PathBuf is its own allocation with its
        // own residual, and the count is per element for the same reason the
        // bytes are — so this scales with the input too.
        let retained_allocations = raw_bytes
            .checked_mul(CONFIG_ALLOCATIONS_PER_SOURCE_BYTE)
            .and_then(|scaled| scaled.checked_add(DEFAULT_CONFIG_ALLOCATION_FLOOR))
            .ok_or_else(too_large)?;
        let not_representable =
            || Error::Config("config planning claim is not representable".to_string());
        let typed_retention_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(retained).map_err(|_| not_representable())?,
            ),
            (
                ResourceClass::OpaqueDependencyResidual,
                u64::try_from(retained_allocations).map_err(|_| not_representable())?,
            ),
        ])
        .map_err(|_| not_representable())?;

        // What is spent to get there: the raw text's buffer, alive at the same
        // moment as the config built from them, and the work of parsing it.
        // Released by `commit` rather than carried for the value's lifetime.
        //
        // `raw_bytes + 1`, not `raw_bytes`, and the extra byte is not a
        // rounding habit: the read deliberately asks for one byte past the
        // measurement so that growth is *detectable*, and `commit` reserves
        // exactly that much up front. Pricing only `raw_bytes` would leave the
        // detection byte unfunded — and a buffer that had to grow to hold it
        // would request unpriced capacity before the growth refusal it exists
        // to trigger could fire.
        let read_capacity = raw_bytes.checked_add(1).ok_or_else(too_large)?;
        // The plan holds a path, and a path is an allocation like any other. It
        // is charged here rather than to the retention because it dies with the
        // load: `commit` releases it just before it releases this lease, and a
        // plan that is never committed drops it with the plan.
        //
        // Capacity, not length, because capacity is what the allocator is
        // holding — the same rule the retained-shape walk follows.
        //
        // **The window this does not cover, stated rather than implied.** The
        // path exists from the moment `prepare_load` derives it, which is before
        // the caller can possibly hold a lease for it: the plan is what tells
        // them what to acquire. That is inherent to letting the caller acquire —
        // it is one path allocation, bounded by the config directory, and it is
        // funded for the whole interval in which any funding exists at all.
        let planning_bytes = read_capacity
            .checked_add(path.capacity())
            .ok_or_else(too_large)?;
        let planning_bytes_u64 = u64::try_from(planning_bytes).map_err(|_| not_representable())?;
        let parse_work_u64 = u64::try_from(read_capacity).map_err(|_| not_representable())?;
        let load_work_claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, planning_bytes_u64),
            // Work scales with the text that is parsed, and the path is not
            // parsed — so this stays the read capacity rather than following the
            // bytes above.
            (ResourceClass::ParsingOrCpuWork, parse_work_u64),
            // The raw buffer and the plan's path: two allocations, two
            // residuals.
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| not_representable())?;

        Ok(PreparedConfigLoad {
            source,
            path,
            typed_retention_claim,
            load_work_claim,
            encoding_ceiling,
        })
    }

    /// Persist to the default location. Pretty-printed JSON for
    /// easy hand-editing; the file isn't on a hot path.
    pub fn save(&self) -> Result<()> {
        let path = crate::dirs::config_path()?;
        let parent = path.parent().ok_or_else(|| {
            Error::Config(format!("config path has no parent: {}", path.display()))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("create {}: {e}", parent.display())))?;
        let serialized = serde_json::to_string_pretty(self)?;
        crate::persist::write_atomic(&path, serialized.as_bytes())
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))?;
        Ok(())
    }

    /// Find a network config by its local `id`.
    pub fn network(&self, id: &str) -> Option<&NetworkConfig> {
        self.networks.iter().find(|n| n.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The planning floor really does cover a fully defaulted config, in both
    /// the shapes it is used for.
    ///
    /// This is the control the floor's honesty rests on. The floor is a
    /// constant because planning has to happen before anything is constructed,
    /// and a constant that nobody checks is exactly the sort of figure that
    /// silently stops being true as fields are added. Serializing the real
    /// `Default` is what keeps it true: add a sub-struct big enough to push a
    /// defaulted config past the floor and this fails here, in a test naming
    /// the reason, rather than as an under-funded load in production.
    ///
    /// Both encodings are checked because the floor prices both — compact for
    /// [`PreparedConfigLoad::encoding_ceiling`], pretty because
    /// [`MeshConfig::save`] writes that form and a later reader plans against
    /// its length.
    #[test]
    fn v4_r3_core_the_planning_floor_covers_a_defaulted_config() {
        let default = MeshConfig::default();
        let compact = serde_json::to_string(&default).expect("a default config serializes");
        let pretty = serde_json::to_string_pretty(&default).expect("a default config serializes");

        assert!(
            compact.len() <= DEFAULT_CONFIG_PLANNING_FLOOR_BYTES,
            "a defaulted config encodes to {} compact bytes, past the {} byte planning floor — \
             raise the floor rather than letting a planned load underfund it",
            compact.len(),
            DEFAULT_CONFIG_PLANNING_FLOOR_BYTES
        );
        assert!(
            pretty.len() <= DEFAULT_CONFIG_PLANNING_FLOOR_BYTES,
            "a defaulted config pretty-prints to {} bytes, past the {} byte planning floor",
            pretty.len(),
            DEFAULT_CONFIG_PLANNING_FLOOR_BYTES
        );
    }

    /// An empty JSON object is the case a length-derived ceiling gets wrong.
    ///
    /// `{}` is two bytes and parses to a complete config with every sub-struct
    /// present, so a plan that priced only the input would fund almost nothing
    /// and retain everything. The floor is what closes that, and this states it
    /// as a property rather than leaving it as a comment: the config a
    /// two-byte input becomes must still fit inside what a two-byte input was
    /// planned for.
    #[test]
    fn v4_r3_core_an_empty_object_is_priced_for_what_it_becomes() {
        let expanded: MeshConfig = serde_json::from_str("{}").expect("an empty object parses");
        let encoded = serde_json::to_string(&expanded).expect("the expansion serializes");
        let planned = "{}".len() + DEFAULT_CONFIG_PLANNING_FLOOR_BYTES;

        assert!(
            encoded.len() > "{}".len(),
            "the point of this control is that the expansion is larger than its input"
        );
        assert!(
            encoded.len() <= planned,
            "a two-byte input expands to {} bytes, past the {planned} a two-byte input is \
             planned for",
            encoded.len()
        );
    }

    /// Repeated minimal network entries stay inside the plan.
    ///
    /// **The case a single global floor gets wrong.** `networks` is an array,
    /// and every element that omits `stun_servers`, `turn_servers`,
    /// `signaling` and `topology` expands into all four defaults. That
    /// expansion is per element, so it accumulates linearly with the entry
    /// count and will pass any fixed constant once the document is long
    /// enough — the one-`{}` controls above cannot see this at all, because a
    /// single empty object expands exactly once.
    ///
    /// All three figures the plan publishes are checked, because being short in
    /// any of them is an under-funded load: the normalized encoding against
    /// `encoding_ceiling`, the retained bytes against the planned retention,
    /// and the **count of separate allocations** against the planned residual.
    ///
    /// The allocation tally walks the parsed structure and counts its actual
    /// owned `String`s and `Vec`s. It deliberately does *not* go through
    /// `mailbox_measure_serialized`: that helper models a decoded
    /// `serde_json::Value` tree, whose per-node overhead is many times the
    /// bytes it came from, while `MeshConfig` is a typed struct. Measuring one
    /// with the other would compare unlike things and fail for a reason that
    /// says nothing about this plan.
    ///
    /// The entry count is far past anything a real deployment carries, on
    /// purpose: the property is that the *ratio* holds, and a control that used
    /// two entries would pass on a constant that fails at fifty.
    #[test]
    fn v4_r3_core_the_plan_covers_many_minimally_specified_networks() {
        const ENTRIES: usize = 256;

        // Minimal in exactly the sense that matters: both required fields, and
        // nothing else, so every defaulted field expands per element.
        let entries: Vec<String> = (0..ENTRIES)
            .map(|index| format!(r#"{{"id":"n{index}","network_id":"w{index}"}}"#))
            .collect();
        let raw = format!(
            r#"{{"version":{CONFIG_VERSION},"networks":[{}]}}"#,
            entries.join(",")
        );

        let parsed: MeshConfig = serde_json::from_str(&raw).expect("minimal network entries parse");
        assert_eq!(
            parsed.networks.len(),
            ENTRIES,
            "the control must actually exercise every entry"
        );

        let planned_ceiling = raw.len() * CONFIG_EXPANSION_BYTES_PER_SOURCE_BYTE
            + DEFAULT_CONFIG_PLANNING_FLOOR_BYTES;
        let encoded = serde_json::to_string(&parsed).expect("the expansion serializes");
        assert!(
            encoded.len() > raw.len(),
            "the point of this control is that {ENTRIES} minimal entries expand"
        );
        assert!(
            encoded.len() <= planned_ceiling,
            "{ENTRIES} minimal entries encode to {} bytes, past the planned ceiling of \
             {planned_ceiling} — raise CONFIG_EXPANSION_BYTES_PER_SOURCE_BYTE rather than \
             letting a planned load underfund it",
            encoded.len()
        );

        let planned_retention = std::mem::size_of::<MeshConfig>() + planned_ceiling;
        let planned_allocations =
            raw.len() * CONFIG_ALLOCATIONS_PER_SOURCE_BYTE + DEFAULT_CONFIG_ALLOCATION_FLOOR;
        let held = std::mem::size_of::<MeshConfig>() + config_owned_bytes(&parsed);
        let allocations = config_owned_allocations(&parsed);
        assert!(
            allocations > ENTRIES,
            "the point of this control is that each entry retains several allocations"
        );
        assert!(
            held <= planned_retention,
            "{ENTRIES} minimal entries hold {held} bytes, past the planned {planned_retention}"
        );
        assert!(
            allocations <= planned_allocations,
            "{ENTRIES} minimal entries retain {allocations} separate allocations, past the \
             planned {planned_allocations} — raise CONFIG_ALLOCATIONS_PER_SOURCE_BYTE rather \
             than letting the residual term underfund them"
        );
    }

    /// The same three figures, against a document that populates **every**
    /// repeatable family this schema has.
    ///
    /// The minimal-entry control above finds the worst *ratio*, because an
    /// element that says almost nothing still expands into all its defaults.
    /// It cannot find the worst *magnitude*, because nothing in it is
    /// populated: no extra STUN urls, no second TURN server, no signaling
    /// relays, no denylist, no pinned peers, and — the family that lives
    /// outside `networks` entirely — no TURN **service** credentials. Each of
    /// those is an array whose contents scale with the input, and a ceiling
    /// proved only against defaults would say nothing about any of them.
    ///
    /// `services.turn.credentials` matters particularly: it is the one
    /// repeatable family at the document root rather than inside a network, so
    /// a control that walked only `networks` would miss it however many entries
    /// it used.
    #[test]
    fn v4_r3_core_the_plan_covers_every_populated_repeatable_family() {
        const ENTRIES: usize = 64;
        const PER_FAMILY: usize = 8;

        let list = |prefix: &str, index: usize| -> String {
            (0..PER_FAMILY)
                .map(|item| format!(r#""{prefix}-{index}-{item}""#))
                .collect::<Vec<_>>()
                .join(",")
        };
        let networks: Vec<String> = (0..ENTRIES)
            .map(|index| {
                let stun = list("stun:host", index);
                let turn = list("turn:host", index);
                format!(
                    r#"{{"id":"n{index}","network_id":"w{index}","label":"long label {index}",
                       "signaling":{{"strategy":"nostr","servers":[{}],"denylist":[{}]}},
                       "stun_servers":[{{"urls":[{stun}]}}],
                       "turn_servers":[{{"urls":[{turn}],"username":"user-{index}",
                                         "credential":"secret-{index}"}}],
                       "pinned_peers":[{}]}}"#,
                    list("wss://relay", index),
                    list("denied", index),
                    list("peer", index),
                )
            })
            .collect();
        let credentials: Vec<String> = (0..ENTRIES)
            .map(|index| format!(r#"{{"username":"svc-{index}","password":"pw-{index}"}}"#))
            .collect();
        let raw = format!(
            r#"{{"version":{CONFIG_VERSION},"networks":[{}],
                 "services":{{"turn":{{"credentials":[{}]}}}}}}"#,
            networks.join(","),
            credentials.join(",")
        );

        let parsed: MeshConfig = serde_json::from_str(&raw).expect("a populated document parses");
        // Every family is genuinely exercised — a typo in the document above
        // would otherwise let this pass while measuring defaults.
        assert_eq!(parsed.networks.len(), ENTRIES);
        assert_eq!(parsed.services.turn.credentials.len(), ENTRIES);
        let first = &parsed.networks[0];
        assert_eq!(first.stun_servers[0].urls.len(), PER_FAMILY);
        assert_eq!(first.turn_servers[0].urls.len(), PER_FAMILY);
        assert!(first.turn_servers[0].username.is_some());
        assert!(first.turn_servers[0].credential.is_some());
        assert_eq!(first.signaling.servers.len(), PER_FAMILY);
        assert_eq!(first.signaling.denylist.len(), PER_FAMILY);
        assert_eq!(first.pinned_peers.len(), PER_FAMILY);

        let planned_ceiling = raw.len() * CONFIG_EXPANSION_BYTES_PER_SOURCE_BYTE
            + DEFAULT_CONFIG_PLANNING_FLOOR_BYTES;
        let planned_retention = std::mem::size_of::<MeshConfig>() + planned_ceiling;
        let planned_allocations =
            raw.len() * CONFIG_ALLOCATIONS_PER_SOURCE_BYTE + DEFAULT_CONFIG_ALLOCATION_FLOOR;

        let encoded = serde_json::to_string(&parsed).expect("the document serializes");
        let held = std::mem::size_of::<MeshConfig>() + config_owned_bytes(&parsed);
        let allocations = config_owned_allocations(&parsed);

        assert!(
            encoded.len() <= planned_ceiling,
            "a fully populated document encodes to {} bytes, past the planned {planned_ceiling}",
            encoded.len()
        );
        assert!(
            held <= planned_retention,
            "a fully populated document holds {held} bytes, past the planned {planned_retention}"
        );
        assert!(
            allocations <= planned_allocations,
            "a fully populated document retains {allocations} separate allocations, past the \
             planned {planned_allocations}"
        );
    }

    /// The inline records a vector's own buffer holds — capacity, not length,
    /// because that is what it reserved from the allocator.
    fn vec_buffer_bytes<T>(values: &Vec<T>) -> usize {
        values.capacity() * std::mem::size_of::<T>()
    }

    fn string_vec_bytes(values: &Vec<String>) -> usize {
        vec_buffer_bytes(values) + values.iter().map(String::capacity).sum::<usize>()
    }

    /// One allocation for the vector's own buffer, plus one per string it
    /// holds.
    ///
    /// The leading `1` is the whole reason this takes `&Vec<String>` and not
    /// `&[String]`: it counts the container's *own* heap allocation, and only a
    /// `Vec` has one. A slice is a borrowed view whose backing store might be a
    /// `Vec`, an array, or a boxed slice, so the same body against `&[String]`
    /// would be adding one for an allocation it can no longer prove exists.
    /// The signature is the proof, which is why the lint is suppressed here
    /// rather than followed.
    #[expect(
        clippy::ptr_arg,
        reason = "the Vec-ness is load-bearing: the leading 1 counts the vector's own \
                  buffer allocation, which a slice cannot attest to"
    )]
    fn string_vec_allocations(values: &Vec<String>) -> usize {
        1 + values.len()
    }

    /// Every heap byte one network element retains.
    ///
    /// Walks capacity rather than length throughout: a `Vec` or `String` holds
    /// whatever it reserved, not whatever it filled, and a tally that measured
    /// length would understate exactly the case where a parser over-reserved.
    /// Element buffers are counted separately from the elements' own contents,
    /// because a `Vec<String>` owns `size_of::<String>() * capacity` of inline
    /// records *before* any of the strings behind them.
    fn network_owned_bytes(network: &NetworkConfig) -> usize {
        let mut bytes =
            network.id.capacity() + network.network_id.capacity() + network.label.capacity();
        bytes += network.signaling.strategy.capacity();
        bytes += string_vec_bytes(&network.signaling.servers);
        bytes += string_vec_bytes(&network.signaling.denylist);
        bytes += vec_buffer_bytes(&network.stun_servers);
        for stun in &network.stun_servers {
            bytes += string_vec_bytes(&stun.urls);
        }
        bytes += vec_buffer_bytes(&network.turn_servers);
        for turn in &network.turn_servers {
            bytes += string_vec_bytes(&turn.urls);
            bytes += turn.username.as_ref().map_or(0, String::capacity);
            bytes += turn.credential.as_ref().map_or(0, String::capacity);
        }
        bytes += string_vec_bytes(&network.pinned_peers);
        bytes += network
            .roster_path
            .as_ref()
            .map_or(0, |path| path.capacity());
        if let TopologyMode::Hubs { hubs, .. } = &network.topology {
            bytes += vec_buffer_bytes(hubs);
        }
        bytes
    }

    fn network_owned_allocations(network: &NetworkConfig) -> usize {
        // Three owned strings, counted even when empty. A ceiling that assumed
        // an empty `String` elides its allocation would be short the moment
        // somebody fills the field in.
        let mut count = 3;
        count += 1; // signaling strategy
        count += string_vec_allocations(&network.signaling.servers);
        count += string_vec_allocations(&network.signaling.denylist);
        count += 1; // the stun vector
        for stun in &network.stun_servers {
            count += string_vec_allocations(&stun.urls);
        }
        count += 1; // the turn vector
        for turn in &network.turn_servers {
            count += string_vec_allocations(&turn.urls);
            count += usize::from(turn.username.is_some());
            count += usize::from(turn.credential.is_some());
        }
        count += string_vec_allocations(&network.pinned_peers);
        count += usize::from(network.roster_path.is_some());
        if let TopologyMode::Hubs { hubs, .. } = &network.topology {
            count += 1 + hubs.len();
        }
        count
    }

    /// Every heap byte the whole config retains, root families included.
    ///
    /// The root is not only the `networks` array: `services.turn.credentials`
    /// is a second family that scales with the input, and the update, daemon
    /// and service structs each own strings of their own. A tally that walked
    /// only `networks` would be measuring a strict subset of what the plan is
    /// asked to fund.
    fn config_owned_bytes(config: &MeshConfig) -> usize {
        let mut bytes = config
            .identity_path
            .as_ref()
            .map_or(0, |path| path.capacity());
        bytes += config.auto_update.channel.capacity() + config.auto_update.auto_apply.capacity();
        bytes += config
            .auto_update
            .stable_url
            .as_ref()
            .map_or(0, String::capacity);
        bytes += config
            .auto_update
            .beta_url
            .as_ref()
            .map_or(0, String::capacity);
        bytes += config
            .daemon
            .control_socket
            .as_ref()
            .map_or(0, |path| path.capacity());
        bytes += config.daemon.log_level.capacity();
        bytes += config.services.signaling.bind.capacity();
        bytes += config.services.stun.bind.capacity();
        bytes += config.services.turn.bind.capacity()
            + config.services.turn.public_ip.capacity()
            + config.services.turn.realm.capacity();
        bytes += vec_buffer_bytes(&config.services.turn.credentials);
        for credential in &config.services.turn.credentials {
            bytes += credential.username.capacity() + credential.password.capacity();
        }
        bytes += vec_buffer_bytes(&config.networks);
        bytes += config
            .networks
            .iter()
            .map(network_owned_bytes)
            .sum::<usize>();
        bytes
    }

    fn config_owned_allocations(config: &MeshConfig) -> usize {
        let mut count = usize::from(config.identity_path.is_some());
        count += 2; // update channel and auto-apply
        count += usize::from(config.auto_update.stable_url.is_some());
        count += usize::from(config.auto_update.beta_url.is_some());
        count += usize::from(config.daemon.control_socket.is_some());
        count += 1; // daemon log level
        count += 2; // signaling and stun bind addresses
        count += 3; // turn bind, public ip and realm
        count += 1 + config.services.turn.credentials.len() * 2;
        count += 1; // the networks buffer
        count += config
            .networks
            .iter()
            .map(network_owned_allocations)
            .sum::<usize>();
        count
    }

    #[test]
    fn default_is_current_with_defaults() {
        let cfg = MeshConfig::default();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(cfg.auto_update.enabled);
        assert_eq!(cfg.auto_update.channel, "stable");
        // Alpha default: ride every release.
        assert_eq!(cfg.auto_update.auto_apply, "all");
        assert_eq!(cfg.auto_update.check_interval_hours, 6);
        assert!(cfg.daemon.enabled);
        assert!(cfg.networks.is_empty());
    }

    #[test]
    fn topology_default_is_full_mesh() {
        // The truthful default: pre-0.2.34 networks all ran a full
        // mesh (the old "ring" only shelved frames). `Ring` now names
        // the shaped ring and is only ever chosen deliberately.
        assert_eq!(TopologyMode::default(), TopologyMode::FullMesh);
    }

    #[test]
    fn old_hard_alpha_config_is_refused_not_migrated() {
        let old = MeshConfig {
            version: 1,
            ..Default::default()
        };
        assert!(require_current_version(old).is_err());
    }

    #[test]
    fn topology_effective_n_preferred_falls_back() {
        let r = TopologyMode::Ring { n_preferred: None };
        assert_eq!(r.effective_n_preferred(), 3);
        let r5 = TopologyMode::Ring {
            n_preferred: Some(5),
        };
        assert_eq!(r5.effective_n_preferred(), 5);
        // Non-Ring topologies don't have an n_preferred — return 0.
        assert_eq!(TopologyMode::FullMesh.effective_n_preferred(), 0);
    }

    #[test]
    fn topology_serde_tags_by_kind() {
        let ring = TopologyMode::Ring {
            n_preferred: Some(3),
        };
        let s = serde_json::to_string(&ring).unwrap();
        assert!(s.contains("\"kind\":\"ring\""), "got: {s}");
        assert!(s.contains("\"n_preferred\":3"));

        let star = TopologyMode::Star {
            hub: "abcdef".into(),
        };
        let s = serde_json::to_string(&star).unwrap();
        assert!(s.contains("\"kind\":\"star\""));
        assert!(s.contains("\"hub\":\"abcdef\""));

        let full = TopologyMode::FullMesh;
        let s = serde_json::to_string(&full).unwrap();
        assert!(s.contains("\"kind\":\"full_mesh\""));
    }

    #[test]
    fn signaling_defaults_carry_denylist() {
        let s = SignalingConfig::default();
        assert_eq!(s.strategy, "nostr");
        assert_eq!(s.redundancy, DEFAULT_SIGNALING_REDUNDANCY);
        assert!(s.denylist.iter().any(|h| h == "relay.damus.io"));
    }

    #[test]
    fn round_trip_empty_config() {
        let cfg = MeshConfig::default();
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn network_config_omits_stun_field_picks_up_defaults() {
        // A user writing a minimal network config without
        // mentioning stun_servers should get the built-in defaults
        // rather than launching with zero ICE servers.
        let json = r#"{
            "id": "n1",
            "network_id": "test-net"
        }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.stun_servers, default_stun_servers());
        assert!(!cfg.stun_servers.is_empty());
        assert!(cfg.stun_servers[0]
            .urls
            .iter()
            .any(|u| u.contains("myownmesh")));
        // TURN is filled in the same way — an omitted field picks up the
        // reference TURN with its guest credential so symmetric-NAT peers
        // connect out of the box.
        assert_eq!(cfg.turn_servers, default_turn_servers());
        assert_eq!(cfg.turn_servers[0].username.as_deref(), Some("guest"));
        assert!(cfg.turn_servers[0].urls[0].contains("myownmesh"));
    }

    #[test]
    fn network_kind_silent_round_trips_and_defaults_open() {
        use crate::network_state::NetworkKind;
        // Explicit `"kind": "silent"` decodes to Silent.
        let json = r#"{ "id": "n1", "network_id": "t", "kind": "silent" }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.kind, NetworkKind::Silent);
        // A round-trip preserves it.
        let s = serde_json::to_string(&cfg).unwrap();
        assert!(s.contains("\"kind\":\"silent\""), "got: {s}");
        let back: NetworkConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.kind, NetworkKind::Silent);
        // An old config that omits `kind` keeps decoding to the default (Open),
        // so existing networks are untouched.
        let old = r#"{ "id": "n1", "network_id": "t" }"#;
        let cfg: NetworkConfig = serde_json::from_str(old).unwrap();
        assert_eq!(cfg.kind, NetworkKind::Open);
    }

    #[test]
    fn mesh_config_with_a_silent_network_round_trips() {
        use crate::network_state::NetworkKind;
        let mut cfg = MeshConfig::default();
        let mut net = NetworkConfig::from_network_id("support", "cec-support");
        net.kind = NetworkKind::Silent;
        cfg.networks.push(net);
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
        assert_eq!(back.networks[0].kind, NetworkKind::Silent);
    }

    #[test]
    fn turn_servers_opt_out_with_empty_array() {
        // An explicit empty array disables the default reference TURN.
        let json = r#"{ "id": "n1", "network_id": "t", "turn_servers": [] }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.turn_servers.is_empty());
    }

    #[test]
    fn services_default_off() {
        let s = ServicesConfig::default();
        // A fresh device IS a node by default; the hosted services are
        // all opt-in.
        assert!(s.node.enabled);
        assert!(!s.signaling.enabled);
        assert!(!s.stun.enabled);
        assert!(!s.turn.enabled);
        assert_eq!(s.signaling.port, DEFAULT_SIGNALING_SERVER_PORT);
        assert_eq!(s.stun.port, DEFAULT_STUN_TURN_PORT);
        assert_eq!(s.turn.port, DEFAULT_STUN_TURN_PORT);
        assert_eq!(s.turn.realm, "myownmesh");
        // Signaling ships safe flood-limit defaults.
        assert_eq!(s.signaling.limits, SignalingLimits::default());
        assert!(s.signaling.limits.max_event_rate > 0);
        // TURN bandwidth is unlimited until configured.
        assert_eq!(s.turn.max_bps_per_connection, 0);
    }

    #[test]
    fn services_round_trip() {
        let mut cfg = MeshConfig::default();
        cfg.services.signaling.enabled = true;
        cfg.services.turn.enabled = true;
        cfg.services.turn.public_ip = "203.0.113.7".to_string();
        // Replace the placeholder default with a real operator entry.
        cfg.services.turn.credentials = vec![TurnCredential {
            username: "alice".into(),
            password: "s3cret".into(),
        }];
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
        assert!(back.services.signaling.enabled);
        assert_eq!(back.services.turn.credentials.len(), 1);
        assert_eq!(back.services.turn.credentials[0].username, "alice");
    }

    #[test]
    fn turn_service_default_ships_placeholder_credential() {
        // The default TURN service carries one non-empty placeholder
        // credential so an enabled relay accepts allocations out of the
        // box and users can see the shape to mirror into `turn_servers`.
        let turn = TurnServiceConfig::default();
        assert_eq!(turn.credentials.len(), 1);
        assert!(!turn.credentials[0].username.is_empty());
        assert!(!turn.credentials[0].password.is_empty());
    }

    #[test]
    fn turn_server_default_credential_matches_client_default() {
        // "Network in a box" only works if an enabled TURN server accepts
        // the credential clients use by default — so the server-side
        // placeholder and the client-side `default_turn_servers` entry
        // must stay in lockstep.
        let server = TurnServiceConfig::default();
        let client = default_turn_servers();
        assert_eq!(server.credentials.len(), 1);
        assert_eq!(client.len(), 1);
        assert_eq!(
            Some(&server.credentials[0].username),
            client[0].username.as_ref()
        );
        assert_eq!(
            Some(&server.credentials[0].password),
            client[0].credential.as_ref()
        );
    }

    #[test]
    fn turn_service_default_relay_range_is_unbounded() {
        // Default must NOT cap the relay out of the box — 0 means "use the
        // OS ephemeral range". Operators opt into a fixed window.
        assert_eq!(TurnServiceConfig::default().relay_port_min, 0);
    }

    #[test]
    fn network_config_empty_stun_array_opts_out() {
        // Writing an explicit empty list must remain empty — the
        // defaults only fire when the field is absent.
        let json = r#"{
            "id": "n1",
            "network_id": "test-net",
            "stun_servers": []
        }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.stun_servers.is_empty());
    }
}
