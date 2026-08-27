//! Config schema for `~/.myownmesh/config.json`. Reading & writing
//! lives here so any caller (binary, library embedder, tests) shares
//! the same parse / default behavior.
//!
//! Schema versioning uses one exact hard-alpha `version` field. This build
//! refuses any other version rather than migrating or guessing compatibility.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(any(test, windows))]
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::DeviceId;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};

/// Flood-protection limits for the self-hosted signaling relay. Defined
/// in the signaling crate (its natural home) and re-used here so the
/// config, the daemon, and the relay all share one shape.
pub use myownmesh_signaling::server::Limits as SignalingLimits;

pub const CONFIG_VERSION: u32 = 2;

static CONFIG_TRANSACTION_GATE: OnceLock<Mutex<()>> = OnceLock::new();

fn config_transaction_gate() -> &'static Mutex<()> {
    CONFIG_TRANSACTION_GATE.get_or_init(|| Mutex::new(()))
}

/// The cross-process half of the config transaction fence.
///
/// Unix keeps the lock pathname after release and relies on `flock`'s inode
/// ownership, while Windows uses a delete-on-close handle. Other platforms
/// fail closed because a portable crash-release primitive is unavailable.
struct ConfigFileLease {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    _file: std::fs::File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigFileIdentity {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileTime {
    _low: u32,
    _high: u32,
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileInformation {
    _attributes: u32,
    _creation_time: WindowsFileTime,
    _access_time: WindowsFileTime,
    _write_time: WindowsFileTime,
    volume_serial: u32,
    _file_size_high: u32,
    _file_size_low: u32,
    _links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: *mut std::ffi::c_void,
        information: *mut WindowsFileInformation,
    ) -> i32;
}

impl ConfigFileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn from_file(file: &std::fs::File) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_metadata(&file.metadata().map_err(|error| {
                Error::Config(format!("stat config: {error}"))
            })?))
        }

        #[cfg(windows)]
        {
            let mut information = std::mem::MaybeUninit::<WindowsFileInformation>::uninit();
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
                == 0
            {
                return Err(Error::Config(format!(
                    "get config file identity: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let information = unsafe { information.assume_init() };
            let metadata = file
                .metadata()
                .map_err(|error| Error::Config(format!("stat config: {error}")))?;
            Ok(Self {
                len: metadata.len(),
                volume_serial: information.volume_serial,
                file_index: (u64::from(information.file_index_high) << 32)
                    | u64::from(information.file_index_low),
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = file;
            Err(Error::Config(
                "config file identity is unsupported on this platform".to_string(),
            ))
        }
    }
}

impl ConfigFileLease {
    fn acquire(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|error| {
                    Error::Config(format!(
                        "open config transaction lock {}: {error}",
                        path.display()
                    ))
                })?;
            const LOCK_EX: std::os::raw::c_int = 2;
            if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
                return Err(Error::Config(format!(
                    "config transaction is busy: {}",
                    path.display()
                )));
            }
            Ok(Self { _file: file })
        }

        #[cfg(windows)]
        {
            const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .share_mode(0)
                    .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
                    .open(path)
                {
                    Ok(file) => break Ok(Self { _file: file }),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if Instant::now() >= deadline {
                            break Err(Error::Config(format!(
                                "timed out waiting for config transaction: {}",
                                path.display()
                            )));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        break Err(Error::Config(format!(
                            "open config transaction lock {}: {error}",
                            path.display()
                        )));
                    }
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(Error::Config(format!(
                "config transactions are unsupported on this platform: {}",
                path.display()
            )))
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

/// One in-process and cross-process config transaction lease.
struct ConfigTransactionLease {
    _file: ConfigFileLease,
    _process: MutexGuard<'static, ()>,
}

impl ConfigTransactionLease {
    fn acquire(config_path: &Path) -> Result<Self> {
        let process = config_transaction_gate()
            .lock()
            .map_err(|_| Error::Config("config transaction gate was poisoned".to_string()))?;
        let parent = config_path.parent().ok_or_else(|| {
            Error::Config(format!(
                "config path has no parent: {}",
                config_path.display()
            ))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Config(format!("create {}: {error}", parent.display())))?;
        let name = config_path.file_name().ok_or_else(|| {
            Error::Config(format!(
                "config path has no file name: {}",
                config_path.display()
            ))
        })?;
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let lock_path = config_path.with_file_name(lock_name);
        let file = ConfigFileLease::acquire(&lock_path)?;
        Ok(Self {
            _file: file,
            _process: process,
        })
    }
}

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

/// One deliberately opaque reservation for the loader-owned parsed config.
///
/// Serde defaults can expand a short source into arbitrarily many owned fields
/// as repeatable families grow, so neither source-byte ratios nor a fixed floor
/// truthfully price the resulting allocator graph. The owner therefore names
/// that graph as one broader dependency residual, acquired before parsing and
/// held for exactly as long as the finished [`MeshConfig`]. It also covers the
/// allocation-free serde traversal used to measure the compact encoding before
/// the caller acquires its output buffer; no loader work is performed after the
/// residual owner is released.
fn config_loader_residual_claim() -> ResourceClaim {
    ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
}

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

fn read_config_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Config(format!("read {}: {error}", path.display()))),
    }
}

/// Read one config while the transaction lease is held, returning the exact
/// bytes used as the commit CAS witness. A corrupt file may be quarantined by
/// parsing; in that case the post-quarantine absence is the baseline.
fn load_config_locked(path: &Path) -> Result<(MeshConfig, Option<Vec<u8>>)> {
    let Some(bytes) = read_config_bytes(path)? else {
        return Ok((MeshConfig::default(), None));
    };
    let raw = String::from_utf8(bytes.clone())
        .map_err(|error| Error::Config(format!("read {}: {error}", path.display())))?;
    let config = parse_or_quarantine(&raw, path)?;
    let baseline = if path.exists() { Some(bytes) } else { None };
    Ok((config, baseline))
}

fn save_config_locked(path: &Path, config: &MeshConfig) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Config(format!("config path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::Config(format!("create {}: {error}", parent.display())))?;
    let serialized = serde_json::to_string_pretty(config)?;
    crate::persist::write_atomic(path, serialized.as_bytes())
        .map_err(|error| Error::Config(format!("write {}: {error}", path.display())))
}

/// Where a prepared load will get its bytes and exact file identity.
enum PreparedConfigSource {
    /// No file. The plan will produce [`MeshConfig::default`] and reads
    /// nothing.
    Missing,
    /// An **already-open** handle and the length the plan was measured
    /// against. Opened during planning rather than at commit so the bytes that
    /// get read are the bytes that were measured, not whatever a later `open`
    /// would find. The identity rejects an uncoordinated replacement before
    /// the prepared handle can quarantine the wrong pathname.
    Present {
        file: std::fs::File,
        len: u64,
        identity: ConfigFileIdentity,
    },
}

fn ensure_prepared_source_identity(path: &Path, source: &PreparedConfigSource) -> Result<()> {
    match source {
        PreparedConfigSource::Missing => match std::fs::metadata(path) {
            Ok(_) => Err(Error::Config(format!(
                "config {} appeared after preparation",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Config(format!("stat {}: {error}", path.display()))),
        },
        PreparedConfigSource::Present { identity, .. } => {
            let file = std::fs::File::open(path)
                .map_err(|error| Error::Config(format!("open {}: {error}", path.display())))?;
            if ConfigFileIdentity::from_file(&file)? != *identity {
                Err(Error::Config(format!(
                    "config {} changed after preparation",
                    path.display()
                )))
            } else {
                Ok(())
            }
        }
    }
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
/// The transaction lease is acquired during preparation and held through
/// commit. The caller still acquires against [`Self::loader_residual_claim`]
/// and [`Self::load_work_claim`], then hands both leases to [`Self::commit`].
/// Once committed, the funded owner can measure its compact width before the
/// caller acquires output capacity. Quarantine, the fail-safe default and the
/// version refusal stay in this crate, where they are already the one source of
/// truth.
///
/// Move-only, and there is no accessor for the handle. A plan is a single
/// permission to perform one load.
#[must_use = "a prepared load has opened the config file and must be committed or dropped"]
pub struct PreparedConfigLoad {
    source: PreparedConfigSource,
    /// Held from preparation through commit, so supported writers cannot
    /// change the prepared path between its identity check and parse.
    _transaction: ConfigTransactionLease,
    /// Kept because quarantine needs the path, and the plan may be the only
    /// thing still holding it by the time a corrupt parse is discovered.
    path: PathBuf,
    loader_residual_claim: ResourceClaim,
    load_work_claim: ResourceClaim,
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
    _loader_residual: ResourceLease,
}

impl FundedMeshConfig {
    pub fn get(&self) -> &MeshConfig {
        &self.value
    }

    /// Exact compact JSON width, counted without constructing an output buffer.
    pub fn compact_encoded_len(&self) -> Result<usize> {
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "config width overflow")
                })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut count = Count(0);
        serde_json::to_writer(&mut count, &self.value)?;
        Ok(count.0)
    }
}

impl PreparedConfigLoad {
    /// The broader dependency represented by the parsed config.
    ///
    /// This names the allocator graph serde constructs and the allocation-free
    /// compact-width traversal performed while that graph is owned. Raw input
    /// bytes and parsing CPU remain separately and mechanically charged by
    /// [`Self::load_work_claim`], which ends when the load finishes.
    pub const fn loader_residual_claim(&self) -> ResourceClaim {
        self.loader_residual_claim
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
    /// is released here once the buffer is gone; `loader_residual` covers the
    /// config and travels out inside the returned owner.
    pub fn commit(
        self,
        loader_residual: ResourceLease,
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
        if loader_residual.claim() != self.loader_residual_claim {
            return Err(Error::Config(
                "config loader residual was not taken for this plan's exact residual claim"
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
            _transaction,
            path,
            loader_residual_claim: _,
            load_work_claim: _,
        } = self;

        ensure_prepared_source_identity(&path, &source)?;

        let value = match source {
            PreparedConfigSource::Missing => MeshConfig::default(),
            PreparedConfigSource::Present { file, len, .. } => {
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
            _loader_residual: loader_residual,
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
        let _transaction = ConfigTransactionLease::acquire(&path)?;
        let (config, _) = load_config_locked(&path)?;
        Ok(config)
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
    /// The broader residual covers defaults because
    /// absent fields expand to defaults and the input's own length says nothing
    /// about that expansion.
    pub fn prepare_load() -> Result<PreparedConfigLoad> {
        let path = crate::dirs::config_path()?;
        let transaction = ConfigTransactionLease::acquire(&path)?;
        let source = match std::fs::File::open(&path) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|e| Error::Config(format!("stat {}: {e}", path.display())))?;
                let len = metadata.len();
                let identity = ConfigFileIdentity::from_file(&file)?;
                PreparedConfigSource::Present {
                    file,
                    len,
                    identity,
                }
            }
            // Absent is the ordinary first-run case, not a failure: the plan
            // will produce defaults, and the loader residual names their
            // allocator graph without pretending the absent file sized it.
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
        // Serde's finished allocator graph is intentionally not inferred from
        // source bytes. The broader residual is acquired before parsing and
        // remains coupled to the resulting config through its final width walk.
        let loader_residual_claim = config_loader_residual_claim();

        let not_representable =
            || Error::Config("config planning claim is not representable".to_string());

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
        // holding; the work claim must cover the path's actual reservation.
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
            _transaction: transaction,
            path,
            loader_residual_claim,
            load_work_claim,
        })
    }

    /// Persist to the default location. Pretty-printed JSON for
    /// easy hand-editing; the file isn't on a hot path.
    pub fn save(&self) -> Result<()> {
        let path = crate::dirs::config_path()?;
        let _transaction = ConfigTransactionLease::acquire(&path)?;
        save_config_locked(&path, self)
    }

    /// Atomically load, mutate, and persist the current configuration.
    ///
    /// The process-local gate and the adjacent OS lock serialize supported
    /// writers. The exact pre-mutation file bytes are then checked again
    /// immediately before the atomic replacement, so an uncoordinated writer
    /// cannot silently erase a disjoint update.
    pub fn transaction<R>(mutate: impl FnOnce(&mut MeshConfig) -> Result<R>) -> Result<R> {
        let path = crate::dirs::config_path()?;
        Self::transaction_at(path, mutate)
    }

    /// Path-parameterized form of [`MeshConfig::transaction`] for embedders
    /// that keep more than one configuration file and for deterministic tests.
    pub fn transaction_at<R>(
        path: impl AsRef<Path>,
        mutate: impl FnOnce(&mut MeshConfig) -> Result<R>,
    ) -> Result<R> {
        let path = path.as_ref();
        let _transaction = ConfigTransactionLease::acquire(path)?;
        let (mut config, baseline) = load_config_locked(path)?;
        let result = mutate(&mut config)?;
        if read_config_bytes(path)? != baseline {
            return Err(Error::Config(format!(
                "config changed during transaction: {}",
                path.display()
            )));
        }
        save_config_locked(path, &config)?;
        Ok(result)
    }

    /// Find a network config by its local `id`.
    pub fn network(&self, id: &str) -> Option<&NetworkConfig> {
        self.networks.iter().find(|n| n.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    };
    use std::thread;

    fn transaction_test_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "myownmesh-config-{}-{}-{}.json",
            label,
            std::process::id(),
            id
        ))
    }

    fn transaction_lock_path(path: &Path) -> PathBuf {
        let mut name = path
            .file_name()
            .expect("transaction test path has a file name")
            .to_os_string();
        name.push(".lock");
        path.with_file_name(name)
    }

    fn remove_transaction_test_files(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(transaction_lock_path(path));
    }

    fn transaction_marker_path(path: &Path, marker: &str) -> PathBuf {
        let mut name = path
            .file_name()
            .expect("transaction test path has a file name")
            .to_os_string();
        name.push(format!(".{marker}"));
        path.with_file_name(name)
    }

    fn wait_for_transaction_marker(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "timed out waiting for transaction marker {}",
            path.display()
        );
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

    #[test]
    fn config_transaction_serializes_same_process_rmw_union() {
        let path = transaction_test_path("union");
        let active = Arc::new(AtomicBool::new(false));
        let overlap = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (first_completed_tx, first_completed_rx) = mpsc::channel();
        let (second_attempt_tx, second_attempt_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let first_path = path.clone();
        let first_active = Arc::clone(&active);
        let first = thread::spawn(move || {
            MeshConfig::transaction_at(&first_path, move |config| {
                assert!(!first_active.swap(true, Ordering::SeqCst));
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                config
                    .networks
                    .push(NetworkConfig::from_network_id("first", "first-wire"));
                first_active.store(false, Ordering::SeqCst);
                first_completed_tx.send(()).unwrap();
                Ok(())
            })
        });

        entered_rx.recv().unwrap();
        let second_path = path.clone();
        let second_active = Arc::clone(&active);
        let second_overlap = Arc::clone(&overlap);
        let second = thread::spawn(move || {
            second_attempt_tx.send(()).unwrap();
            MeshConfig::transaction_at(&second_path, move |config| {
                second_entered_tx.send(()).unwrap();
                if second_active.swap(true, Ordering::SeqCst) {
                    second_overlap.store(true, Ordering::SeqCst);
                }
                config.services.signaling.enabled = true;
                second_active.store(false, Ordering::SeqCst);
                Ok(())
            })
        });

        second_attempt_rx.recv().unwrap();
        assert!(second_entered_rx
            .recv_timeout(Duration::from_millis(25))
            .is_err());
        release_tx.send(()).unwrap();
        first_completed_rx.recv().unwrap();
        second_entered_rx.recv().unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        let final_config = MeshConfig::transaction_at(&path, |config| Ok(config.clone())).unwrap();
        assert!(!overlap.load(Ordering::SeqCst));
        assert!(final_config.services.signaling.enabled);
        assert_eq!(final_config.networks.len(), 1);
        assert_eq!(final_config.networks[0].id, "first");
        remove_transaction_test_files(&path);
    }

    #[test]
    fn config_transaction_subprocess_worker() {
        let Some(path) = std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let attempted = PathBuf::from(
            std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_ATTEMPTED")
                .expect("child attempted marker"),
        );
        let entered = PathBuf::from(
            std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_ENTERED").expect("child entered marker"),
        );
        let completed = PathBuf::from(
            std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_COMPLETED")
                .expect("child completed marker"),
        );
        std::fs::write(&attempted, b"attempted").expect("child attempted marker write");
        MeshConfig::transaction_at(&path, |config| {
            std::fs::write(&entered, b"entered").expect("child entered marker write");
            config.services.signaling.enabled = true;
            Ok(())
        })
        .expect("child transaction");
        std::fs::write(&completed, b"completed").expect("child completed marker write");
    }

    #[test]
    fn config_transaction_serializes_cross_process_rmw_union() {
        let path = transaction_test_path("subprocess");
        let attempted = transaction_marker_path(&path, "attempted");
        let entered = transaction_marker_path(&path, "entered");
        let completed = transaction_marker_path(&path, "completed");
        let (parent_entered_tx, parent_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let parent_path = path.clone();
        let parent = thread::spawn(move || {
            MeshConfig::transaction_at(&parent_path, move |config| {
                parent_entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                config
                    .networks
                    .push(NetworkConfig::from_network_id("parent", "parent-wire"));
                Ok(())
            })
        });

        parent_entered_rx.recv().unwrap();
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("config::tests::config_transaction_subprocess_worker")
            .arg("--nocapture")
            .env("MYOWNMESH_CONFIG_TX_CHILD_PATH", path.as_os_str())
            .env("MYOWNMESH_CONFIG_TX_CHILD_ATTEMPTED", attempted.as_os_str())
            .env("MYOWNMESH_CONFIG_TX_CHILD_ENTERED", entered.as_os_str())
            .env("MYOWNMESH_CONFIG_TX_CHILD_COMPLETED", completed.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn transaction child");

        wait_for_transaction_marker(&attempted);
        thread::sleep(Duration::from_millis(50));
        assert!(!entered.exists(), "child entered before parent release");
        assert!(child.try_wait().unwrap().is_none(), "child completed early");
        release_tx.send(()).unwrap();
        parent.join().unwrap().unwrap();
        wait_for_transaction_marker(&entered);
        wait_for_transaction_marker(&completed);
        assert!(child.wait().unwrap().success());

        let final_config = MeshConfig::transaction_at(&path, |config| Ok(config.clone())).unwrap();
        assert!(final_config.services.signaling.enabled);
        assert_eq!(final_config.networks.len(), 1);
        assert_eq!(final_config.networks[0].id, "parent");
        remove_transaction_test_files(&path);
        let _ = std::fs::remove_file(attempted);
        let _ = std::fs::remove_file(entered);
        let _ = std::fs::remove_file(completed);
    }

    #[test]
    fn config_transaction_rejects_uncoordinated_replacement() {
        let path = transaction_test_path("cas");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let transaction_path = path.clone();
        let transaction = thread::spawn(move || {
            MeshConfig::transaction_at(&transaction_path, move |config| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                config.services.signaling.enabled = true;
                Ok(())
            })
        });

        entered_rx.recv().unwrap();
        let mut replacement = MeshConfig::default();
        replacement.services.turn.enabled = true;
        save_config_locked(&path, &replacement).unwrap();
        release_tx.send(()).unwrap();
        let error = transaction.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("changed during transaction"));
        remove_transaction_test_files(&path);
    }

    #[test]
    fn prepared_load_rejects_corrupt_to_valid_replacement() {
        let path = transaction_test_path("prepared-identity");
        std::fs::write(&path, b"{ corrupt config").unwrap();
        let transaction = ConfigTransactionLease::acquire(&path).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let source = PreparedConfigSource::Present {
            len: metadata.len(),
            identity: ConfigFileIdentity::from_file(&file).unwrap(),
            file,
        };

        // A direct atomic replacement is not allowed to make the prepared
        // handle quarantine valid V in place of the corrupt C it measured.
        save_config_locked(&path, &MeshConfig::default()).unwrap();
        assert!(ensure_prepared_source_identity(&path, &source).is_err());

        drop(source);
        drop(transaction);
        remove_transaction_test_files(&path);
    }
}
