//! Concrete mDNS/DNS-SD signaling driver — the LAN-local counterpart
//! of [`crate::nostr::driver`]. Discovery rides DNS-SD (one
//! [`wire::SERVICE_TYPE`] service instance per driver, room handle in
//! TXT); the SDP/candidate exchange rides a unicast TCP connection to
//! the port advertised in SRV, because an SDP with its candidate set
//! is far too large for TXT records.
//!
//! Deliberate properties:
//!
//! - **Clock-free.** No TLS, no timestamps — signaling works on a
//!   host whose wall clock is still at the epoch (a NanoKVM before
//!   its NTP sync), which is exactly the window local claiming has
//!   to cover.
//! - **Untrusted, like a public Nostr room.** Anything on the LAN
//!   can observe the advertisement or inject frames. The engine's
//!   ed25519 mutual-auth handshake over the DTLS channel that this
//!   signaling bootstraps remains the real authentication gate; a
//!   forged frame can at worst waste a handshake attempt.
//! - **Pluggable discovery backend.** The registration/browse half lives
//!   behind [`super::discovery`]: the pure-Rust `mdns-sd` daemon by default
//!   (per-driver socket set, coexists with a system daemon via
//!   SO_REUSEADDR/SO_REUSEPORT), or the platform's own DNS-SD daemon through
//!   the `dnssd` C API on iOS (raw multicast sockets are entitlement-gated
//!   there; mDNSResponder isn't). The exchange below is backend-independent.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, trace, warn};

use super::discovery::{Discovery, DiscoveryConfig, DiscoveryEvent};
use super::wire::{self, DeviceIdValidator, Frame};
use crate::nostr::handle::derive_room_handle;
use crate::{
    CarrierAttribution, ErasedOwner, ErasedSource, Error, InboundSink, OutboundSource, OwnedSignal,
    SignalingMessage,
};

/// Maximum number of accepted or dialed exchanges owned by one driver.
pub const MAX_ACTIVE_CONNECTIONS: usize = 256;

/// Configuration for one driver instance.
#[derive(Clone)]
pub struct MdnsDriverConfig {
    /// App-id used in the room-handle derivation — same value the
    /// Nostr driver uses, so both transports converge on one room
    /// per `(app_id, network_id)`.
    pub app_id: String,
    /// Network id (the user-facing identifier; the room handle is
    /// derived from `(app_id, network_id)`).
    pub network_id: String,
    /// Our peer's wire-level device id (the ed25519 pubkey surfaced
    /// by the mesh layer).
    pub device_id: String,
    /// Port for the TCP exchange listener. 0 (the default) binds an
    /// ephemeral port; the actual port is advertised via SRV.
    pub service_port: u16,
    /// Application-owned canonical Device-ID policy. Signaling must not
    /// duplicate the identity representation used by the core crate.
    pub device_id_validator: DeviceIdValidator,
    /// Application-owned custody for every retained service alias.
    pub alias_provider: Arc<dyn AliasProvider>,
}

impl std::fmt::Debug for MdnsDriverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsDriverConfig")
            .field("app_id", &self.app_id)
            .field("network_id", &self.network_id)
            .field("device_id", &self.device_id)
            .field("service_port", &self.service_port)
            .finish_non_exhaustive()
    }
}

/// Typed refusal from the application's exact alias custody provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasRefusal {
    Provider(String),
    Arithmetic(String),
}

/// The complete pre-admission retention plan for one alias. The application
/// provider charges both content and the fixed structural cells before the
/// alias table is mutated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasRetention {
    pub key_capacity: usize,
    pub peer_capacity: usize,
    pub node_bytes: usize,
}

/// Complete pre-admission plan for one retained peer observation. The peer
/// table is intrusive, so these are the exact moved buffers and node rather
/// than an estimate for a collection's hidden bucket capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRetention {
    pub peer_capacity: usize,
    pub address_capacity: usize,
    pub node_bytes: usize,
}

impl PeerRetention {
    fn for_peer(peer: &String, addrs: &Vec<IpAddr>) -> Self {
        Self::from_parts(peer.capacity(), addrs)
    }

    fn from_parts(peer_capacity: usize, addrs: &Vec<IpAddr>) -> Self {
        Self {
            peer_capacity,
            address_capacity: addrs.capacity(),
            node_bytes: std::mem::size_of::<PeerNode>(),
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        let address_bytes = self
            .address_capacity
            .checked_mul(std::mem::size_of::<IpAddr>())
            .ok_or_else(|| AliasRefusal::Arithmetic("peer address size overflow".into()))?;
        self.peer_capacity
            .checked_add(address_bytes)
            .and_then(|bytes| bytes.checked_add(self.node_bytes))
            .ok_or_else(|| AliasRefusal::Arithmetic("peer content size overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("peer content size exceeds u64".into()))
    }

    pub fn allocation_count(self) -> std::result::Result<u64, AliasRefusal> {
        let count = 1usize
            .checked_add(usize::from(self.peer_capacity != 0))
            .and_then(|count| count.checked_add(usize::from(self.address_capacity != 0)))
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| AliasRefusal::Arithmetic("peer allocation count overflow".into()))?;
        count
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("peer allocation count exceeds u64".into()))
    }
}

/// Exact stream-time custody plan. The fixed queue and worker shape comes
/// from the existing driver constants; no future connection is reserved at
/// discovery time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRetention {
    pub key_capacity: usize,
    pub node_bytes: usize,
    pub socket_handles: usize,
    pub native_objects: usize,
    pub queue_slots: usize,
    pub worker_tasks: usize,
    pub opaque_allocations: usize,
}

/// Additional exact identity-buffer plan for an inbound stream whose sender
/// is not known until its first validated frame. This is acquired before the
/// sender key enters the intrusive connection registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionIdentityRetention {
    pub key_capacity: usize,
}

impl ConnectionIdentityRetention {
    /// Plan the exact identity buffer retained when an inbound peer becomes
    /// known from its first validated frame.
    pub fn for_peer(peer: &str) -> Self {
        Self {
            key_capacity: peer.len(),
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        self.key_capacity
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("connection identity size exceeds u64".into()))
    }

    pub fn opaque_count(self) -> std::result::Result<u64, AliasRefusal> {
        1u64.checked_add(u64::from(self.key_capacity != 0))
            .ok_or_else(|| {
                AliasRefusal::Arithmetic("connection identity residual count overflow".into())
            })
    }
}

impl ConnectionRetention {
    /// Plan one concrete connection using the exact wire representation of
    /// its known peer, when present.  An inbound stream has no peer key until
    /// its first authenticated frame and therefore contributes no key bytes
    /// to this plan; its identity buffer is planned separately.
    pub fn for_peer(key: Option<&str>) -> Self {
        Self {
            key_capacity: key.map_or(0, str::len),
            node_bytes: std::mem::size_of::<ConnNode>(),
            socket_handles: 2,
            native_objects: 1,
            queue_slots: OUTBOUND_QUEUE_CAP,
            worker_tasks: 2,
            // One channel allocation and one erased provider-owner allocation.
            opaque_allocations: 2,
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        self.key_capacity
            .checked_add(self.node_bytes)
            .ok_or_else(|| AliasRefusal::Arithmetic("connection content size overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("connection content size exceeds u64".into()))
    }

    pub fn opaque_count(self) -> std::result::Result<u64, AliasRefusal> {
        self.queue_slots
            .checked_add(self.worker_tasks)
            .and_then(|count| count.checked_add(self.opaque_allocations))
            .ok_or_else(|| AliasRefusal::Arithmetic("connection residual count overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("connection residual count exceeds u64".into()))
    }
}

impl AliasRetention {
    fn for_alias(key: &String, peer: &String) -> Self {
        Self {
            key_capacity: key.capacity(),
            peer_capacity: peer.capacity(),
            node_bytes: std::mem::size_of::<AliasNode>(),
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        self.key_capacity
            .checked_add(self.peer_capacity)
            .and_then(|bytes| bytes.checked_add(self.node_bytes))
            .ok_or_else(|| AliasRefusal::Arithmetic("alias content size overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("alias content size exceeds u64".into()))
    }

    pub fn allocation_count(self) -> std::result::Result<u64, AliasRefusal> {
        let count = 1usize
            .checked_add(usize::from(self.key_capacity != 0))
            .and_then(|count| count.checked_add(usize::from(self.peer_capacity != 0)))
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| AliasRefusal::Arithmetic("alias allocation count overflow".into()))?;
        count
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("alias allocation count exceeds u64".into()))
    }
}

/// Required application seam for retaining one discovered service alias.
/// The returned owner is held until that exact alias is removed or displaced.
pub trait AliasProvider: Send + Sync {
    fn retain_alias(
        &self,
        key: &str,
        peer: &str,
        retention: AliasRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    /// Reserve the exact intrusive peer node and moved endpoint buffers
    /// before the peer registry is changed.
    fn retain_peer(
        &self,
        peer: &str,
        retention: PeerRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    /// Reserve one concrete stream, its fixed queue/task shape, and registry
    /// node immediately before the stream is split or published.
    fn retain_connection(
        &self,
        peer: Option<&str>,
        retention: ConnectionRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    /// Reserve the exact sender identity buffer for an inbound stream whose
    /// peer becomes known only after its first validated frame.
    fn retain_connection_identity(
        &self,
        peer: &str,
        retention: ConnectionIdentityRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;
}

/// Inbound signaling events the driver pushes to the engine.
/// Mirrors [`crate::nostr::driver::NostrInbound`].
#[derive(Debug, Clone)]
pub enum MdnsInbound {
    /// A peer's advertisement resolved (or refreshed) in our room.
    PeerAnnounced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer's advertisement was withdrawn (mDNS goodbye) or its
    /// record expired from the cache.
    PeerLeft {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer addressed us directly over the TCP exchange.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
/// Mirrors [`crate::nostr::driver::NostrOutbound`].
#[derive(Debug, Clone)]
pub enum MdnsOutbound {
    /// Ensure our advertisement is registered. The registration is
    /// the announce — mDNS handles repetition and query responses —
    /// so repeats are cheap no-ops.
    Announce,
    /// Withdraw the advertisement (sends the mDNS goodbye, which
    /// surfaces as `PeerLeft` on every browser).
    Leave,
    DirectedToPeer {
        to: String,
        msg: SignalingMessage,
    },
}

/// How long a dial to a peer's advertised exchange port may take
/// before we try its next address (or give up).
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// An outbound exchange connection is closed after this much idle —
/// signaling for one handshake is bursty; anything longer-lived than
/// a burst should re-dial.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Inbound exchange connections are dropped after this much idle.
const INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_DISCOVERED_PEERS: usize = 1024;
const OUTBOUND_QUEUE_CAP: usize = 128;

/// Cadence of the local re-announce tick: every interval, each peer
/// still present in the mDNS cache is re-surfaced to the engine as a
/// `PeerAnnounced`. This mirrors the Nostr driver's ~60 s steady
/// announce heartbeat, which the engine's re-offer pacing expects —
/// a peer stuck at Sighted is re-offered on announce arrivals.
const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(60);

/// Start the driver. Fails fast if the mDNS daemon or the TCP
/// listener can't come up (unlike Nostr, the fallible setup here is
/// synchronous) — callers keep their engine-side receiver and can
/// fall back to other transports.
pub fn start<S>(
    config: MdnsDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<MdnsInbound>,
) -> crate::Result<MdnsDriverHandle>
where
    S: OutboundSource<MdnsOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    if !(config.device_id_validator)(&config.device_id) {
        return Err(Error::Other("mDNS local device id is not canonical".into()));
    }
    let room_handle = derive_room_handle(&config.app_id, &config.network_id);

    // TCP exchange listener first — its port goes into the SRV record.
    let std_listener = std::net::TcpListener::bind(("0.0.0.0", config.service_port))
        .map_err(|e| Error::Bind(format!("0.0.0.0:{}", config.service_port), e))?;
    let port = std_listener
        .local_addr()
        .map_err(|e| Error::Bind("local_addr".into(), e))?
        .port();
    std_listener
        .set_nonblocking(true)
        .map_err(|e| Error::Bind("set_nonblocking".into(), e))?;

    let instance = wire::instance_name(&room_handle, &config.device_id);
    // Browse starts inside the backend before the first register, so we never
    // miss a burst of resolves racing our own announce.
    let (mut discovery, browse_rx) = Discovery::start(&DiscoveryConfig {
        service_type: wire::SERVICE_TYPE.to_string(),
        instance,
        port,
        txt: wire::txt_properties(&room_handle, &config.device_id),
    })?;
    let discovery_task = discovery.take_task();
    let discovery = Arc::new(discovery);

    // Soft failure (e.g. no usable interface yet) — the re-announce tick
    // retries registration.
    let registered = discovery.register();
    if !registered {
        warn!("mdns register failed (will retry)");
    }

    info!(
        network = %config.network_id,
        room_handle = %&room_handle[..room_handle.len().min(16)],
        port,
        "starting mDNS driver"
    );

    let shared = Arc::new(Shared {
        room_handle,
        device_id: config.device_id,
        device_id_validator: config.device_id_validator,
        alias_provider: config.alias_provider,
        discovery: discovery.clone(),
        registered: AtomicBool::new(registered),
        peers: Mutex::new(PeerOwnership::default()),
        aliases: Mutex::new(AliasOwnership::default()),
        conns: Mutex::new(ConnectionOwnership::default()),
        connection_slots: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
        connection_tasks: Arc::new(Mutex::new(Some(JoinSet::new()))),
        stopped: Arc::new(AtomicBool::new(false)),
        // Zero is the permanent exhausted sentinel; live connections start
        // at the first nonzero generation so the first adoption is usable.
        conn_gen: AtomicU64::new(1),
        inbound_tx,
        cancel: watch::channel(false).0,
    });

    let mut tasks = Vec::new();
    if let Some(task) = discovery_task {
        tasks.push(task);
    }

    // Browse pump: mDNS resolutions → peer table + PeerAnnounced/PeerLeft.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_browse(shared, browse_rx).await;
            trace!("mdns browse pump exiting");
        }));
    }

    // Outbound pump: engine events → registration changes + TCP frames.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_outbound(shared, Box::new(ErasedSource::new(outbound))).await;
            trace!("mdns outbound pump exiting");
        }));
    }

    // Accept loop for the TCP exchange.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_accept(shared, std_listener).await;
            trace!("mdns accept loop exiting");
        }));
    }

    // Re-announce tick — see [`REANNOUNCE_INTERVAL`].
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_reannounce(shared).await;
        }));
    }

    Ok(MdnsDriverHandle {
        discovery,
        tasks,
        connection_tasks: shared.connection_tasks.clone(),
        stopped: shared.stopped.clone(),
        cancel: shared.cancel.clone(),
    })
}

/// Handle returned by [`start`]. Drop or call [`Self::stop`] to
/// withdraw the advertisement and stop every spawned task.
pub struct MdnsDriverHandle {
    discovery: Arc<Discovery>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    connection_tasks: Arc<Mutex<Option<JoinSet<()>>>>,
    stopped: Arc<AtomicBool>,
    cancel: watch::Sender<bool>,
}

impl MdnsDriverHandle {
    fn request_stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.cancel.send(true);
        // Goodbye first (peers get PeerLeft promptly), then shut the
        // backend down (closes the browse stream). The async owner joins
        // tasks after this signal; the compatibility stop aborts them.
        self.discovery.unregister();
        self.discovery.shutdown();
    }

    /// Signal shutdown and join every driver-owned Tokio task.
    pub async fn stop_and_join(mut self) {
        self.request_stop();
        while let Some(task) = self.tasks.pop() {
            let _ = task.await;
        }
        let mut connection_tasks = self.connection_tasks.lock().take().unwrap_or_default();
        while connection_tasks.join_next().await.is_some() {}
    }

    /// Compatibility signal-only stop for callers that cannot await. The
    /// owning async boundary should prefer [`Self::stop_and_join`].
    pub fn stop(&self) {
        self.request_stop();
        for t in &self.tasks {
            t.abort();
        }
        if let Some(mut connection_tasks) = self.connection_tasks.lock().take() {
            connection_tasks.abort_all();
        }
    }
}

impl Drop for MdnsDriverHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Shared {
    room_handle: String,
    device_id: String,
    device_id_validator: DeviceIdValidator,
    alias_provider: Arc<dyn AliasProvider>,
    discovery: Arc<Discovery>,
    registered: AtomicBool,
    /// Peers resolved in our room: device id → exchange endpoint.
    peers: Mutex<PeerOwnership>,
    /// Exact backend service aliases grouped by decoded peer. A peer is
    /// withdrawn only after its final alias disappears.
    aliases: Mutex<AliasOwnership>,
    /// Live exchange connections, either direction: device id →
    /// writer. Outbound dials register at connect; inbound accepts
    /// register under the first `from` their frames carry, so a reply
    /// can ride the same socket the request arrived on.
    conns: Mutex<ConnectionOwnership>,
    connection_slots: Arc<Semaphore>,
    connection_tasks: Arc<Mutex<Option<JoinSet<()>>>>,
    stopped: Arc<AtomicBool>,
    conn_gen: AtomicU64,
    inbound_tx: InboundSink<MdnsInbound>,
    cancel: watch::Sender<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerEntry {
    addrs: Vec<IpAddr>,
    port: u16,
}

struct PeerNode {
    peer: String,
    entry: PeerEntry,
    owner: ErasedOwner,
    next: Option<Box<PeerNode>>,
}

#[derive(Default)]
struct PeerOwnership {
    head: Option<Box<PeerNode>>,
    count: usize,
}

impl PeerOwnership {
    fn contains(&self, peer: &str) -> bool {
        self.get(peer).is_some()
    }

    fn get(&self, peer: &str) -> Option<PeerEntry> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                return Some(current.entry.clone());
            }
            node = current.next.as_deref();
        }
        None
    }

    fn keys(&self) -> Vec<String> {
        let mut peers = Vec::with_capacity(self.count);
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            peers.push(current.peer.clone());
            node = current.next.as_deref();
        }
        peers
    }

    fn can_insert(&self, peer: &str) -> std::result::Result<(), AliasRefusal> {
        if self.contains(peer) || self.count < MAX_DISCOVERED_PEERS {
            return Ok(());
        }
        Err(AliasRefusal::Provider("peer capacity exhausted".into()))
    }

    fn peer_capacity(&self, peer: &str) -> Option<usize> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                return Some(current.peer.capacity());
            }
            node = current.next.as_deref();
        }
        None
    }

    fn refresh(
        &mut self,
        peer: &str,
        entry: PeerEntry,
        owner: ErasedOwner,
    ) -> std::result::Result<(), AliasRefusal> {
        if let Some(node) = self.find_mut(peer) {
            node.entry = entry;
            node.owner = owner;
            return Ok(());
        }
        Err(AliasRefusal::Provider("peer refresh lost its node".into()))
    }

    fn insert_new(
        &mut self,
        peer: String,
        entry: PeerEntry,
        owner: ErasedOwner,
    ) -> std::result::Result<(), AliasRefusal> {
        self.can_insert(&peer)?;
        let next = self.head.take();
        self.head = Some(Box::new(PeerNode {
            peer,
            entry,
            owner,
            next,
        }));
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| AliasRefusal::Arithmetic("peer count overflow".into()))?;
        Ok(())
    }

    fn remove(&mut self, peer: &str) -> Option<PeerEntry> {
        let mut link = &mut self.head;
        loop {
            let node = link.as_ref()?;
            if node.peer == peer {
                let mut removed = link.take().expect("peer link still present");
                *link = removed.next.take();
                self.count = self.count.checked_sub(1).expect("peer count present");
                return Some(removed.entry);
            }
            link = &mut link.as_mut().expect("peer link present").next;
        }
    }

    fn find_mut(&mut self, peer: &str) -> Option<&mut PeerNode> {
        let mut node = self.head.as_deref_mut();
        while let Some(current) = node {
            if current.peer == peer {
                return Some(current);
            }
            node = current.next.as_deref_mut();
        }
        None
    }
}

/// Exact DNS-SD alias ownership. A decoded peer may be represented by more
/// than one backend service key (for example, one per interface), so one key's
/// removal cannot withdraw the peer while another key remains live.
#[derive(Default)]
pub struct AliasOwnership {
    head: Option<Box<AliasNode>>,
    count: usize,
}

struct AliasNode {
    key: String,
    peer: String,
    generation: u64,
    owner: ErasedOwner,
    next: Option<Box<AliasNode>>,
}

impl AliasOwnership {
    /// Bind one exact service key to a decoded peer. Returns an old peer only
    /// when rebinding made that peer lose its final alias.
    pub fn bind(
        &mut self,
        key: String,
        peer: String,
        generation: u64,
        owner: ErasedOwner,
    ) -> std::result::Result<Option<String>, AliasRefusal> {
        let displaced = self
            .peer_for_key(&key)
            .filter(|old_peer| old_peer != &peer)
            .filter(|old_peer| !self.has_other_alias(&key, old_peer));
        let mut cursor = self.head.as_mut();
        while let Some(node) = cursor {
            if node.key == key {
                node.peer = peer;
                node.generation = generation;
                node.owner = owner;
                return Ok(displaced);
            }
            cursor = node.next.as_mut();
        }
        if self.count == usize::MAX {
            drop(owner);
            return Err(AliasRefusal::Arithmetic("alias count overflow".into()));
        }
        let node = Box::new(AliasNode {
            key,
            peer: peer.clone(),
            generation,
            owner,
            next: self.head.take(),
        });
        self.head = Some(node);
        self.count = self.count.checked_add(1).expect("alias count prechecked");
        Ok(None)
    }

    /// Remove one exact service key. The boolean is true only when its peer
    /// has no remaining aliases.
    pub fn remove(&mut self, key: &str, generation: u64) -> Option<(String, bool)> {
        let mut link = &mut self.head;
        loop {
            let node = link.as_ref()?;
            if node.key == key {
                if node.generation != generation {
                    return None;
                }
                let mut removed = link.take().expect("alias link still present");
                *link = removed.next.take();
                self.count = self.count.checked_sub(1).expect("alias count present");
                let peer = removed.peer;
                let last = !self.contains_peer(&peer);
                return Some((peer, last));
            }
            link = &mut link.as_mut().expect("alias link present").next;
        }
    }

    /// Number of aliases currently attached to one decoded peer.
    pub fn alias_count(&self, peer: &str) -> usize {
        let mut count = 0;
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                count += 1;
            }
            node = current.next.as_deref();
        }
        count
    }

    fn contains_peer(&self, peer: &str) -> bool {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                return true;
            }
            node = current.next.as_deref();
        }
        false
    }

    fn has_other_alias(&self, key: &str, peer: &str) -> bool {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.key != key && current.peer == peer {
                return true;
            }
            node = current.next.as_deref();
        }
        false
    }

    fn peer_for_key(&self, key: &str) -> Option<String> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.key == key {
                return Some(current.peer.clone());
            }
            node = current.next.as_deref();
        }
        None
    }
}

#[derive(Clone)]
struct ConnHandle {
    generation: u64,
    tx: mpsc::Sender<OwnedSignal<String, ErasedOwner>>,
    stop: watch::Sender<bool>,
}

struct ConnNode {
    peer: Arc<str>,
    handle: ConnHandle,
    _owner: ErasedOwner,
    next: Option<Box<ConnNode>>,
}

#[derive(Default)]
struct ConnectionOwnership {
    head: Option<Box<ConnNode>>,
}

impl ConnectionOwnership {
    fn sender(&self, peer: &str) -> Option<mpsc::Sender<OwnedSignal<String, ErasedOwner>>> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer.as_ref() == peer {
                return Some(current.handle.tx.clone());
            }
            node = current.next.as_deref();
        }
        None
    }

    fn insert(
        &mut self,
        peer: Arc<str>,
        handle: ConnHandle,
        owner: ErasedOwner,
    ) -> Option<ConnHandle> {
        let displaced = self.remove(&peer, None).map(|node| node.handle);
        self.head = Some(Box::new(ConnNode {
            peer,
            handle,
            _owner: owner,
            next: self.head.take(),
        }));
        displaced
    }

    fn remove(&mut self, peer: &str, generation: Option<u64>) -> Option<ConnNode> {
        let mut link = &mut self.head;
        loop {
            let node = link.as_ref()?;
            if node.peer.as_ref() == peer
                && generation.is_none_or(|generation| node.handle.generation == generation)
            {
                let mut removed = link.take().expect("connection link still present");
                *link = removed.next.take();
                return Some(*removed);
            }
            link = &mut link.as_mut().expect("connection link present").next;
        }
    }

    fn remove_generation(&mut self, peer: &str, generation: u64) {
        let _ = self.remove(peer, Some(generation));
    }
}

/// A connection slot remains occupied until both halves have observed the
/// connection's local stop signal and released their shared owner.
struct ConnectionLease {
    _permit: OwnedSemaphorePermit,
}

fn next_connection_generation(counter: &AtomicU64) -> Option<u64> {
    // MAX is the final valid generation.  Advance to zero only after handing
    // it out; zero is the permanent exhausted sentinel and is never reused
    // for a later connection fence.
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            if value == 0 {
                None
            } else if value == u64::MAX {
                Some(0)
            } else {
                Some(value + 1)
            }
        })
        .ok()
}

async fn run_browse(shared: Arc<Shared>, mut browse_rx: mpsc::Receiver<DiscoveryEvent>) {
    // Stream closes when the backend shuts down.
    let mut cancel = shared.cancel.subscribe();
    loop {
        let event = tokio::select! {
            event = browse_rx.recv() => event,
            _ = cancel.changed() => return,
        };
        let Some(event) = event else { break };
        if *cancel.borrow() {
            return;
        }
        match event {
            DiscoveryEvent::Resolved {
                generation,
                key,
                mut addrs,
                port,
                txt,
            } => {
                let advert = wire::parse_advert(
                    |k| txt.get(k).cloned(),
                    &shared.room_handle,
                    &shared.device_id,
                    shared.device_id_validator,
                );
                let Some(advert) = advert else { continue };
                if addrs.is_empty() {
                    trace!(peer = %advert.peer, "mdns advert without IPv4 address — skipped");
                    continue;
                }
                addrs.sort();
                let entry = PeerEntry { addrs, port };
                let peer = advert.peer;
                let peers = shared.peers.lock();
                let known = peers.contains(&peer);
                let at_capacity = peers.count >= MAX_DISCOVERED_PEERS;
                let peer_capacity_ok = peers.can_insert(&peer).is_ok();
                let existing_peer_capacity = peers.peer_capacity(&peer);
                drop(peers);
                if (!known && at_capacity) || !peer_capacity_ok {
                    continue;
                }
                let peer_node = (!known).then(|| peer.clone());
                let peer_retention = match peer_node.as_ref() {
                    Some(peer_node) => PeerRetention::for_peer(peer_node, &entry.addrs),
                    None => {
                        PeerRetention::from_parts(existing_peer_capacity.unwrap_or(0), &entry.addrs)
                    }
                };
                let peer_owner = match shared.alias_provider.retain_peer(&peer, peer_retention) {
                    Ok(owner) => owner,
                    Err(refusal) => {
                        debug!(?refusal, "mdns peer retention refused");
                        continue;
                    }
                };
                let retention = AliasRetention::for_alias(&key, &peer);
                let alias_owner = match shared.alias_provider.retain_alias(&key, &peer, retention) {
                    Ok(owner) => owner,
                    Err(refusal) => {
                        drop(peer_owner);
                        debug!(?refusal, "mdns alias retention refused");
                        continue;
                    }
                };
                let bind_result = {
                    let mut aliases = shared.aliases.lock();
                    aliases.bind(key.clone(), peer, generation, alias_owner)
                };
                let (displaced, current_peer) = match bind_result {
                    Ok(displaced) => {
                        let current_peer = shared
                            .aliases
                            .lock()
                            .peer_for_key(&key)
                            .expect("bound alias has a peer");
                        (displaced, current_peer)
                    }
                    Err(refusal) => {
                        drop(peer_owner);
                        debug!(?refusal, "mdns alias bind refused");
                        continue;
                    }
                };
                if let Some(old_peer) = displaced {
                    shared.peers.lock().remove(&old_peer);
                    stop_connection(&shared, &old_peer);
                    debug!(peer = %&old_peer[..old_peer.len().min(16)], "mdns peer lost final alias");
                    if shared
                        .inbound_tx
                        .send(MdnsInbound::PeerLeft {
                            device_id: old_peer,
                            attribution: CarrierAttribution::SenderClaimed,
                        })
                        .is_err()
                    {
                        let _ = shared.cancel.send(true);
                        return;
                    }
                }
                let peer_result = if known {
                    shared
                        .peers
                        .lock()
                        .refresh(&current_peer, entry, peer_owner)
                } else {
                    shared.peers.lock().insert_new(
                        peer_node.expect("new peer node was prepared"),
                        entry,
                        peer_owner,
                    )
                };
                if let Err(refusal) = peer_result {
                    debug!(?refusal, "mdns peer bind refused after pre-admission");
                    return;
                }
                debug!(peer = %&current_peer[..current_peer.len().min(16)], "mdns peer resolved");
                // Every resolve (first sight or cache refresh) surfaces as
                // an announce; the engine is idempotent on repeats, same
                // as with periodic Nostr announces.
                //
                // **`SenderClaimed`, and the mDNS daemon seeing the record is
                // not what makes it otherwise.** The device id here was parsed
                // out of the advertisement's TXT record, which any LAN
                // participant may write with any value: what the daemon
                // established is that *a record* appeared, not whose device it
                // names. The same holds for the expiry and re-surface sites
                // below - withdrawing a record you advertised proves nothing
                // about the device id inside it. Until an mDNS service record
                // carries an independently authenticated binding to the device
                // key, none of this carrier's presence or withdrawal is a
                // carrier-established identity.
                if shared
                    .inbound_tx
                    .send(MdnsInbound::PeerAnnounced {
                        attribution: CarrierAttribution::SenderClaimed,
                        device_id: current_peer,
                    })
                    .is_err()
                {
                    let _ = shared.cancel.send(true);
                    return;
                }
            }
            DiscoveryEvent::Removed { generation, key } => {
                if let Some((peer, last)) = shared.aliases.lock().remove(&key, generation) {
                    if !last {
                        continue;
                    }
                    shared.peers.lock().remove(&peer);
                    stop_connection(&shared, &peer);
                    debug!(peer = %&peer[..peer.len().min(16)], "mdns peer withdrew");
                    if shared
                        .inbound_tx
                        .send(MdnsInbound::PeerLeft {
                            device_id: peer,
                            attribution: CarrierAttribution::SenderClaimed,
                        })
                        .is_err()
                    {
                        let _ = shared.cancel.send(true);
                        return;
                    }
                }
            }
        }
    }
}

async fn run_outbound(
    shared: Arc<Shared>,
    mut source: Box<dyn OutboundSource<MdnsOutbound, Owner = ErasedOwner>>,
) {
    let mut cancel = shared.cancel.subscribe();
    loop {
        let Some(outbound) = (tokio::select! {
            outbound = source.recv() => outbound,
            _ = cancel.changed() => return,
        }) else {
            break;
        };
        // Dispatched on a borrow. Only the directed arm builds anything, and it
        // is handed the whole owned signal so the encoded line inherits the
        // funding instead of becoming an unowned allocation beside it. The two
        // registration arms build nothing and drop the signal — and its owner —
        // at the end of the iteration.
        if matches!(outbound.value(), MdnsOutbound::DirectedToPeer { .. }) {
            let _ = send_directed(&shared, outbound).await;
            continue;
        }
        let accepted = match outbound.value() {
            MdnsOutbound::Announce => {
                if !shared.registered.load(Ordering::SeqCst) {
                    register(&shared)
                } else {
                    true
                }
                // Already registered: the daemon re-announces and
                // answers queries on its own — nothing to do.
            }
            MdnsOutbound::Leave => {
                if shared.registered.swap(false, Ordering::SeqCst) {
                    shared.discovery.unregister();
                }
                true
            }
            MdnsOutbound::DirectedToPeer { .. } => unreachable!("directed arm handled above"),
        };
        if accepted {
            outbound.accept();
        }
    }
    let _ = shared.cancel.send(true);
    shared.discovery.shutdown();
}

fn register(shared: &Shared) -> bool {
    if shared.discovery.register() {
        shared.registered.store(true, Ordering::SeqCst);
        true
    } else {
        debug!("mdns register retry failed");
        false
    }
}

/// Encode one directed message and get it onto a connection.
///
/// # The encoded line carries the owner, and the writer holds both
///
/// Serializing produces a second allocation the size of the frame. It used to
/// be a bare `String` handed to a writer queue that can park on a slow or dead
/// socket for as long as the connection lasts, with nothing tying that buffer
/// back to whatever admitted the message it came from.
///
/// The encode is a [`OwnedSignal::map`] over the whole signal now, so the line
/// *is* the value and the owner comes with it. The writer queue carries
/// `OwnedSignal<String, ErasedOwner>` and drops an entry only once the write has
/// completed or the connection is gone, so a parked writer keeps its funding
/// live for exactly as long as it keeps the bytes.
async fn send_directed(
    shared: &Arc<Shared>,
    outbound: OwnedSignal<MdnsOutbound, ErasedOwner>,
) -> bool {
    let MdnsOutbound::DirectedToPeer { to, .. } = outbound.value() else {
        return false;
    };
    let to = to.clone();
    let room_handle = shared.room_handle.clone();
    let from = shared.device_id.clone();
    let line = outbound.map(move |outbound| match outbound {
        MdnsOutbound::DirectedToPeer { to, msg } => wire::encode_frame(&Frame {
            v: wire::PROTOCOL_VERSION,
            room: room_handle,
            from,
            to,
            msg,
        }),
        // Unreachable: the borrow above already matched the directed arm, and
        // the value is private, so nothing could have changed it in between.
        // Encoding nothing is the inert answer if that ever stops being true.
        _ => String::new(),
    });
    // Fast path: an existing connection for this peer — in either
    // direction. An inbound connection the peer dialed serves our
    // replies too (see `adopt_stream`), which is what lets a device
    // answer an offer even when its own mDNS view of the offerer is
    // missing or stale (asymmetric visibility).
    // `send` gives the value back when the writer is gone, so a dead connection
    // returns the line *and its owner* here rather than dropping either: the
    // dial below reuses the same allocation and the same funding.
    let commit = line.commit_unit();
    let existing = shared.conns.lock().sender(&to);
    let line = match existing {
        Some(handle) => match handle.try_send(line) {
            Ok(()) => {
                if let Some(commit) = &commit {
                    commit.accept();
                }
                return true;
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(peer = %&to[..to.len().min(16)], "mdns connection outbound queue is full or closed");
                return false;
            }
            Err(mpsc::error::TrySendError::Closed(returned)) => returned,
        },
        None => line,
    };

    // Dial. Snapshot the endpoint before awaiting anything.
    let Some(entry) = shared.peers.lock().get(&to) else {
        debug!(peer = %&to[..to.len().min(16)], "mdns directed message for unknown peer dropped");
        return false;
    };
    // All advertised addresses race concurrently and the first
    // connect wins — a host advertises every interface (docker
    // bridges, secondary NICs, …) and dialing serially would burn a
    // full DIAL_TIMEOUT per dead address, longer than a handshake
    // window.
    let attempts: Vec<_> = entry
        .addrs
        .iter()
        .map(|addr| {
            let addr = *addr;
            let port = entry.port;
            Box::pin(async move {
                timeout(DIAL_TIMEOUT, TcpStream::connect((addr, port)))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout")
                    })?
            })
        })
        .collect();
    match futures::future::select_ok(attempts).await {
        Ok((stream, _rest)) => {
            let Some(tx) = adopt_stream(shared, stream, Some(to.clone())) else {
                debug!(peer = %&to[..to.len().min(16)], "mdns connection identity space exhausted");
                return false;
            };
            match tx.send(line).await {
                Ok(()) => {
                    if let Some(commit) = &commit {
                        commit.accept();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(e) => {
            debug!(
                peer = %&to[..to.len().min(16)],
                "mdns peer unreachable on every advertised address: {e}"
            );
            false
        }
    }
}

/// Take ownership of an exchange connection (dialed or accepted):
/// register its writer in the connection table and spawn the writer +
/// reader tasks. `known_peer` is the peer id for outbound dials;
/// inbound connections register lazily under the first authenticated
/// `from` their frames carry, so replies can ride the same socket.
fn adopt_stream(
    shared: &Arc<Shared>,
    stream: TcpStream,
    known_peer: Option<String>,
) -> Option<mpsc::Sender<OwnedSignal<String, ErasedOwner>>> {
    if shared.stopped.load(Ordering::Acquire) {
        return None;
    }
    let connection_retention = ConnectionRetention::for_peer(known_peer.as_deref());
    let connection_owner = match shared
        .alias_provider
        .retain_connection(known_peer.as_deref(), connection_retention)
    {
        Ok(owner) => owner,
        Err(refusal) => {
            debug!(?refusal, "mdns connection retention refused");
            return None;
        }
    };
    let slot = shared
        .connection_slots
        .clone()
        .try_acquire_owned()
        .ok()
        .map(|_permit| ConnectionLease { _permit })
        .map(Arc::new)?;
    if shared.stopped.load(Ordering::Acquire) {
        return None;
    }
    let generation = next_connection_generation(&shared.conn_gen)?;
    let (read_half, write_half) = stream.into_split();
    let (tx, rx) = mpsc::channel::<OwnedSignal<String, ErasedOwner>>(OUTBOUND_QUEUE_CAP);
    let (local_stop, _) = watch::channel(false);
    // Serialize task registration with stop's drain. Once this guard is
    // acquired, shutdown cannot take the registry between the stopped check
    // and publishing either half's JoinHandle.
    let mut connection_tasks = shared.connection_tasks.lock();
    if shared.stopped.load(Ordering::Acquire) {
        return None;
    }
    // The peer this connection is registered under — set at adopt
    // time for outbound dials, on first frame for inbound accepts.
    let registered_as = Arc::new(Mutex::new(None::<Arc<str>>));
    let pending_owner = Arc::new(Mutex::new(Some(connection_owner)));
    if let Some(peer) = known_peer {
        if shared.stopped.load(Ordering::Acquire) {
            return None;
        }
        let owner = pending_owner
            .lock()
            .take()
            .expect("outbound connection owner is available");
        let peer_key: Arc<str> = Arc::from(peer.as_str());
        let displaced = shared.conns.lock().insert(
            peer_key.clone(),
            ConnHandle {
                generation,
                tx: tx.clone(),
                stop: local_stop.clone(),
            },
            owner,
        );
        if let Some(displaced) = displaced {
            let _ = displaced.stop.send(true);
        }
        *registered_as.lock() = Some(peer_key);
    }

    // Writer: drains the queue onto the socket; exits on idle, write
    // error, or when every sender is gone.
    {
        let shared = shared.clone();
        let registered_as = registered_as.clone();
        let cancel = shared.cancel.subscribe();
        let local_cancel = local_stop.subscribe();
        let local_stop = local_stop.clone();
        let _slot = slot.clone();
        let writer_task = async move {
            run_writer(write_half, rx, cancel, local_cancel).await;
            let _ = local_stop.send(true);
            // Deregister — only our own generation; a newer connection
            // may have replaced this entry already.
            if let Some(peer) = registered_as.lock().clone() {
                shared.conns.lock().remove_generation(&peer, generation);
            }
        };
        let tasks = connection_tasks.as_mut()?;
        tasks.spawn(writer_task);
    }

    // Reader: parses frames addressed to us and (for inbound
    // connections) registers the writer under the sender's id.
    {
        let shared = shared.clone();
        let tx = tx.clone();
        let registered_as = registered_as.clone();
        let pending_owner = pending_owner.clone();
        let local_cancel = local_stop.subscribe();
        let local_stop = local_stop.clone();
        let _slot = slot;
        let reader_task = async move {
            run_reader(&shared, read_half, local_cancel, |from| {
                if shared.stopped.load(Ordering::Acquire) {
                    return;
                }
                let mut reg = registered_as.lock();
                if reg.is_none() {
                    if !shared.peers.lock().contains(from) {
                        return;
                    }
                    let identity_retention = ConnectionIdentityRetention::for_peer(from);
                    let identity_owner = match shared
                        .alias_provider
                        .retain_connection_identity(from, identity_retention)
                    {
                        Ok(owner) => owner,
                        Err(refusal) => {
                            debug!(?refusal, "mdns connection identity retention refused");
                            return;
                        }
                    };
                    let Some(owner) = pending_owner.lock().take() else {
                        drop(identity_owner);
                        return;
                    };
                    let peer_key: Arc<str> = Arc::from(from);
                    let displaced = shared.conns.lock().insert(
                        peer_key.clone(),
                        ConnHandle {
                            generation,
                            tx: tx.clone(),
                            stop: local_stop.clone(),
                        },
                        Box::new((owner, identity_owner)) as ErasedOwner,
                    );
                    if let Some(displaced) = displaced {
                        let _ = displaced.stop.send(true);
                    }
                    *reg = Some(peer_key);
                }
            })
            .await;
            let _ = local_stop.send(true);
            // A dead read side means the conversation is over even if
            // writes would still go through — deregister so the next
            // exchange re-dials.
            if let Some(peer) = registered_as.lock().clone() {
                shared.conns.lock().remove_generation(&peer, generation);
            }
            trace!("mdns exchange connection closed");
        };
        let tasks = connection_tasks.as_mut()?;
        tasks.spawn(reader_task);
    }

    Some(tx)
}

/// Drain the queue onto the socket.
///
/// Each entry is an [`OwnedSignal`], held for the whole of its own write and
/// dropped at the end of the iteration — after the bytes and the newline are on
/// the wire, or immediately on a write error. So while a line is queued behind a
/// slow peer, or parked half-written, the owner that admitted the message it was
/// encoded from is still alive. On exit the receiver is dropped with everything
/// still queued, releasing those owners together.
async fn run_writer(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<OwnedSignal<String, ErasedOwner>>,
    mut cancel: watch::Receiver<bool>,
    mut local_cancel: watch::Receiver<bool>,
) {
    loop {
        let next = tokio::select! {
            next = timeout(CONN_IDLE_TIMEOUT, rx.recv()) => next,
            _ = cancel.changed() => return,
            _ = local_cancel.changed() => return,
        };
        match next {
            Ok(Some(line)) => {
                if write_half.write_all(line.value().as_bytes()).await.is_err() {
                    return;
                }
                if write_half.write_all(b"\n").await.is_err() {
                    return;
                }
                drop(line);
            }
            // Sender dropped (driver stopping / conn replaced) or idle.
            Ok(None) | Err(_) => return,
        }
    }
}

async fn run_accept(shared: Arc<Shared>, std_listener: std::net::TcpListener) {
    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            warn!("mdns exchange listener unusable: {e}");
            return;
        }
    };
    let mut cancel = shared.cancel.subscribe();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => Some(accepted),
            _ = cancel.changed() => return,
        };
        match accepted.expect("listener accept branch selected") {
            Ok((stream, _remote)) => {
                if adopt_stream(&shared, stream, None).is_none() {
                    debug!("mdns accepted connection identity space exhausted");
                }
            }
            Err(e) => {
                debug!("mdns accept error: {e}");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn run_reader(
    shared: &Arc<Shared>,
    read_half: tokio::net::tcp::OwnedReadHalf,
    mut local_cancel: watch::Receiver<bool>,
    mut on_peer_frame: impl FnMut(&str),
) {
    let mut reader = BufReader::new(read_half);
    let mut buf: Vec<u8> = Vec::with_capacity(wire::MAX_FRAME_BYTES.min(8192));
    let mut cancel = shared.cancel.subscribe();
    loop {
        if *cancel.borrow() || shared.stopped.load(Ordering::Acquire) {
            return;
        }
        buf.clear();
        let read = tokio::select! {
            read = timeout(
                INBOUND_IDLE_TIMEOUT,
                read_bounded_line(&mut reader, &mut buf),
            ) => read,
            _ = cancel.changed() => return,
            _ = local_cancel.changed() => return,
        };
        match read {
            Ok(Ok(true)) => {}
            // EOF, oversized/garbage frame, io error, or idle timeout —
            // drop the connection; the peer re-dials if it needs us.
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => return,
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            return;
        };
        if line.trim().is_empty() {
            continue;
        }
        let frame = match wire::decode_frame(line) {
            Ok(f) => f,
            Err(e) => {
                trace!("mdns frame parse failed: {e}");
                return;
            }
        };
        if !wire::frame_is_for_us(
            &frame,
            &shared.room_handle,
            &shared.device_id,
            shared.device_id_validator,
        ) {
            trace!("mdns frame for another room/recipient dropped");
            continue;
        }
        on_peer_frame(&frame.from);
        let inbound = match frame.msg {
            // Both are attributed to the frame's own sender field, which is
            // also what the peer table above is keyed on - a leave naming a
            // third party used to reach the engine as that third party's.
            // Sender-claimed either way: `frame.from` is decoded payload too,
            // never checked against the wire source.
            SignalingMessage::Announce { .. } => MdnsInbound::PeerAnnounced {
                device_id: frame.from,
                attribution: CarrierAttribution::SenderClaimed,
            },
            SignalingMessage::Leave { peer_id: _ } => MdnsInbound::PeerLeft {
                device_id: frame.from,
                attribution: CarrierAttribution::SenderClaimed,
            },
            other => MdnsInbound::Message {
                from: frame.from,
                msg: other,
            },
        };
        if shared.inbound_tx.send(inbound).is_err() {
            let _ = shared.cancel.send(true);
            return;
        }
    }
}

/// Read one `\n`-terminated line into `buf` (newline excluded).
/// Returns `Ok(true)` on a full line, `Ok(false)` on clean EOF, and
/// errors if the line exceeds [`wire::MAX_FRAME_BYTES`] — bounding
/// what an unauthenticated LAN peer can make us buffer.
async fn read_bounded_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(false);
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if buf.len().saturating_add(pos) > wire::MAX_FRAME_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mdns frame exceeds size cap",
                ));
            }
            buf.extend_from_slice(&chunk[..pos]);
            reader.consume(pos + 1);
            return Ok(true);
        }
        if buf.len().saturating_add(chunk.len()) > wire::MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mdns frame exceeds size cap",
            ));
        }
        buf.extend_from_slice(chunk);
        let n = chunk.len();
        reader.consume(n);
    }
}

/// Remove and stop exactly the connection currently registered for `peer`.
/// Signaling the owner before the stale task can publish another frame keeps
/// alias withdrawal and connection replacement on the same lifecycle fence.
fn stop_connection(shared: &Shared, peer: &str) {
    if let Some(node) = shared.conns.lock().remove(peer, None) {
        let _ = node.handle.stop.send(true);
    }
}

async fn run_reannounce(shared: Arc<Shared>) {
    let mut cancel = shared.cancel.subscribe();
    loop {
        tokio::select! {
            _ = sleep(REANNOUNCE_INTERVAL) => {}
            _ = cancel.changed() => return,
        }
        if *cancel.borrow() {
            return;
        }
        // Registration retry — covers a register() that failed at
        // start (no usable interface yet) or a transient daemon error.
        if !shared.registered.load(Ordering::SeqCst) {
            register(&shared);
        }
        // Re-surface every cached peer so the engine's announce-paced
        // retry logic (re-offers for Sighted-stuck peers) keeps
        // working without Nostr's relay heartbeat. A crashed peer
        // that never sent its goodbye lingers until its record TTL
        // expires — the engine tolerates announces for unreachable
        // peers, so this is noise, not harm.
        let peers: Vec<String> = shared.peers.lock().keys();
        for device_id in peers {
            if shared
                .inbound_tx
                .send(MdnsInbound::PeerAnnounced {
                    device_id,
                    attribution: CarrierAttribution::SenderClaimed,
                })
                .is_err()
            {
                let _ = shared.cancel.send(true);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DropCounter(Arc<AtomicU64>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn peer_retention_replacement_and_refusal_preserve_registry_state() {
        let released = Arc::new(AtomicU64::new(0));
        let mut peers = PeerOwnership::default();
        peers
            .insert_new(
                "peer-a".into(),
                PeerEntry {
                    addrs: vec!["127.0.0.1".parse().unwrap()],
                    port: 1,
                },
                Box::new(DropCounter(Arc::clone(&released))),
            )
            .unwrap();
        peers
            .refresh(
                "peer-a",
                PeerEntry {
                    addrs: vec!["127.0.0.2".parse().unwrap()],
                    port: 2,
                },
                Box::new(DropCounter(Arc::clone(&released))),
            )
            .unwrap();
        assert_eq!(released.load(Ordering::SeqCst), 1);
        assert_eq!(peers.get("peer-a").unwrap().port, 2);

        let mut full = PeerOwnership {
            head: None,
            count: MAX_DISCOVERED_PEERS,
        };
        let refusal = full.insert_new(
            "peer-b".into(),
            PeerEntry {
                addrs: Vec::new(),
                port: 3,
            },
            Box::new(DropCounter(Arc::clone(&released))),
        );
        assert!(refusal.is_err());
        assert_eq!(full.count, MAX_DISCOVERED_PEERS);
        assert!(!full.contains("peer-b"));
        assert_eq!(released.load(Ordering::SeqCst), 2);
        drop(peers.remove("peer-a"));
        assert_eq!(released.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn connection_registry_replacement_and_generation_removal_release_owner() {
        let released = Arc::new(AtomicU64::new(0));
        let (tx, _rx) = mpsc::channel(1);
        let (stop, _) = watch::channel(false);
        let mut conns = ConnectionOwnership::default();
        conns.insert(
            Arc::from("peer-a"),
            ConnHandle {
                generation: 1,
                tx: tx.clone(),
                stop: stop.clone(),
            },
            Box::new(DropCounter(Arc::clone(&released))),
        );
        conns.insert(
            Arc::from("peer-a"),
            ConnHandle {
                generation: 2,
                tx,
                stop,
            },
            Box::new(DropCounter(Arc::clone(&released))),
        );
        assert_eq!(released.load(Ordering::SeqCst), 1);
        conns.remove_generation("peer-a", 1);
        assert!(conns.sender("peer-a").is_some());
        conns.remove_generation("peer-a", 2);
        assert!(conns.sender("peer-a").is_none());
        assert_eq!(released.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn connection_slots_have_a_finite_cap_and_release() {
        let slots = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
        let mut leases = Vec::with_capacity(MAX_ACTIVE_CONNECTIONS);
        for _ in 0..MAX_ACTIVE_CONNECTIONS {
            leases.push(slots.clone().try_acquire_owned().expect("slot available"));
        }
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(leases.pop());
        assert!(slots.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn connection_supervisor_joins_each_worker_once() {
        let mut supervisor = JoinSet::new();
        supervisor.spawn(async {});
        assert!(supervisor.join_next().await.is_some());
        assert!(supervisor.join_next().await.is_none());
    }

    /// An owner that records its own release.
    ///
    /// What the owner type is for is *when* the funding goes back, and no
    /// assertion about a type can observe that. This can: it fires once, in
    /// `Drop`.
    struct ReleaseFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for ReleaseFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// **An encoded frame waiting behind a slow peer still has its funding, and
    /// a connection that goes away releases everything it was still holding.**
    ///
    /// The writer queue is where an outbound line parks: a peer that has stopped
    /// reading, or a socket the OS has not yet failed, can hold a frame there for
    /// as long as the connection lasts. This is the retention that the old
    /// `String` queue had no way to express — the bytes existed with nothing
    /// tying them back to whatever admitted the message they came from.
    ///
    /// Asserted at the queue rather than through [`run_writer`], because the
    /// property is about a line that has *not* been written and a writer that is
    /// draining a real socket is exactly the thing that would make that
    /// non-deterministic. The two halves discriminate in opposite directions: a
    /// queue that dropped the owner on enqueue fails the first assertion, and a
    /// teardown that leaked the queued entries fails the second.
    #[test]
    fn a_queued_line_holds_its_owner_until_the_connection_lets_go() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let released = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::unbounded_channel::<OwnedSignal<String, ErasedOwner>>();
        tx.send(OwnedSignal::new(
            "frame".to_string(),
            Box::new(ReleaseFlag(Arc::clone(&released))) as ErasedOwner,
        ))
        .expect("the writer queue accepts a line");
        assert!(
            !released.load(Ordering::SeqCst),
            "the encoded bytes are queued and could still be written, so their \
             funding must not be back"
        );
        // The writer exiting drops the receiver with everything still queued —
        // idle timeout, write error, or driver shutdown all end here.
        drop(rx);
        assert!(
            released.load(Ordering::SeqCst),
            "a torn-down connection releases the owners of the lines it never \
             managed to write"
        );
    }

    #[test]
    fn connection_generation_exhaustion_never_reuses_an_exact_fence() {
        let counter = AtomicU64::new(1);
        assert_eq!(next_connection_generation(&counter), Some(1));
        assert_eq!(next_connection_generation(&counter), Some(2));

        let counter = AtomicU64::new(u64::MAX);
        assert_eq!(next_connection_generation(&counter), Some(u64::MAX));
        assert_eq!(next_connection_generation(&counter), None);
        assert_eq!(next_connection_generation(&counter), None);
    }
}
