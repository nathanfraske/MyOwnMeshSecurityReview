//! Standalone TURN server (RFC 5766).
//!
//! Relays media / data for peers that can't establish a direct path
//! (symmetric NAT). A TURN server also answers STUN Binding requests, so
//! a single TURN listener covers both jobs in an ICE flow.
//!
//! This is a thin wrapper over the webrtc-rs `turn` crate's
//! [`Server`](turn::server::Server), wired to a single UDP listener and
//! a static long-term-credential auth handler driven by
//! [`TurnServiceConfig`]. Credentials are configured up front (mirror
//! them into each peer's `turn_servers` config); there's no dynamic
//! REST-style credential issuance.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tracing::info;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::relay::RelayAddressGenerator;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use turn::Error as TurnError;
use webrtc_util::vnet::net::Net;
use webrtc_util::Conn;

use myownmesh_core::config::{TurnCredential, TurnServiceConfig};

use crate::{Error, Result};

/// Token bucket over bytes, for per-allocation bandwidth shaping. A cap
/// of 0 is never wrapped (see [`ThrottledRelayGenerator`]), so `rate` is
/// always > 0 here.
struct ByteBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last: Instant,
}

impl ByteBucket {
    fn new(bps: u64) -> Self {
        // The configured rate is also the initial burst. There is no hidden
        // floor: workload capacity comes solely from the provider's explicit
        // per-connection configuration.
        let capacity = bps as f64;
        Self {
            tokens: capacity,
            capacity,
            rate: bps as f64,
            last: Instant::now(),
        }
    }

    /// Refill for elapsed time and try to consume `n` bytes. Returns
    /// `None` if consumed now, or `Some(wait)` if the caller must wait
    /// that long and retry. Pure (takes `now`) so it's unit-testable
    /// without real time. `n` is clamped to capacity so an oversized
    /// datagram still drains through.
    fn try_consume(&mut self, n: usize, now: Instant) -> Option<Duration> {
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        let need = (n as f64).min(self.capacity);
        if self.tokens >= need {
            self.tokens -= need;
            None
        } else {
            Some(Duration::from_secs_f64((need - self.tokens) / self.rate))
        }
    }
}

async fn consume(bucket: &AsyncMutex<ByteBucket>, n: usize) {
    loop {
        let wait = {
            let mut b = bucket.lock().await;
            b.try_consume(n, Instant::now())
        };
        match wait {
            None => return,
            Some(w) => tokio::time::sleep(w).await,
        }
    }
}

/// Wraps an allocation's relay [`Conn`] to shape its throughput to a
/// per-connection byte/sec cap, independently in each direction.
struct ThrottledConn {
    inner: Arc<dyn Conn + Send + Sync>,
    send_bucket: AsyncMutex<ByteBucket>,
    recv_bucket: AsyncMutex<ByteBucket>,
}

impl ThrottledConn {
    fn new(inner: Arc<dyn Conn + Send + Sync>, bps: u64) -> Self {
        Self {
            inner,
            send_bucket: AsyncMutex::new(ByteBucket::new(bps)),
            recv_bucket: AsyncMutex::new(ByteBucket::new(bps)),
        }
    }
}

#[async_trait]
impl Conn for ThrottledConn {
    async fn connect(&self, addr: SocketAddr) -> std::result::Result<(), webrtc_util::Error> {
        self.inner.connect(addr).await
    }
    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, webrtc_util::Error> {
        let n = self.inner.recv(buf).await?;
        consume(&self.recv_bucket, n).await;
        Ok(n)
    }
    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), webrtc_util::Error> {
        let (n, addr) = self.inner.recv_from(buf).await?;
        consume(&self.recv_bucket, n).await;
        Ok((n, addr))
    }
    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, webrtc_util::Error> {
        consume(&self.send_bucket, buf.len()).await;
        self.inner.send(buf).await
    }
    async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::result::Result<usize, webrtc_util::Error> {
        consume(&self.send_bucket, buf.len()).await;
        self.inner.send_to(buf, target).await
    }
    fn local_addr(&self) -> std::result::Result<SocketAddr, webrtc_util::Error> {
        self.inner.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }
    async fn close(&self) -> std::result::Result<(), webrtc_util::Error> {
        self.inner.close().await
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Relay-address generator that delegates allocation to the static
/// generator, then wraps each allocation's relay socket in a
/// [`ThrottledConn`] when a per-connection cap is configured. The cap is
/// global (every allocation gets the same limit).
struct ThrottledRelayGenerator {
    inner: RelayAddressGeneratorStatic,
    max_bps: u64,
    /// Relay sockets are bound from this inclusive port window instead of
    /// the OS ephemeral range, so operators open one small, predictable
    /// UDP range at the firewall. `min <= max` is guaranteed at
    /// construction.
    min_port: u16,
    max_port: u16,
    /// Round-robin starting point so we don't rescan held low ports on
    /// every allocation — just a spread hint, not load-bearing.
    cursor: std::sync::atomic::AtomicU16,
}

impl ThrottledRelayGenerator {
    /// Bind a relay socket on the first free port in `[min_port, max_port]`,
    /// scanning from a rotating cursor. Returns the same `(conn, addr)`
    /// the static generator would, so the caller can wrap it.
    async fn allocate_in_range(
        &self,
        use_ipv4: bool,
    ) -> std::result::Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), TurnError> {
        let span = (self.max_port - self.min_port) as u32 + 1;
        let start = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u32;
        let mut last_err: Option<TurnError> = None;
        for i in 0..span {
            let port = self.min_port + ((start + i) % span) as u16;
            match self.inner.allocate_conn(use_ipv4, port).await {
                Ok(pair) => return Ok(pair),
                Err(e) => last_err = Some(e),
            }
        }
        // `span >= 1` is guaranteed at construction (min <= max), so the
        // loop always ran at least once and set `last_err` on failure.
        Err(last_err.expect("relay port range is non-empty"))
    }
}

#[async_trait]
impl RelayAddressGenerator for ThrottledRelayGenerator {
    fn validate(&self) -> std::result::Result<(), TurnError> {
        self.inner.validate()
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> std::result::Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), TurnError> {
        // The TURN server passes 0 for normal allocations. With a fixed
        // window configured (min_port != 0) pick from it so relay traffic
        // lands on a small firewall-able range; otherwise (min_port == 0,
        // the default) fall through to the OS ephemeral range — unbounded.
        // A non-zero requested_port (e.g. EVEN-PORT) is always honored.
        let (conn, addr) = if requested_port == 0 && self.min_port != 0 {
            self.allocate_in_range(use_ipv4).await?
        } else {
            self.inner.allocate_conn(use_ipv4, requested_port).await?
        };
        if self.max_bps == 0 {
            return Ok((conn, addr));
        }
        let throttled: Arc<dyn Conn + Send + Sync> =
            Arc::new(ThrottledConn::new(conn, self.max_bps));
        Ok((throttled, addr))
    }
}

/// Long-term credential auth handler backed by a static username → key
/// map. The key is the MD5 digest `generate_auth_key` computes from
/// `username:realm:password`, which is what the TURN message-integrity
/// check compares against — so we never store the plaintext password
/// past startup.
struct StaticAuthHandler {
    cred_map: HashMap<String, Vec<u8>>,
}

impl StaticAuthHandler {
    fn new(realm: &str, creds: &[TurnCredential]) -> Self {
        let mut cred_map = HashMap::new();
        for c in creds {
            cred_map.insert(
                c.username.clone(),
                generate_auth_key(&c.username, realm, &c.password),
            );
        }
        Self { cred_map }
    }
}

impl AuthHandler for StaticAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> std::result::Result<Vec<u8>, TurnError> {
        self.cred_map
            .get(username)
            .cloned()
            .ok_or(TurnError::ErrNoSuchUser)
    }
}

/// A running TURN server. Constructed via [`TurnServer::start`].
pub struct TurnServer;

type TaskReaperSender = mpsc::Sender<ReapEntry>;

struct ReapEntry {
    task: JoinHandle<std::result::Result<(), String>>,
    terminal: Arc<TaskTerminal>,
}

struct TaskTerminal {
    finished: AtomicBool,
    notify: Notify,
}

impl TaskTerminal {
    fn new() -> Self {
        Self {
            finished: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn mark(&self) {
        self.finished.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

/// Handle to a running TURN server. Call [`TurnServerHandle::stop`] to
/// request the dependency's close protocol and join its close task; dropping
/// it sends the same request and hands the exact task to a bounded reaper.
pub struct TurnServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::result::Result<(), String>>>,
    terminal: Arc<TaskTerminal>,
    task_reaper: Option<TaskReaperSender>,
    task_reaper_handle: Option<JoinHandle<()>>,
    local_addr: SocketAddr,
    relay_ip: IpAddr,
}

impl TurnServerHandle {
    /// The address the listener actually bound (resolves an ephemeral
    /// port to the real one — used in tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The public/relay IP the server hands out in allocations.
    pub fn relay_ip(&self) -> IpAddr {
        self.relay_ip
    }

    /// Stop the server, closing allocations and the listener.
    pub async fn stop(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = if let Some(task) = self.task.take() {
            task.await
        } else {
            Ok(Ok(()))
        };
        self.terminal.mark();
        drop(self.task_reaper.take());
        if let Some(reaper) = self.task_reaper_handle.take() {
            reaper
                .await
                .map_err(|error| Error::TaskJoin(error.to_string()))?;
        }
        match task_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Error::Turn(error)),
            Err(error) => Err(Error::TaskJoin(error.to_string())),
        }
    }
}

impl Drop for TurnServerHandle {
    fn drop(&mut self) {
        let Some(shutdown) = self.shutdown.take() else {
            return;
        };
        let _ = shutdown.send(());
        let Some(task) = self.task.take() else {
            return;
        };
        let entry = ReapEntry {
            task,
            terminal: Arc::clone(&self.terminal),
        };
        let Some(reaper) = self.task_reaper.take() else {
            reap_without_runtime(entry);
            return;
        };
        match reaper.try_send(entry) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(entry))
            | Err(mpsc::error::TrySendError::Closed(entry)) => reap_without_runtime(entry),
        }
        drop(self.task_reaper_handle.take());
    }
}

fn spawn_task_reaper() -> (TaskReaperSender, JoinHandle<()>) {
    let (sender, mut receiver) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        while let Some(entry) = receiver.recv().await {
            reap_entry(entry).await;
        }
    });
    (sender, task)
}

async fn reap_entry(entry: ReapEntry) {
    match entry.task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!("dropped TURN close task returned an error: {error}");
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) => warn_join_error(error),
    }
    entry.terminal.mark();
}

fn warn_join_error(error: tokio::task::JoinError) {
    tracing::warn!("dropped TURN close task did not join normally: {error}");
}

fn reap_without_runtime(entry: ReapEntry) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(reap_entry(entry));
    } else {
        let ReapEntry { task, terminal } = entry;
        match join_without_runtime(task) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("dropped TURN close task returned an error: {error}");
            }
            Err(error) if error.is_cancelled() => {}
            Err(error) => warn_join_error(error),
        }
        terminal.mark();
    }
}

struct ThreadUnparker(thread::Thread);

impl Wake for ThreadUnparker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn join_without_runtime(
    mut task: JoinHandle<std::result::Result<(), String>>,
) -> std::result::Result<std::result::Result<(), String>, tokio::task::JoinError> {
    let waker = Waker::from(Arc::new(ThreadUnparker(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut task = std::pin::Pin::new(&mut task);
    loop {
        match std::future::Future::poll(task.as_mut(), &mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => thread::park(),
        }
    }
}

impl TurnServer {
    /// Bind a UDP listener and start the TURN server. Fails fast on
    /// misconfiguration (no credentials, or a wildcard bind with no
    /// public IP to advertise) since a TURN server that can't be
    /// reached or authenticated against is worse than none.
    pub async fn start(config: &TurnServiceConfig) -> Result<TurnServerHandle> {
        if config.credentials.is_empty() {
            return Err(Error::TurnConfig(
                "TURN requires at least one username/password credential".into(),
            ));
        }
        let relay_ip = resolve_relay_ip(config)?;

        let bind_addr = format!("{}:{}", config.bind, config.port);
        let conn = Arc::new(
            UdpSocket::bind(&bind_addr)
                .await
                .map_err(|e| Error::Bind(bind_addr.clone(), e))?,
        );
        let local_addr = conn
            .local_addr()
            .map_err(|e| Error::Bind(bind_addr.clone(), e))?;

        let auth_handler = Arc::new(StaticAuthHandler::new(&config.realm, &config.credentials));

        // Clamp the relay range so `min <= max` always holds (a
        // misconfigured max collapses to a single port rather than
        // underflowing the span).
        let relay_port_min = config.relay_port_min;
        let relay_port_max = config.relay_port_max.max(config.relay_port_min);

        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                // Wrap the static generator so each allocation's relay
                // socket is drawn from the configured port range and
                // bandwidth-shaped to the configured cap (a no-op
                // passthrough when the cap is 0).
                relay_addr_generator: Box::new(ThrottledRelayGenerator {
                    inner: RelayAddressGeneratorStatic {
                        relay_address: relay_ip,
                        // Interface the relay sockets bind on; the
                        // wildcard is fine here — relay_address is what
                        // clients are told to use.
                        address: "0.0.0.0".to_owned(),
                        net: Arc::new(Net::new(None)),
                    },
                    max_bps: config.max_bps_per_connection,
                    min_port: relay_port_min,
                    max_port: relay_port_max,
                    cursor: std::sync::atomic::AtomicU16::new(0),
                }),
            }],
            realm: config.realm.clone(),
            auth_handler,
            // Zero = use the crate's DEFAULT_LIFETIME for channel binds.
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .map_err(|e| Error::Turn(e.to_string()))?;

        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            server.close().await.map_err(|error| error.to_string())
        });
        let terminal = Arc::new(TaskTerminal::new());
        let (task_reaper, task_reaper_handle) = spawn_task_reaper();

        let relay_ports = if relay_port_min == 0 {
            "OS ephemeral range".to_string()
        } else {
            format!("{relay_port_min}-{relay_port_max}")
        };
        info!(
            %local_addr,
            %relay_ip,
            realm = %config.realm,
            credentials = config.credentials.len(),
            relay_ports = %relay_ports,
            "TURN listening — open UDP {} (control) and the relay ports ({}) at the firewall AND your cloud/provider security group",
            config.port, relay_ports
        );
        Ok(TurnServerHandle {
            shutdown: Some(shutdown),
            task: Some(task),
            terminal,
            task_reaper: Some(task_reaper),
            task_reaper_handle: Some(task_reaper_handle),
            local_addr,
            relay_ip,
        })
    }
}

/// Resolve the IP a TURN allocation should advertise. Prefers
/// `public_ip`; falls back to the bind address; rejects a wildcard
/// (clients can't connect to 0.0.0.0).
fn resolve_relay_ip(config: &TurnServiceConfig) -> Result<IpAddr> {
    let candidate = if config.public_ip.trim().is_empty() {
        config.bind.trim().to_string()
    } else {
        config.public_ip.trim().to_string()
    };
    let ip: IpAddr = candidate
        .parse()
        .map_err(|_| Error::TurnConfig(format!("relay address '{candidate}' is not a valid IP")))?;
    if ip.is_unspecified() {
        return Err(Error::TurnConfig(
            "TURN public_ip must be set to the server's routable address when bind is a wildcard \
             (0.0.0.0 / ::)"
                .into(),
        ));
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(u: &str, p: &str) -> TurnCredential {
        TurnCredential {
            username: u.into(),
            password: p.into(),
        }
    }

    fn loopback_config() -> TurnServiceConfig {
        TurnServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
            public_ip: "127.0.0.1".into(),
            realm: "myownmesh".into(),
            credentials: vec![cred("alice", "s3cret")],
            max_bps_per_connection: 0,
            relay_port_min: 49152,
            relay_port_max: 50151,
        }
    }

    #[tokio::test]
    async fn rejects_missing_credentials() {
        let mut cfg = loopback_config();
        cfg.credentials.clear();
        assert!(matches!(
            TurnServer::start(&cfg).await,
            Err(Error::TurnConfig(_))
        ));
    }

    #[tokio::test]
    async fn rejects_wildcard_bind_without_public_ip() {
        let cfg = TurnServiceConfig {
            enabled: true,
            bind: "0.0.0.0".into(),
            port: 0,
            public_ip: "".into(),
            realm: "myownmesh".into(),
            credentials: vec![cred("alice", "pw")],
            max_bps_per_connection: 0,
            relay_port_min: 49152,
            relay_port_max: 50151,
        };
        assert!(matches!(
            TurnServer::start(&cfg).await,
            Err(Error::TurnConfig(_))
        ));
    }

    #[tokio::test]
    async fn starts_and_stops_on_loopback() {
        let server = TurnServer::start(&loopback_config()).await.unwrap();
        assert_ne!(server.local_addr().port(), 0);
        assert_eq!(server.relay_ip().to_string(), "127.0.0.1");
        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn active_stop_observes_turn_close_terminal() {
        let server = TurnServer::start(&loopback_config()).await.unwrap();
        let terminal = Arc::clone(&server.terminal);

        server.stop().await.unwrap();

        assert!(terminal.finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn drop_outside_runtime_is_reaped_by_runtime_owner() {
        let server = TurnServer::start(&loopback_config()).await.unwrap();
        let terminal = Arc::clone(&server.terminal);
        let notified = terminal.notify.notified();

        std::thread::spawn(move || drop(server))
            .join()
            .expect("drop thread panicked");
        notified.await;

        assert!(terminal.finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn relay_allocations_land_in_configured_range() {
        // An allocation with no requested port must draw from the bounded
        // relay range, so operators can open one small UDP window.
        let generator = ThrottledRelayGenerator {
            inner: RelayAddressGeneratorStatic {
                relay_address: "127.0.0.1".parse().unwrap(),
                address: "127.0.0.1".to_owned(),
                net: Arc::new(Net::new(None)),
            },
            max_bps: 0,
            min_port: 50500,
            max_port: 50519,
            cursor: std::sync::atomic::AtomicU16::new(0),
        };
        match generator.allocate_conn(true, 0).await {
            Ok((_conn, addr)) => assert!(
                (50500..=50519).contains(&addr.port()),
                "relay port {} is outside the configured range",
                addr.port()
            ),
            // The whole 20-port window can be unbindable in a sandboxed CI
            // host, and that is not a logic failure. Windows reserves dynamic
            // "excluded port ranges" (Hyper-V/WinNAT) that shift per boot and
            // can swallow a small window entirely — the bind then returns
            // WSAEACCES (os error 10013); a hardened Linux sandbox can deny a
            // bind the same way. The allocator's contract is exactly what ran:
            // scan the range, surface an error only when nothing binds. So
            // accept an OS bind refusal instead of flaking CI over it, while
            // still failing on any *other* error (a real allocator bug).
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                assert!(
                    msg.contains("permission")
                        || msg.contains("forbidden")
                        || msg.contains("denied")
                        || msg.contains("access"),
                    "relay allocation failed for a non-environmental reason: {e}"
                );
                eprintln!(
                    "relay_allocations_land_in_configured_range: host refused the whole \
                     50500-50519 window ({e}); skipping the range assertion"
                );
            }
        }
    }

    #[tokio::test]
    async fn unbounded_range_falls_back_to_os_ephemeral() {
        // min_port == 0 is the default: no fixed window, allocation still
        // succeeds on an OS-assigned port (just not constrained).
        let generator = ThrottledRelayGenerator {
            inner: RelayAddressGeneratorStatic {
                relay_address: "127.0.0.1".parse().unwrap(),
                address: "127.0.0.1".to_owned(),
                net: Arc::new(Net::new(None)),
            },
            max_bps: 0,
            min_port: 0,
            max_port: 0,
            cursor: std::sync::atomic::AtomicU16::new(0),
        };
        let (_conn, addr) = generator.allocate_conn(true, 0).await.unwrap();
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn byte_bucket_shapes_to_rate() {
        // rate 100_000 B/s → the configured rate is the burst capacity.
        let mut b = ByteBucket::new(100_000);
        let t0 = Instant::now();
        // First 100KB fits in the burst — no wait.
        assert!(b.try_consume(100_000, t0).is_none());
        // Immediately asking for 50KB more must wait ~0.5s (no refill).
        let wait = b.try_consume(50_000, t0).expect("should need to wait");
        assert!(
            wait.as_millis() >= 400 && wait.as_millis() <= 600,
            "got {wait:?}"
        );
        // After 1s of refill, the bucket is full again.
        assert!(b.try_consume(50_000, t0 + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn byte_bucket_oversized_datagram_never_deadlocks() {
        // A datagram larger than a tiny cap's per-second budget still
        // drains (clamped to capacity) rather than waiting forever.
        let mut b = ByteBucket::new(1_000); // no hidden burst floor
        let t0 = Instant::now();
        // Drain the burst, then a full datagram is clamped to capacity.
        assert!(b.try_consume(65_536, t0).is_none());
        let wait = b
            .try_consume(65_536, t0)
            .expect("should wait but not forever");
        assert!(wait.as_secs_f64().is_finite());
    }

    #[tokio::test]
    async fn turn_with_bandwidth_cap_starts() {
        // A configured cap must not break startup or allocation wiring.
        let mut cfg = loopback_config();
        cfg.max_bps_per_connection = 256_000;
        let server = TurnServer::start(&cfg).await.unwrap();
        assert_ne!(server.local_addr().port(), 0);
        server.stop().await.unwrap();
    }

    #[test]
    fn auth_handler_keys_known_users_only() {
        let handler = StaticAuthHandler::new("myownmesh", &[cred("alice", "pw")]);
        let src: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let key = handler.auth_handle("alice", "myownmesh", src).unwrap();
        assert_eq!(key, generate_auth_key("alice", "myownmesh", "pw"));
        assert!(handler.auth_handle("mallory", "myownmesh", src).is_err());
    }

    // Proves the server actually serves on the wire: a real TURN client
    // sends a STUN Binding request through the TURN listener and gets a
    // reflexive address back. (A TURN server answers Binding requests as
    // part of being a TURN server.)
    #[tokio::test]
    async fn answers_binding_request_through_turn_listener() {
        use turn::client::{Client, ClientConfig};

        let server = TurnServer::start(&loopback_config()).await.unwrap();
        let server_port = server.local_addr().port();

        let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = Client::new(ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: String::new(),
            username: String::new(),
            password: String::new(),
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn,
            vnet: None,
        })
        .await
        .unwrap();
        client.listen().await.unwrap();

        let mapped = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.send_binding_request_to(&format!("127.0.0.1:{server_port}")),
        )
        .await
        .expect("TURN binding request timed out")
        .expect("binding request failed");
        // The server saw us come from loopback.
        assert_eq!(mapped.ip().to_string(), "127.0.0.1");

        client.close().await.unwrap();
        server.stop().await.unwrap();
    }
}
