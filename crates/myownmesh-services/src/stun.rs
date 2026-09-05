//! Standalone STUN server.
//!
//! Answers RFC 5389 Binding requests with the source transport address
//! XOR-mapped per spec. Pure reflexion: no authentication, no
//! allocations, no `CHANGE-REQUEST` handling — just the one job a STUN
//! server does in an ICE flow, which is to tell a client what address
//! the world sees it coming from.
//!
//! For relaying (symmetric NAT), run the [`crate::turn`] server instead
//! — a TURN server answers Binding requests too, so you rarely need
//! both on one host.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Condvar;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use stun::message::{Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use myownmesh_core::config::StunServiceConfig;
use myownmesh_core::{LocalApplicationResourceScope, ResourceClaim, ResourceClass, ResourceLease};

use crate::turn::{reserve_final_task_custody, FinalTaskCustody};
use crate::{Error, Result};

/// A running STUN server. Constructed via
/// [`StunServer::start_with_resource_scope`].
pub struct StunServer;

struct TaskTerminal {
    finished: AtomicBool,
    notify: Notify,
    #[cfg(test)]
    done: (std::sync::Mutex<bool>, Condvar),
}

impl TaskTerminal {
    fn new() -> Self {
        Self {
            finished: AtomicBool::new(false),
            notify: Notify::new(),
            #[cfg(test)]
            done: (std::sync::Mutex::new(false), Condvar::new()),
        }
    }

    fn mark(&self) {
        self.finished.store(true, Ordering::Release);
        self.notify.notify_waiters();
        #[cfg(test)]
        {
            let (done, wake) = &self.done;
            *done
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            wake.notify_all();
        }
    }

    #[cfg(test)]
    fn wait_finished(&self) {
        let (done, wake) = &self.done;
        let mut done = done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*done {
            done = wake
                .wait(done)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Handle to a running STUN server. Call [`StunServerHandle::stop_and_wait`]
/// to abort and join the listener. Dropping it aborts the listener and hands
/// its exact join handle to the service's explicitly bounded final custodian
/// for terminal observation when the owner cannot await. The terminal closure
/// joins the original task directly on the custodian worker.
pub struct StunServerHandle {
    task: Option<JoinHandle<()>>,
    terminal: Arc<TaskTerminal>,
    final_task_custody: FinalTaskCustody,
    service_lease: Option<ResourceLease>,
    local_addr: SocketAddr,
}

impl StunServerHandle {
    /// The address the server actually bound. Useful when the config
    /// requested port 0 (ephemeral) — common in tests.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Abort the listener and join it to its terminal state.
    ///
    /// STUN's listener has no protocol shutdown frame; cancellation is the
    /// service's explicit stop signal. Awaiting the join closes the lifecycle
    /// boundary and surfaces an unexpected panic instead of leaving a detached
    /// task behind.
    pub async fn stop_and_wait(mut self) -> Result<()> {
        let task_result = if let Some(task) = self.task.take() {
            task.abort();
            task.await
        } else {
            Ok(())
        };
        self.terminal.mark();
        drop(self.service_lease.take());
        match task_result {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(Error::TaskJoin(error.to_string())),
        }
    }
}

impl Drop for StunServerHandle {
    fn drop(&mut self) {
        let final_task_custody = &mut self.final_task_custody;
        let Some(task) = self.task.take() else {
            return;
        };
        task.abort();
        let terminal = Arc::clone(&self.terminal);
        let service_lease = self.service_lease.take();
        submit_final_task(
            Box::new(move || {
                if let Err(error) = join_without_runtime(task) {
                    if !error.is_cancelled() {
                        warn!("dropped STUN listener did not join normally: {error}");
                    }
                }
                terminal.mark();
                drop(service_lease);
            }),
            final_task_custody,
        );
    }
}

fn submit_final_task(task: Box<dyn FnOnce() + Send + 'static>, custody: &mut FinalTaskCustody) {
    if let Err(task) = custody.submit(task) {
        // Refusal is explicit and nonblocking. The exact owned terminal job
        // is run here; no fallback thread may detach the observation.
        task();
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
    mut task: JoinHandle<()>,
) -> std::result::Result<(), tokio::task::JoinError> {
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

impl StunServer {
    /// The unscoped constructor is intentionally non-binding. Service
    /// ownership must come from the process owner's resource scope.
    pub async fn start(config: &StunServiceConfig) -> Result<StunServerHandle> {
        let _ = config;
        Err(Error::Resource(
            "owner-selected resource scope required; use start_with_resource_scope".into(),
        ))
    }

    /// Bind a UDP socket and start serving Binding requests under exact
    /// owner-funded custody. The scope is consumed by the service boundary;
    /// the noncloneable lease remains with the handle until terminal join.
    pub async fn start_with_resource_scope(
        config: &StunServiceConfig,
        scope: LocalApplicationResourceScope,
    ) -> Result<StunServerHandle> {
        let service_lease = scope
            .acquire(stun_startup_claim())
            .map_err(|error| Error::Resource(error.to_string()))?;
        let final_task_custody = reserve_final_task_custody(1)
            .ok_or_else(|| Error::TaskJoin("service final-task custody exhausted".into()))?;
        let addr = format!("{}:{}", config.bind, config.port);
        let socket = UdpSocket::bind(&addr)
            .await
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        let local_addr = socket
            .local_addr()
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        info!(%local_addr, "STUN server listening");
        let socket = Arc::new(socket);
        let terminal = Arc::new(TaskTerminal::new());
        let task = tokio::spawn(serve(socket));
        Ok(StunServerHandle {
            task: Some(task),
            terminal,
            final_task_custody,
            service_lease: Some(service_lease),
            local_addr,
        })
    }
}

fn stun_startup_claim() -> ResourceClaim {
    ResourceClaim::try_from_entries([
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 2),
    ])
    .expect("fixed STUN startup claim is representable")
}

async fn serve(socket: Arc<UdpSocket>) {
    // STUN messages are tiny; an MTU-sized buffer is plenty and a stray
    // oversized datagram just gets truncated and fails to decode (which
    // we handle as a bad packet).
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("STUN recv error: {e}");
                continue;
            }
        };
        match binding_response(&buf[..n], src) {
            Ok(Some(resp)) => {
                if let Err(e) = socket.send_to(&resp, src).await {
                    trace!(%src, "STUN send error: {e}");
                } else {
                    trace!(%src, "STUN binding response sent");
                }
            }
            // Decoded fine but wasn't a Binding request — ignore
            // silently (could be a TURN client probing the wrong port).
            Ok(None) => {}
            Err(e) => trace!(%src, "STUN: dropping bad packet: {e}"),
        }
    }
}

/// Build a Binding success response for an incoming packet. Returns
/// `Ok(None)` when the packet decodes but isn't a Binding request, and
/// `Err` when it doesn't decode as STUN at all.
fn binding_response(packet: &[u8], src: SocketAddr) -> Result<Option<Vec<u8>>> {
    let mut req = Message::new();
    req.unmarshal_binary(packet)
        .map_err(|e| Error::Decode(e.to_string()))?;
    if req.typ != BINDING_REQUEST {
        return Ok(None);
    }
    debug!(%src, "STUN binding request");

    let mut resp = Message::new();
    let xor = XorMappedAddress {
        ip: src.ip(),
        port: src.port(),
    };
    // Order matters: the request setter copies its transaction id onto
    // the response, and XorMappedAddress XORs the address against that
    // transaction id, so it must run after the request setter.
    resp.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(req.clone()),
        Box::new(xor),
    ])
    .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(Some(resp.raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stun::message::Getter;
    use stun::xoraddr::XorMappedAddress;

    fn test_scope() -> LocalApplicationResourceScope {
        let grant = ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|class| (class, 1_000_000)),
        )
        .expect("test provider grant is representable");
        let port = myownmesh_core::ResourceProviderPort::new(
            myownmesh_core::FiniteResourceProvider::new(grant),
        )
        .expect("test provider is valid");
        LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("test application scope is valid")
    }

    async fn start_with_scope(config: &StunServiceConfig) -> Result<StunServerHandle> {
        StunServer::start_with_resource_scope(config, test_scope()).await
    }

    #[tokio::test]
    async fn binding_request_gets_reflexive_address_back() {
        let cfg = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0, // ephemeral
        };
        let server = start_with_scope(&cfg).await.unwrap();
        let server_addr = server.local_addr();

        // A real client socket sends a real Binding request.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let mut req = Message::new();
        req.build(&[Box::new(BINDING_REQUEST)]).unwrap();
        client.send_to(&req.raw, server_addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("STUN response timed out")
        .unwrap();
        assert_eq!(from, server_addr);

        let mut resp = Message::new();
        resp.unmarshal_binary(&buf[..n]).unwrap();
        assert_eq!(resp.typ, BINDING_SUCCESS);
        assert_eq!(resp.transaction_id, req.transaction_id);

        // The server should report back the client's own address.
        let mut mapped = XorMappedAddress::default();
        mapped.get_from(&resp).unwrap();
        assert_eq!(mapped.ip, client_addr.ip());
        assert_eq!(mapped.port, client_addr.port());

        server.stop_and_wait().await.unwrap();
    }

    #[tokio::test]
    async fn non_binding_packet_is_ignored() {
        // Garbage that isn't STUN at all decodes-errors and is dropped;
        // a well-formed non-Binding message returns None. Either way
        // the helper must not panic.
        let src: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(binding_response(b"not a stun packet", src).is_err());
    }

    #[tokio::test]
    async fn active_stop_observes_listener_terminal() {
        let cfg = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        let server = start_with_scope(&cfg).await.unwrap();
        let terminal = Arc::clone(&server.terminal);

        server.stop_and_wait().await.unwrap();

        assert!(terminal.finished.load(Ordering::Acquire));
    }

    #[test]
    fn runtime_ended_before_drop_is_reaped_without_runtime_reentry() {
        let (server, terminal) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("single-thread runtime");
            runtime.block_on(async {
                let config = StunServiceConfig {
                    enabled: true,
                    bind: "127.0.0.1".into(),
                    port: 0,
                };
                let server = start_with_scope(&config).await.unwrap();
                let terminal = Arc::clone(&server.terminal);
                (server, terminal)
            })
        };

        drop(server);

        terminal.wait_finished();
        assert!(terminal.finished.load(Ordering::Acquire));
    }

    #[test]
    fn current_thread_drop_observes_worker_before_runtime_destruction() {
        let (terminal, worker_done, port) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("single-thread runtime");
            runtime.block_on(async {
                let config = StunServiceConfig {
                    enabled: true,
                    bind: "127.0.0.1".into(),
                    port: 0,
                };
                let server = start_with_scope(&config).await.unwrap();
                let terminal = Arc::clone(&server.terminal);
                let worker_done = server.final_task_custody.worker_done_witness();
                let port = server.local_addr().port();
                drop(server);
                (terminal, worker_done, port)
            })
        };

        assert!(terminal.finished.load(Ordering::Acquire));
        assert!(worker_done.load(Ordering::Acquire));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("replacement runtime");
        runtime.block_on(async {
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port,
            };
            start_with_scope(&config)
                .await
                .expect("Drop released the exact control port")
                .stop_and_wait()
                .await
                .unwrap();
        });
    }

    #[tokio::test]
    async fn stopped_stun_releases_the_exact_control_port_for_reuse() {
        let mut config = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        let first = start_with_scope(&config).await.unwrap();
        let port = first.local_addr().port();
        first.stop_and_wait().await.unwrap();

        config.port = port;
        let second = start_with_scope(&config).await.unwrap();
        assert_eq!(second.local_addr().port(), port);
        second.stop_and_wait().await.unwrap();
    }

    #[tokio::test]
    async fn exact_startup_grant_rejects_n_plus_one_and_reuses_after_stop() {
        let insufficient_port =
            myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(
                stun_startup_claim()
                    .checked_sub(ResourceClaim::single(ResourceClass::WorkerOrTask, 1))
                    .unwrap(),
            ))
            .unwrap();
        let insufficient_scope =
            LocalApplicationResourceScope::transport_lab_child_of(&insufficient_port).unwrap();
        let insufficient_config = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        assert!(matches!(
            StunServer::start_with_resource_scope(&insufficient_config, insufficient_scope).await,
            Err(Error::Resource(_))
        ));

        let port = myownmesh_core::ResourceProviderPort::new(
            myownmesh_core::FiniteResourceProvider::new(stun_startup_claim()),
        )
        .unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
        let config = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        let first = StunServer::start_with_resource_scope(&config, scope.clone())
            .await
            .unwrap();
        let refused = StunServer::start_with_resource_scope(&config, scope.clone()).await;
        assert!(matches!(refused, Err(Error::Resource(_))));
        first.stop_and_wait().await.unwrap();
        StunServer::start_with_resource_scope(&config, scope)
            .await
            .unwrap()
            .stop_and_wait()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn drop_outside_runtime_is_reaped_by_runtime_owner() {
        let cfg = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        let server = start_with_scope(&cfg).await.unwrap();
        let terminal = Arc::clone(&server.terminal);
        let notified = terminal.notify.notified();

        std::thread::spawn(move || drop(server))
            .join()
            .expect("drop thread panicked");
        notified.await;

        assert!(terminal.finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn double_bind_same_port_errors() {
        let cfg = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        let server = start_with_scope(&cfg).await.unwrap();
        let taken = server.local_addr();
        // Re-binding the now-occupied port must surface as Error::Bind.
        let cfg2 = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: taken.port(),
        };
        let err = start_with_scope(&cfg2).await;
        assert!(matches!(err, Err(Error::Bind(_, _))));
        server.stop_and_wait().await.unwrap();
    }
}
