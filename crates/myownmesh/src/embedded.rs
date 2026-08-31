//! Run the daemon wholly inside a host application's process.
//!
//! This is `myownmesh serve` minus the process: the same mesh instance,
//! network registry, hosted services, updater tick, and control-socket
//! listener, started as tasks on the caller's tokio runtime and torn down
//! through the returned [`EmbeddedDaemon`] instead of a signal handler.
//!
//! The one intended consumer is a mobile app (iOS forbids spawning the
//! daemon as a child process), but nothing here is mobile-specific — any
//! embedder that wants the daemon in-process can use it.

use tracing::{info, warn};

use crate::control;
use crate::registry::NetworkRegistry;
use crate::services::ServiceManager;

/// Typed startup failures for the embedded daemon.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedStartError {
    /// Infrastructure-only startup must not create a network participant.
    #[error("infrastructure-only startup requires node participation to be disabled")]
    InfrastructureOnlyRequiresNodeDisabled,

    #[error("open mesh: {0}")]
    OpenMesh(#[from] myownmesh_core::Error),

    #[error("service policy: {0}")]
    ServicePolicy(#[from] crate::services::ServicePolicyError),

    #[error("network startup: {0}")]
    NetworkStartup(String),

    #[error("custody startup recovery: {0}")]
    CustodyRecovery(myownmesh_core::Error),

    #[error("cleanup custodian startup: {0}")]
    CleanupCustody(String),
}

/// Ordered terminal failures observed while draining the daemon.
#[derive(Debug, thiserror::Error)]
#[error("daemon shutdown failed: {failures:?}")]
pub struct EmbeddedShutdownError {
    pub failures: Vec<EmbeddedShutdownFailure>,
}

#[derive(Debug)]
pub struct EmbeddedShutdownFailure {
    pub stage: &'static str,
    pub error: String,
}

#[cfg(test)]
struct EmbeddedTaskWitness {
    control_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    control_terminal: std::sync::Arc<std::sync::atomic::AtomicBool>,
    updater_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    updater_terminal: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cleanup_terminal: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cleanup_thread_joined: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cleanup_root_join_errors: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cleanup_root_panics: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cleanup_root_cancellations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    updater_gate: std::sync::Arc<tokio::sync::Notify>,
    updater_gate_open: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
impl EmbeddedTaskWitness {
    fn new() -> Self {
        use std::sync::atomic::AtomicBool;
        Self {
            control_started: std::sync::Arc::new(AtomicBool::new(false)),
            control_terminal: std::sync::Arc::new(AtomicBool::new(false)),
            updater_started: std::sync::Arc::new(AtomicBool::new(false)),
            updater_terminal: std::sync::Arc::new(AtomicBool::new(false)),
            cleanup_terminal: std::sync::Arc::new(AtomicBool::new(false)),
            cleanup_thread_joined: std::sync::Arc::new(AtomicBool::new(false)),
            cleanup_root_join_errors: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cleanup_root_panics: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cleanup_root_cancellations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            updater_gate: std::sync::Arc::new(tokio::sync::Notify::new()),
            updater_gate_open: std::sync::Arc::new(AtomicBool::new(false)),
        }
    }
}

#[cfg(test)]
struct EmbeddedTaskTerminal(std::sync::Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
static INJECT_CLEANUP_RUNTIME_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, unix))]
fn set_cleanup_runtime_failure_for_test(fail: bool) {
    INJECT_CLEANUP_RUNTIME_FAILURE.store(fail, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
impl Drop for EmbeddedTaskTerminal {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The one pre-existing owner that owns the non-awaitable Drop handoff.
///
/// `EmbeddedDaemon::drop` cannot await, and spawning a cleanup future from
/// there would make the service/network drain itself detachable. This
/// custodian is therefore created before either daemon root task. Drop only
/// installs a bounded request in its one-slot mailbox and latches the normal
/// supervisor cancellation; the custodian then joins both roots and drains
/// services and networks in the same order as [`EmbeddedDaemon::shutdown`].
///
/// The custodian's `WorkerOrTask` lease is acquired before its owner thread is
/// spawned and held until its terminal branch, so cleanup is part of the
/// caller-selected finite resource grant. Its terminal signal is retained for
/// the graceful path; the non-awaitable Drop path observes the shared witness
/// while the already-existing custodian performs the bounded drain. The
/// custodian's OS-thread handle is then transferred to the process-owned,
/// one-slot join reaper, which retains and joins it after that terminal signal.
struct EmbeddedCleanupCustodian {
    mailbox: std::sync::Arc<EmbeddedCleanupMailbox>,
    terminal: Option<tokio::sync::oneshot::Receiver<std::result::Result<(), String>>>,
    thread_reaper: std::sync::mpsc::SyncSender<EmbeddedCleanupThreadBatch>,
    thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    cleanup_thread_joined: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

struct EmbeddedCleanupThreadBatch {
    thread: std::thread::JoinHandle<()>,
    #[cfg(test)]
    joined: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

struct EmbeddedCleanupThreadReaper {
    sender: Option<std::sync::mpsc::SyncSender<EmbeddedCleanupThreadBatch>>,
    _thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// The reaper is process-lived, so its one `WorkerOrTask` charge is held
    /// for the same lifetime rather than being silently borrowed from the
    /// first daemon that happened to start it.
    _lease: myownmesh_core::ResourceLease,
}

impl Drop for EmbeddedCleanupThreadReaper {
    fn drop(&mut self) {
        // Close the mailbox before joining so the receiver can observe its
        // terminal state. The process-global owner is retained by OnceLock;
        // this path is also used by isolated controls that must observe the
        // owner thread's join rather than detach it.
        self.sender.take();
        if let Some(thread) = self
            ._thread
            .lock()
            .expect("cleanup reaper mutex is not poisoned")
            .take()
        {
            let _ = thread.join();
        }
    }
}

// One bounded, process-lived owner receives cleanup-thread handles after a
// synchronous Drop. Keeping its own JoinHandle in the OnceLock means this
// owner is not itself detached; it is deliberately non-self because it never
// joins the thread that is executing it. Its worker/task lease is acquired
// before the thread is spawned and remains in this OnceLock until process exit.
static EMBEDDED_CLEANUP_THREAD_REAPER: std::sync::OnceLock<
    std::sync::Mutex<Option<EmbeddedCleanupThreadReaper>>,
> = std::sync::OnceLock::new();

fn embedded_cleanup_thread_reaper(
    scope: &myownmesh_core::LocalApplicationResourceScope,
) -> std::result::Result<std::sync::mpsc::SyncSender<EmbeddedCleanupThreadBatch>, String> {
    let slot = EMBEDDED_CLEANUP_THREAD_REAPER.get_or_init(|| std::sync::Mutex::new(None));
    embedded_cleanup_thread_reaper_in(scope, slot)
}

fn embedded_cleanup_thread_reaper_in(
    scope: &myownmesh_core::LocalApplicationResourceScope,
    slot: &std::sync::Mutex<Option<EmbeddedCleanupThreadReaper>>,
) -> std::result::Result<std::sync::mpsc::SyncSender<EmbeddedCleanupThreadBatch>, String> {
    let mut slot = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(reaper) = slot.as_ref() {
        return Ok(reaper
            .sender
            .as_ref()
            .expect("a live cleanup reaper retains its mailbox")
            .clone());
    }

    let reaper = {
        // This is process-lifetime work, not a per-daemon cleanup charge.
        // Acquire it before constructing the OS thread so a provider with no
        // spare WorkerOrTask capacity refuses the reaper before any work is
        // made live.
        let lease = scope
            .acquire(myownmesh_core::ResourceClaim::single(
                myownmesh_core::ResourceClass::WorkerOrTask,
                1,
            ))
            .map_err(|error| error.to_string())?;
        let (sender, receiver) = std::sync::mpsc::sync_channel::<EmbeddedCleanupThreadBatch>(1);
        let thread = std::thread::Builder::new()
            .name("myownmesh-embedded-cleanup-join".to_string())
            .spawn(move || {
                while let Ok(batch) = receiver.recv() {
                    let _ = batch.thread.join();
                    #[cfg(test)]
                    batch
                        .joined
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .map_err(|error| error.to_string())?;
        EmbeddedCleanupThreadReaper {
            sender: Some(sender),
            _thread: std::sync::Mutex::new(Some(thread)),
            _lease: lease,
        }
    };
    let sender = reaper
        .sender
        .as_ref()
        .expect("a newly built cleanup reaper retains its mailbox")
        .clone();
    *slot = Some(reaper);
    Ok(sender)
}

struct EmbeddedCleanupMailbox {
    request: std::sync::Mutex<Option<EmbeddedCleanupRequest>>,
    ready: std::sync::Condvar,
}

enum EmbeddedCleanupRequest {
    Graceful,
    Dropped {
        control: tokio::task::JoinHandle<std::result::Result<(), String>>,
        updater: tokio::task::JoinHandle<()>,
        service_manager: std::sync::Arc<ServiceManager>,
        registry: std::sync::Arc<NetworkRegistry>,
    },
}

impl EmbeddedCleanupCustodian {
    fn new(
        lease: myownmesh_core::ResourceLease,
        thread_reaper: std::sync::mpsc::SyncSender<EmbeddedCleanupThreadBatch>,
        #[cfg(test)] witness: std::sync::Arc<EmbeddedTaskWitness>,
    ) -> std::result::Result<Self, String> {
        let mailbox = std::sync::Arc::new(EmbeddedCleanupMailbox {
            request: std::sync::Mutex::new(None),
            ready: std::sync::Condvar::new(),
        });
        let thread_mailbox = std::sync::Arc::clone(&mailbox);
        let (terminal_sender, terminal) = tokio::sync::oneshot::channel();
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        #[cfg(test)]
        let cleanup_thread_joined = std::sync::Arc::clone(&witness.cleanup_thread_joined);
        let thread = std::thread::Builder::new()
            .name("myownmesh-embedded-cleanup".to_string())
            .spawn(move || {
                #[cfg(test)]
                if INJECT_CLEANUP_RUNTIME_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = ready_sender.send(Err("injected cleanup runtime failure".to_string()));
                    return;
                }
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        let _ = ready_sender.send(Ok(()));
                        runtime
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                let request = {
                    let mut slot = thread_mailbox
                        .request
                        .lock()
                        .expect("embedded cleanup mailbox is not poisoned");
                    loop {
                        if let Some(request) = slot.take() {
                            break request;
                        }
                        slot = thread_mailbox
                            .ready
                            .wait(slot)
                            .expect("embedded cleanup mailbox is not poisoned");
                    }
                };
                let outcome = runtime.block_on(async move {
                    {
                        let _lease = lease;
                        if let EmbeddedCleanupRequest::Dropped {
                            control,
                            updater,
                            service_manager,
                            registry,
                        } = request
                        {
                            let _control_result = control.await;
                            #[cfg(test)]
                            if let Err(error) = &_control_result {
                                witness
                                    .cleanup_root_join_errors
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if error.is_panic() {
                                    witness
                                        .cleanup_root_panics
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                                if error.is_cancelled() {
                                    witness
                                        .cleanup_root_cancellations
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                            }
                            let _updater_result = updater.await;
                            #[cfg(test)]
                            if let Err(error) = &_updater_result {
                                witness
                                    .cleanup_root_join_errors
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if error.is_panic() {
                                    witness
                                        .cleanup_root_panics
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                                if error.is_cancelled() {
                                    witness
                                        .cleanup_root_cancellations
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                            }
                            let _ = service_manager.shutdown().await;
                            let _ = registry.shutdown_all_with_departures().await;
                        }
                    }
                    #[cfg(test)]
                    witness
                        .cleanup_terminal
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                });
                let _ = terminal_sender.send(outcome);
            })
            .map_err(|error| error.to_string())?;
        match ready_receiver.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = thread.join();
                #[cfg(test)]
                cleanup_thread_joined.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(error);
            }
            Err(error) => {
                let _ = thread.join();
                #[cfg(test)]
                cleanup_thread_joined.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(format!(
                    "cleanup runtime readiness handshake failed: {error}"
                ));
            }
        }
        Ok(Self {
            mailbox,
            terminal: Some(terminal),
            thread_reaper,
            thread: Some(thread),
            #[cfg(test)]
            cleanup_thread_joined,
        })
    }

    fn request(&self, request: EmbeddedCleanupRequest) {
        let mut slot = self
            .mailbox
            .request
            .lock()
            .expect("embedded cleanup mailbox is not poisoned");
        debug_assert!(slot.is_none(), "embedded cleanup is requested once");
        if slot.is_none() {
            *slot = Some(request);
        }
        drop(slot);
        self.mailbox.ready.notify_one();
    }

    async fn finish_graceful(mut self) -> std::result::Result<(), String> {
        self.request(EmbeddedCleanupRequest::Graceful);
        let terminal = self
            .terminal
            .take()
            .expect("embedded cleanup task is present until shutdown");
        let terminal_result = terminal.await.map_err(|error| error.to_string())?;
        let thread = self
            .thread
            .take()
            .expect("embedded cleanup thread is present until terminal cleanup");
        let thread_result = thread.join();
        #[cfg(test)]
        self.cleanup_thread_joined
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if thread_result.is_err() {
            return Err("embedded cleanup thread panicked before join".to_string());
        }
        terminal_result
    }

    fn handoff_drop(
        &self,
        control: tokio::task::JoinHandle<std::result::Result<(), String>>,
        updater: tokio::task::JoinHandle<()>,
        service_manager: std::sync::Arc<ServiceManager>,
        registry: std::sync::Arc<NetworkRegistry>,
    ) {
        self.request(EmbeddedCleanupRequest::Dropped {
            control,
            updater,
            service_manager,
            registry,
        });
    }
}

impl Drop for EmbeddedCleanupCustodian {
    fn drop(&mut self) {
        // A daemon Drop hands the roots to this already-running owner before
        // this value is dropped. Graceful shutdown consumes its terminal
        // signal. If construction is abandoned before either handoff, wake the
        // owner into its empty terminal branch rather than leaving it parked.
        if self
            .mailbox
            .request
            .lock()
            .expect("embedded cleanup mailbox is not poisoned")
            .is_none()
        {
            self.request(EmbeddedCleanupRequest::Graceful);
        }
        if let Some(thread) = self.thread.take() {
            let batch = EmbeddedCleanupThreadBatch {
                thread,
                #[cfg(test)]
                joined: std::sync::Arc::clone(&self.cleanup_thread_joined),
            };
            match self.thread_reaper.try_send(batch) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(batch))
                | Err(std::sync::mpsc::TrySendError::Disconnected(batch)) => {
                    let _ = batch.thread.join();
                    #[cfg(test)]
                    batch
                        .joined
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    }
}

/// A daemon running inside this process. Keep it alive for the daemon's
/// lifetime; call [`shutdown`](Self::shutdown) for the same graceful teardown
/// `myownmesh serve` performs on SIGTERM (stop services, announce departures,
/// leave networks).
pub struct EmbeddedDaemon {
    mesh: myownmesh_core::MeshHandle,
    registry: std::sync::Arc<NetworkRegistry>,
    service_manager: std::sync::Arc<ServiceManager>,
    supervisor: crate::supervisor::RuntimeSupervisor,
    cleanup: Option<EmbeddedCleanupCustodian>,
    graceful_completed: bool,
    #[cfg(test)]
    _task_witness: std::sync::Arc<EmbeddedTaskWitness>,
    /// The control surface, retained so shutdown can wait for it.
    ///
    /// Held rather than detached, and that is the whole of it: dropping the
    /// handle this spawn returns detaches the task, so [`Self::shutdown`] had no
    /// way to know whether `control::serve` had returned. Its `serve` is what
    /// makes the terminal claim — no accepted connection task is still live and
    /// the client registry has reached `Closed` — and an embedder that returned
    /// from `shutdown` without it was reporting a daemon closed while its
    /// control socket, its connection tasks and their registrations were all
    /// still up.
    control: Option<tokio::task::JoinHandle<std::result::Result<(), String>>>,
    /// The updater is part of this daemon's lifecycle rather than a detached
    /// process-global task. Shutdown requests cancellation and joins it.
    updater: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for EmbeddedDaemon {
    fn drop(&mut self) {
        if self.graceful_completed {
            return;
        }
        // Drop cannot await. Latch the same cancellation state used by the
        // graceful path, then hand both root handles to the pre-existing
        // custodian. This keeps their JoinErrors and service/network teardown
        // behind one bounded owner rather than aborting and detaching them.
        self.supervisor.request_shutdown();
        let control = self
            .control
            .take()
            .expect("embedded control task is present until shutdown");
        let updater = self
            .updater
            .take()
            .expect("embedded updater task is present until shutdown");
        self.cleanup
            .as_ref()
            .expect("embedded cleanup custodian is present until shutdown")
            .handoff_drop(
                control,
                updater,
                std::sync::Arc::clone(&self.service_manager),
                std::sync::Arc::clone(&self.registry),
            );
    }
}

impl EmbeddedDaemon {
    /// The device handle — identity, events, joins.
    pub fn mesh(&self) -> &myownmesh_core::MeshHandle {
        &self.mesh
    }

    /// The runtime's shutdown request, for a host that must observe one it did
    /// not make.
    ///
    /// A reset submits through this object, so a host that only ever waits on
    /// its own signal would keep running against state the daemon has deleted.
    /// There is no subscribe-in-time rule: the request is a latched state, and
    /// `wait_requested` resolves on one submitted before this handle even
    /// existed — which it can be, since the control socket is accepting before
    /// startup returns.
    pub fn supervisor(&self) -> &crate::supervisor::RuntimeSupervisor {
        &self.supervisor
    }

    /// Hold this daemon until its runtime is asked to stop, then drain it.
    ///
    /// The whole of what a host with no signal source of its own has to do, and
    /// the reason it exists is that the two halves were previously the host's to
    /// join: a reset submitted through the supervisor stopped the *control
    /// surface*, while hosted services, departure announcements and every joined
    /// network were only torn down by [`Self::shutdown`]. A host that did not
    /// write that glue kept a half-dead daemon.
    ///
    /// One drain, shared with an embedder's explicit `shutdown` — this is that
    /// call, after the wait. Idempotent because it consumes the daemon: there is
    /// no second drain to run, rather than a flag saying there is not. Nothing
    /// here is timed and nothing ends the host process; this returns and the
    /// application carries on.
    pub async fn run_until_shutdown(self) -> std::result::Result<(), EmbeddedShutdownError> {
        self.supervisor.wait_requested().await;
        self.shutdown().await
    }

    /// Graceful teardown, exactly like the serve binary's signal path.
    ///
    /// The control surface goes first and is *awaited*, and the order is the
    /// contract rather than a preference. Everything below this line removes
    /// state a control request can still be dispatched against — hosted
    /// services, then every joined network — so a connection task outliving the
    /// broadcast would be operating on a daemon that had already reported those
    /// gone. Awaiting `serve` is what establishes that no such task exists: it
    /// does not return until every connection it accepted has ended and its
    /// client registry has reached `Closed`.
    ///
    /// Nothing here is timed. `serve`'s own drain is what ends the accepted
    /// tasks, and it ends them by signalling rather than by aborting, so a
    /// request already in flight is finished rather than dropped half-applied.
    pub async fn shutdown(mut self) -> std::result::Result<(), EmbeddedShutdownError> {
        // The same request a reset submits, through the same object: idempotent,
        // so a daemon already draining because its state was reset is not
        // signalled twice, and an embedder is never told to wait on a second
        // drain that will not happen.
        self.supervisor.request_shutdown();
        // The control surface, before anything it might still be serving is
        // taken away. A panic in the control task is reported rather than
        // swallowed: it means the drain did not complete, and the teardown below
        // is then running against state the control surface may still hold.
        let mut failures = Vec::new();
        match self
            .control
            .take()
            .expect("embedded control task is present until shutdown")
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!("control task returned an error: {error}");
                failures.push(EmbeddedShutdownFailure {
                    stage: "control",
                    error,
                });
            }
            Err(error) => {
                warn!("control task did not end cleanly: {error}");
                failures.push(EmbeddedShutdownFailure {
                    stage: "control",
                    error: error.to_string(),
                });
            }
        }
        if let Err(error) = self
            .updater
            .take()
            .expect("embedded updater task is present until shutdown")
            .await
        {
            warn!("updater task did not end cleanly: {error}");
            failures.push(EmbeddedShutdownFailure {
                stage: "updater",
                error: error.to_string(),
            });
        }
        // Stop hosted services before tearing down networks.
        if let Err(error) = self.service_manager.shutdown().await {
            warn!("hosted service shutdown failed: {error}");
            failures.push(EmbeddedShutdownFailure {
                stage: "services",
                error: error.to_string(),
            });
        }
        // Supervise authenticated departures with teardown. A silent peer can
        // otherwise hold departure forever before shutdown gets to cancel its
        // waiter; the carrier hint remains in the departure future. Nothing is
        // skipped, and failed teardown is reported rather than assumed clean.
        for outcome in self.registry.shutdown_all_with_departures().await {
            if let Err(e) = outcome {
                warn!("network shutdown failed: {e}");
                failures.push(EmbeddedShutdownFailure {
                    stage: "network",
                    error: e,
                });
            }
        }
        if let Some(cleanup) = self.cleanup.take() {
            if let Err(error) = cleanup.finish_graceful().await {
                warn!("embedded cleanup custodian did not end cleanly: {error}");
                failures.push(EmbeddedShutdownFailure {
                    stage: "cleanup",
                    error,
                });
            }
        }
        self.graceful_completed = true;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(EmbeddedShutdownError { failures })
        }
    }
}

/// Start the daemon with the connector policy selected by the process owner.
///
/// This is the only Arc 03 daemon path that can establish connectors. No
/// capacity, callback weight, or structural real-time limit is inferred here.
///
/// `realtime` must describe the profile that was actually registered on
/// `connector_policy` — [`RealtimeAdvert::unsupported`] if none was. It travels
/// separately rather than being read back off the policy because core keeps a
/// registered profile's codecs and capacity crate-private, so the caller that
/// registered it is the only place that can still see both halves.
///
/// It carries no promise: support, the registered encoding families, and a
/// ceiling only where the owner stated one. Whether a particular flow can open
/// is answered by the typed refusal at open time.
pub async fn start_connector_capable(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, realtime).await
}

/// Start a daemon that only hosts signaling, STUN, or TURN infrastructure.
///
/// The configuration must explicitly disable node participation. This form
/// installs no connector policy, joins no network, and cannot later enable
/// node participation through the live service configuration.
///
/// It still takes the owner's exact resource port. Installing no connector
/// policy removes the connector's demands, not the daemon's: this process
/// still admits IPC payloads, local application state and its own tasks, and
/// all of that has to be funded from an envelope the owner chose rather than
/// from one this function invented.
pub async fn start_infrastructure_only(
    cfg: myownmesh_core::MeshConfig,
    resources: myownmesh_core::ResourceProviderPort,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    if cfg.services.node.enabled {
        return Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled);
    }
    let mesh = myownmesh_core::Mesh::open_infrastructure_only(cfg.clone(), resources).await?;
    // Infrastructure-only installs no connector policy at all, so there is no
    // realtime path to advertise.
    start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported()).await
}

async fn start_with_mesh(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    start_with_mesh_inner(cfg, mesh, realtime, false).await
}

#[cfg(all(test, unix))]
async fn start_with_mesh_for_drop_control(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    start_with_mesh_inner(cfg, mesh, realtime, true).await
}

async fn start_with_mesh_inner(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
    park_updater_for_test: bool,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    #[cfg(not(test))]
    let _ = park_updater_for_test;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        networks = cfg.networks.len(),
        "embedded daemon starting"
    );

    info!(device_id = %mesh.identity().display_id(), "identity ready");

    // Recover interrupted provisional custody before any control socket is
    // spawned. A corrupt store or an unresolvable owner lease is a startup
    // failure: exposing a live control surface while custody state is
    // uncertain would turn an interrupted handoff into an authority decision.
    myownmesh_core::custody::recover_provisional_enrollments()
        .map_err(EmbeddedStartError::CustodyRecovery)?;

    // Construct and synchronously ready the cleanup owner before any service,
    // network, listener, or daemon root can be started. A readiness failure
    // therefore returns the caller's lease before startup has background work
    // to clean up.
    let cleanup_scope = mesh.local_application_resource_scope()?;
    let thread_reaper = embedded_cleanup_thread_reaper(&cleanup_scope)
        .map_err(EmbeddedStartError::CleanupCustody)?;
    let cleanup_lease = cleanup_scope
        .acquire(myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::WorkerOrTask,
            1,
        ))
        .map_err(|error| EmbeddedStartError::CleanupCustody(error.to_string()))?;
    #[cfg(test)]
    let task_witness = std::sync::Arc::new(EmbeddedTaskWitness::new());
    #[cfg(test)]
    if !park_updater_for_test {
        task_witness
            .updater_gate_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    let cleanup_witness = std::sync::Arc::clone(&task_witness);
    let cleanup = EmbeddedCleanupCustodian::new(
        cleanup_lease,
        thread_reaper,
        #[cfg(test)]
        cleanup_witness,
    )
    .map_err(EmbeddedStartError::CleanupCustody)?;

    // The registry holds every JoinedNetwork + its signaling driver handle so
    // the control socket can address them by id. Node participation is a
    // toggle, exactly as in the serve binary.
    let registry = NetworkRegistry::new();
    if cfg.services.node.enabled {
        if let Err(error) =
            crate::services::join_networks_checked(&mesh, &registry, &cfg.networks).await
        {
            for outcome in registry.shutdown_all_with_departures().await {
                if let Err(cleanup_error) = outcome {
                    warn!("network startup refusal cleanup failed: {cleanup_error}");
                }
            }
            return Err(EmbeddedStartError::NetworkStartup(error));
        }
    } else {
        info!("node participation disabled — pure-infrastructure mode (hosting services only)");
    }

    // Infrastructure services (signaling / STUN / TURN); an all-off config
    // (the default) starts nothing.
    let service_manager = ServiceManager::new(mesh.clone(), registry.clone());
    let report = match service_manager.apply(cfg.services.clone()).await {
        Ok(report) => report,
        Err(error) => {
            if let Err(cleanup_error) = service_manager.shutdown().await {
                warn!("service startup refusal cleanup failed: {cleanup_error}");
            }
            for outcome in registry.shutdown_all_with_departures().await {
                if let Err(cleanup_error) = outcome {
                    warn!("network startup cleanup failed: {cleanup_error}");
                }
            }
            return Err(error.into());
        }
    };
    info!(
        signaling = report.signaling.running,
        stun = report.stun.running,
        turn = report.turn.running,
        "services applied from config"
    );

    // Updater tick. Spawned even when disabled in config — the task just
    // exits early.
    // The updater is owned by the embedded daemon and observes the same
    // latched shutdown signal as the control surface.
    let supervisor = crate::supervisor::RuntimeSupervisor::new();
    let updater_supervisor = supervisor.clone();
    #[cfg(test)]
    let updater_witness = std::sync::Arc::clone(&task_witness);
    let updater = tokio::spawn(async move {
        #[cfg(test)]
        let _terminal =
            EmbeddedTaskTerminal(std::sync::Arc::clone(&updater_witness.updater_terminal));
        #[cfg(test)]
        updater_witness
            .updater_started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        loop {
            if updater_witness
                .updater_gate_open
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            let notified = updater_witness.updater_gate.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if updater_witness
                .updater_gate_open
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            tokio::select! {
                _ = notified => {}
                _ = updater_supervisor.wait_requested() => break,
            }
        }
        myownmesh_updater::tick_until_shutdown(async move {
            updater_supervisor.wait_requested().await;
        })
        .await;
    });

    // Control socket: the same listener + wire protocol every client talks
    // to, whether the daemon is a process or embedded.
    let ctl_supervisor = supervisor.clone();
    let ctl_mesh = mesh.clone();
    let ctl_registry = registry.clone();
    let ctl_services = service_manager.clone();
    let ctl_socket = cfg.daemon.control_socket.clone();
    #[cfg(test)]
    let control_witness = std::sync::Arc::clone(&task_witness);
    // Kept, not discarded. See [`EmbeddedDaemon::control`].
    let control = tokio::spawn(async move {
        #[cfg(test)]
        let _terminal =
            EmbeddedTaskTerminal(std::sync::Arc::clone(&control_witness.control_terminal));
        #[cfg(test)]
        control_witness
            .control_started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        control::serve(
            ctl_mesh,
            ctl_registry,
            ctl_services,
            ctl_socket,
            realtime,
            ctl_supervisor,
        )
        .await
        .map_err(|error| error.to_string())
    });

    Ok(EmbeddedDaemon {
        mesh,
        registry,
        service_manager,
        supervisor,
        cleanup: Some(cleanup),
        graceful_completed: false,
        #[cfg(test)]
        _task_witness: task_witness,
        control: Some(control),
        updater: Some(updater),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The connector-capable startup fixture below installs a connector policy,
    // so it spends from the one binary-wide budget `crate::test_resource_provider`
    // grants. It serializes on `crate::exclusive_connector_fixture` with every
    // other module that draws on the same pool. The infrastructure-only test
    // beside it installs no policy and takes no guard.

    fn connector_test_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        // Elastic real-time, which is the only shape there is: what this
        // fixture may do is what `crate::test_resource_provider` funds, and the
        // eleven local counts that used to be stated here bounded nothing the
        // provider was not already bounding.
        let webrtc = myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_realtime(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), webrtc)
    }

    /// Initialize the process-lifetime cleanup-thread owner before taking a
    /// provider baseline. Its one `WorkerOrTask` lease is deliberately part of
    /// that baseline, not a hidden first-start delta attributed to a daemon.
    #[cfg(unix)]
    fn ensure_cleanup_thread_reaper_for_test() {
        let scope = crate::test_application_scope();
        embedded_cleanup_thread_reaper(&scope)
            .expect("the test provider funds the process cleanup-thread reaper");
    }

    fn cleanup_reaper_control_grant(worker_capacity: u64) -> myownmesh_core::ResourceClaim {
        myownmesh_core::ResourceClaim::try_from_entries([
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                2_u64
                    .checked_add(worker_capacity)
                    .expect("the bounded cleanup reaper control grant is representable"),
            ),
            (myownmesh_core::ResourceClass::WorkerOrTask, worker_capacity),
        ])
        .expect("the cleanup reaper control grant is representable")
    }

    /// A transient provider refusal must not poison process-lifetime reaper
    /// initialization. The first exact provider funds its two scopes but no
    /// `WorkerOrTask`; a later provider funds exactly the process scope, local
    /// scope, and one reaper reservation and can therefore start and join the
    /// owner in the same process.
    #[test]
    fn cleanup_reaper_retries_after_transient_worker_refusal() {
        let refused_provider =
            myownmesh_core::FiniteResourceProvider::new(cleanup_reaper_control_grant(0));
        let refused_port = myownmesh_core::ResourceProviderPort::new(refused_provider)
            .expect("the refusal provider funds its process scope");
        let refused_scope =
            myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&refused_port)
                .expect("the refusal provider funds its local scope");
        let slot = std::sync::Mutex::new(None);
        let refusal = embedded_cleanup_thread_reaper_in(&refused_scope, &slot);
        assert!(
            refusal.is_err(),
            "the first provider refuses the reaper before a thread is spawned"
        );
        assert!(
            slot.lock()
                .expect("the isolated reaper slot is not poisoned")
                .is_none(),
            "a transient refusal must not publish an error or partial owner"
        );
        drop(refused_scope);
        drop(refused_port);

        let provider = myownmesh_core::FiniteResourceProvider::new(cleanup_reaper_control_grant(1));
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the retry provider funds its process scope");
        let scope = myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("the retry provider funds its local scope");
        let sender = embedded_cleanup_thread_reaper_in(&scope, &slot)
            .expect("the exact-capacity retry provider starts the reaper");
        assert_eq!(
            provider
                .in_use()
                .amount(myownmesh_core::ResourceClass::WorkerOrTask),
            1
        );

        let joined = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_joined = std::sync::Arc::clone(&joined);
        let thread = std::thread::spawn(move || {
            thread_joined.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        sender
            .send(EmbeddedCleanupThreadBatch {
                thread,
                joined: std::sync::Arc::clone(&joined),
            })
            .expect("the live retry reaper accepts one bounded join request");
        drop(sender);
        drop(slot);
        assert!(
            joined.load(std::sync::atomic::Ordering::SeqCst),
            "the successful retry owner observes its queued thread terminal"
        );
        drop(scope);
        drop(port);
        assert_eq!(provider.in_use(), myownmesh_core::ResourceClaim::ZERO);
    }

    /// Cleanup runtime readiness is a startup gate: an injected construction
    /// failure must return before either root task or the control listener is
    /// created, and the reserved provider capacity must be returned.
    #[cfg(unix)]
    #[tokio::test]
    async fn embedded_cleanup_runtime_failure_leaves_no_startup_residue() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};

        let _fixture = crate::exclusive_connector_fixture().await;
        let provider = crate::test_resource_provider();
        ensure_cleanup_thread_reaper_for_test();
        let process_scope = provider.process_scope();
        let baseline = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes its process pressure");
        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            provider.clone(),
        )
        .await
        .expect("the test mesh opens before cleanup readiness");

        set_cleanup_runtime_failure_for_test(true);
        let result =
            start_with_mesh_for_drop_control(cfg, mesh, control::RealtimeAdvert::unsupported())
                .await;
        set_cleanup_runtime_failure_for_test(false);
        match result {
            Err(EmbeddedStartError::CleanupCustody(error)) => {
                assert!(error.contains("injected cleanup runtime failure"));
            }
            Err(_) => panic!("injected readiness returned the wrong startup error"),
            Ok(_) => panic!("injected readiness unexpectedly started the daemon"),
        }

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "readiness failure occurs before the control listener/root tasks"
        );
        let after = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes post-failure pressure");
        assert_eq!(
            after, baseline,
            "readiness refusal returns the exact WorkerOrTask provider baseline"
        );
    }

    /// `shutdown` does not return before `control::serve` and the connections it
    /// accepted have ended.
    ///
    /// Dropping the spawn's `JoinHandle` would detach the task, leaving
    /// `shutdown` nothing to wait on: it would return while the control socket,
    /// its connection tasks and their registrations were all still up, and then
    /// tear down the services and networks those tasks were still dispatching
    /// against, telling an embedder the daemon was closed while it was not.
    ///
    /// The load-bearing observation is taken at the ordering boundary itself:
    /// the control task sets a witness only after `serve` returns, and shutdown
    /// snapshots that witness immediately before it starts service teardown.
    /// A detached task that happens to finish on the next await cannot make that
    /// earlier snapshot true.
    ///
    /// Two external consequences are asserted as companions, and neither is a
    /// duration:
    ///
    /// 1. the client's own socket reaches end of file, which happens when the
    ///    connection task that was serving it has ended;
    /// 2. and a fresh connect to the same path is refused, which can only be
    ///    true once `serve` has returned and taken its listener with it.
    ///
    /// The subscription is what makes the first claim non-vacuous. An idle
    /// connection might end for any number of reasons; an `events_subscribe`
    /// that has been acked is a connection parked in the stream loop, which is
    /// exactly the task `shutdown` has to wait for.
    ///
    /// Unix-only, for the reason the control-surface shutdown controls are: a
    /// socket at a path this control chooses. Elsewhere the name is
    /// process-wide and two controls in one binary would fight over it.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r2_daemon_embedded_shutdown_waits_for_its_control_surface() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        /// Long enough that a loaded machine will not trip it, short enough that
        /// a genuine hang is named. Nothing below asserts because of it.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);
        async fn guarded<F: std::future::Future>(what: &str, future: F) -> F::Output {
            match tokio::time::timeout(HANG_GUARD, future).await {
                Ok(value) => value,
                Err(_) => panic!("hang guard: {what}"),
            }
        }

        let temp = tempfile::tempdir().expect("temporary daemon state");
        // The parent is deliberately absent: production creates it with
        // owner-only permissions before binding.
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };

        // Parallel test binaries must not race over the process identity
        // anchor in the runner's home directory. Identity injection changes
        // only key storage; `start_with_mesh` below is the same embedded
        // daemon path whose control task and shutdown ordering this control
        // owns.
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon = start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported())
            .await
            .expect("the daemon test grant starts an infrastructure-only daemon");

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let stream = guarded("client connects", async {
            loop {
                // The listener binds inside the spawned control task, so the
                // first connect can lose the race with it. The guard is what
                // fails if it never appears at all.
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => return stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        let (client_reader, mut client_writer) = stream.split();
        let mut client_reader = BufReader::new(client_reader);
        client_writer
            .write_all(b"{\"op\":\"events_subscribe\"}\n")
            .await
            .expect("the client sends its subscribe");
        let mut ack = String::new();
        guarded(
            "the subscription is acked",
            client_reader.read_line(&mut ack),
        )
        .await
        .expect("the daemon answers the subscribe");
        assert!(
            ack.contains("\"subscribed\":true"),
            "non-vacuity: this connection is parked in the stream loop: {ack}"
        );

        guarded("embedded shutdown returns", daemon.shutdown())
            .await
            .expect("embedded daemon shutdown succeeds");

        // The claim, read from outside the daemon: this client's connection was
        // parked in the stream loop above, so a shutdown that returned while
        // `control::serve` was still up would leave it open. That it reads to
        // end is the ordering.
        let mut rest = Vec::new();
        guarded(
            "the client's connection ended",
            client_reader.read_to_end(&mut rest),
        )
        .await
        .expect("the client's half reads to end");

        // And the listener is gone with it.
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "serve returned, so its control socket no longer accepts connections"
        );
    }

    /// The synchronous backstop is distinct from graceful `shutdown`: a host
    /// that abandons the handle must at least latch cancellation and hand the
    /// root tasks to the pre-existing cleanup custodian before their join
    /// handles are dropped. The cloned supervisor makes the latch observable
    /// after the daemon itself is gone; the refused reconnect proves the
    /// control listener was not detached.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r7_embedded_drop_latches_and_drains_root_tasks() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon =
            start_with_mesh_for_drop_control(cfg, mesh, control::RealtimeAdvert::unsupported())
                .await
                .expect("the daemon test grant starts an infrastructure-only daemon");
        let supervisor = daemon.supervisor().clone();
        let witness = std::sync::Arc::clone(&daemon._task_witness);
        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");

        let stream = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("the control listener starts and accepts a client");
        let (reader, mut writer) = stream.split();
        writer
            .write_all(b"{\"op\":\"events_subscribe\"}\n")
            .await
            .expect("the live control client sends subscribe");
        let mut reader = BufReader::new(reader);
        let mut ack = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reader.read_line(&mut ack),
        )
        .await
        .expect("the live control client receives an ack")
        .expect("the live control client can read its ack");
        assert!(ack.contains("\"subscribed\":true"));
        assert!(
            witness
                .control_started
                .load(std::sync::atomic::Ordering::SeqCst),
            "drop control is non-vacuous: control task started"
        );
        assert!(
            witness
                .updater_started
                .load(std::sync::atomic::Ordering::SeqCst),
            "drop control is non-vacuous: updater task started"
        );
        assert!(
            !witness
                .updater_gate_open
                .load(std::sync::atomic::Ordering::SeqCst)
                && !witness
                    .updater_terminal
                    .load(std::sync::atomic::Ordering::SeqCst),
            "drop control holds a live updater root before Drop"
        );
        drop(daemon);
        assert!(
            supervisor.shutdown_requested(),
            "drop must synchronously latch the daemon cancellation state"
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !witness
                .control_terminal
                .load(std::sync::atomic::Ordering::SeqCst)
                || !witness
                    .updater_terminal
                    .load(std::sync::atomic::Ordering::SeqCst)
                || !witness
                    .cleanup_terminal
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("drop observes roots and cleanup custodian reach terminal state");
        assert!(
            witness
                .cleanup_thread_joined
                .load(std::sync::atomic::Ordering::SeqCst),
            "drop cleanup terminal includes an observed OS-thread join"
        );
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "drop must drain the live root control task rather than detach it"
        );
        drop(temp);
    }

    /// Drop is also safe when the caller destroys its runtime before dropping
    /// the daemon. The cleanup custodian owns the handoff on its own OS thread
    /// and runtime, so the canceled root join errors remain observable rather
    /// than being lost with the caller runtime.
    #[cfg(unix)]
    #[test]
    fn v4_r7_embedded_drop_survives_caller_runtime_destruction() {
        use std::sync::atomic::Ordering;

        let fixture_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the fixture runtime builds");
        let _fixture = fixture_runtime.block_on(crate::exclusive_connector_fixture());
        drop(fixture_runtime);
        let provider = crate::test_resource_provider();
        ensure_cleanup_thread_reaper_for_test();
        let process_scope = provider.process_scope();
        let baseline = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes its process pressure");

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the inner current-thread runtime builds");
        let startup_provider = provider.clone();
        let (daemon, witness, supervisor, temp) = runtime.block_on(async move {
            let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
            daemon_config.control_socket = Some(socket);
            let mut services = myownmesh_core::MeshConfig::default().services;
            services.node.enabled = false;
            let cfg = myownmesh_core::MeshConfig {
                auto_update: myownmesh_core::AutoUpdateConfig {
                    enabled: false,
                    ..Default::default()
                },
                daemon: daemon_config,
                services,
                ..Default::default()
            };
            let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
                cfg.clone(),
                std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
                startup_provider,
            )
            .await
            .expect("the inner runtime opens the infrastructure-only mesh");
            let daemon =
                start_with_mesh_for_drop_control(cfg, mesh, control::RealtimeAdvert::unsupported())
                    .await
                    .expect("the inner runtime starts the daemon");
            let witness = std::sync::Arc::clone(&daemon._task_witness);
            let supervisor = daemon.supervisor().clone();
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            assert!(
                witness.updater_started.load(Ordering::SeqCst),
                "the runtime-destruction control starts the updater root"
            );
            assert!(
                !witness.updater_terminal.load(Ordering::SeqCst),
                "the updater remains live before the caller runtime is destroyed"
            );
            (daemon, witness, supervisor, temp)
        });

        // The daemon is deliberately dropped with no caller runtime alive.
        drop(runtime);
        assert!(
            !supervisor.shutdown_requested(),
            "runtime destruction alone does not submit daemon shutdown"
        );
        drop(daemon);
        assert!(
            supervisor.shutdown_requested(),
            "outside-runtime Drop latches the daemon cancellation state"
        );

        let observer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the outside observer runtime builds");
        observer.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !witness
                    .cleanup_terminal
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the independent custodian reaches terminal cleanup");
        });
        drop(observer);

        assert!(
            witness.cleanup_thread_joined.load(Ordering::SeqCst),
            "outside-runtime cleanup reports the OS-thread join"
        );
        assert!(
            witness.cleanup_root_join_errors.load(Ordering::SeqCst) > 0,
            "runtime destruction produces an observed root JoinError"
        );
        let join_errors = witness.cleanup_root_join_errors.load(Ordering::SeqCst);
        let panics = witness.cleanup_root_panics.load(Ordering::SeqCst);
        let cancellations = witness.cleanup_root_cancellations.load(Ordering::SeqCst);
        assert_eq!(
            join_errors,
            panics + cancellations,
            "every root JoinError is classified exactly once"
        );
        assert!(
            cancellations > 0,
            "caller-runtime destruction is observed as root cancellation"
        );

        let after = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes post-cleanup pressure");
        assert_eq!(
            after, baseline,
            "cleanup returns the exact WorkerOrTask provider baseline"
        );
        drop(temp);
    }

    /// A reset submitted **before** the host has a waiter still drains the whole
    /// daemon, and leaves the process hosting it running.
    ///
    /// The discriminating control for B2, and the ordering is the whole of it.
    /// The request used to be a broadcast send: `start_with_mesh` spawns the
    /// control socket and only *then* returns the handle a host could subscribe
    /// through, so a reset arriving in that window signalled nobody, latched the
    /// submitted flag so no later request could signal either, and left the host
    /// waiting forever on a daemon whose state had already been deleted. Here
    /// the request is submitted first — the way the reset arm submits it, once
    /// its response has reached a write disposition — and the waiter is
    /// constructed afterwards, by `run_until_shutdown`.
    ///
    /// `run_until_shutdown` rather than a direct `shutdown`, because a direct
    /// call drains whether or not anything ever observed the request, which is
    /// exactly the claim under test. What it reaches is the same single drain:
    /// the control surface awaited, then hosted services, then departures, then
    /// every joined network.
    ///
    /// The request and an embedder's own `shutdown` are one idempotent path, so
    /// a second submission submits nothing second — asserted rather than
    /// inferred.
    ///
    /// The host being alive is not asserted with a duration or a probe: this
    /// control body simply continues, and a process that had exited could not
    /// run it.
    ///
    /// Unix-only for the reason the control above is: the socket sits at a path
    /// this control chooses.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r7_daemon_b2_a_reset_submitted_before_any_waiter_drains_the_whole_daemon() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};

        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon = start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported())
            .await
            .expect("the daemon test grant starts an infrastructure-only daemon");

        assert!(
            !daemon.supervisor().shutdown_requested(),
            "non-vacuity: nothing has asked this runtime to stop yet"
        );
        // The reset arm's action, submitted once the response has reached its
        // write disposition — and before anything below waits on it.
        assert!(
            daemon.supervisor().request_shutdown(),
            "the reset submits the one request"
        );
        // And the embedder's own shutdown, on the same path, afterwards.
        assert!(
            !daemon.supervisor().request_shutdown(),
            "which a later caller does not submit a second time"
        );

        // The waiter is constructed here, strictly after both submissions. A
        // request that had been a notification would have nothing left to
        // deliver, and this would never return.
        match tokio::time::timeout(HANG_GUARD, daemon.run_until_shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("daemon shutdown failed: {error}"),
            Err(_) => panic!("hang guard: a waiter built after the request resolves and drains"),
        }

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "the drain really ran: serve returned and took its listener with it"
        );
        // Reached, which is the whole of the host-process claim.
        drop(temp);
    }

    #[tokio::test]
    async fn infrastructure_start_requires_node_participation_disabled() {
        // A real port, so the refusal below is the node-participation check and
        // not a missing grant standing in for it.
        let result = start_infrastructure_only(
            myownmesh_core::MeshConfig::default(),
            crate::test_resource_provider(),
        )
        .await;
        assert!(matches!(
            result,
            Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled)
        ));
    }

    /// Configured network startup is checked as a unit: an invalid entry is
    /// returned to the embedder before the control surface becomes live, and
    /// any earlier joined entry is drained through the same registry owner.
    #[tokio::test]
    async fn checked_network_startup_propagates_refusal_before_control_spawn() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let temp = tempfile::tempdir().expect("temporary startup state");
        let mut cfg = myownmesh_core::MeshConfig {
            identity_path: Some(temp.path().join("identity.json")),
            daemon: myownmesh_core::config::DaemonConfig {
                control_socket: Some(temp.path().join("daemon.sock")),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut invalid =
            myownmesh_core::NetworkConfig::from_network_id("startup-control", "startup-network");
        invalid.network_id.clear();
        cfg.networks.push(invalid);

        let result = start_connector_capable(
            cfg,
            connector_test_policy(),
            control::RealtimeAdvert::unsupported(),
        )
        .await;
        match result {
            Err(EmbeddedStartError::NetworkStartup(error)) => {
                assert!(
                    error.contains("network id is empty"),
                    "typed refusal: {error}"
                );
            }
            Err(other) => panic!("startup returned the wrong typed error: {other}"),
            Ok(_) => panic!("invalid configured network unexpectedly started"),
        }
        assert!(
            !temp.path().join("daemon.sock").exists(),
            "network startup refusal precedes control listener creation"
        );
    }

    /// There is one connector-capable startup form, and it takes only the
    /// owner-supplied policy: a policy carrying no sidecar profile still
    /// produces a connector, so no second form is needed and none can install an
    /// authority the caller could not otherwise reach.
    #[tokio::test]
    async fn the_connector_capable_daemon_starts_from_the_owner_policy_alone() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let temp = tempfile::tempdir().expect("temporary daemon state");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(temp.path().join("daemon.sock"));
        let cfg = myownmesh_core::MeshConfig {
            identity_path: Some(temp.path().join("identity.json")),
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            ..Default::default()
        };

        let daemon = start_connector_capable(
            cfg,
            connector_test_policy(),
            control::RealtimeAdvert::unsupported(),
        )
        .await
        .expect("the connector-capable daemon starts from the policy alone");
        assert!(daemon.mesh().connector_resource_report().is_some());
        daemon
            .shutdown()
            .await
            .expect("connector-capable daemon shutdown succeeds");
    }

    /// A caller may destroy its current-thread runtime while the embedded
    /// daemon owns real service and network state. Drop must transfer both
    /// roots to the independent cleanup owner, join that owner thread, and
    /// return every service/registry/provider charge to the exact baseline.
    #[cfg(unix)]
    #[test]
    fn embedded_drop_with_live_service_and_registry_returns_exact_baseline() {
        use std::sync::atomic::Ordering;

        let fixture_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the fixture runtime builds");
        let _fixture = fixture_runtime.block_on(crate::exclusive_connector_fixture());
        drop(fixture_runtime);

        let provider = crate::test_resource_provider();
        ensure_cleanup_thread_reaper_for_test();
        let process_scope = provider.process_scope();
        let baseline_worker = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes worker pressure")
            .in_use;
        let baseline_opaque = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            )
            .expect("the test provider exposes opaque pressure")
            .in_use;

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the inner current-thread runtime builds");
        let startup_provider = provider.clone();
        let (daemon, witness, supervisor, registry, services, temp) =
            runtime.block_on(async move {
                let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
                daemon_config.control_socket = Some(socket);
                let mut service_config = myownmesh_core::MeshConfig::default().services;
                service_config.stun.enabled = true;
                service_config.stun.bind = "127.0.0.1".into();
                service_config.stun.port = 0;

                let mut network = myownmesh_core::config::NetworkConfig::from_network_id(
                    "embedded-live-registry",
                    "embedded-live-registry",
                );
                network.signaling.strategy = "none".into();
                network.signaling.mdns = true;
                network.stun_servers.clear();
                network.turn_servers.clear();
                let cfg = myownmesh_core::MeshConfig {
                    auto_update: myownmesh_core::AutoUpdateConfig {
                        enabled: false,
                        ..Default::default()
                    },
                    daemon: daemon_config,
                    services: service_config,
                    networks: vec![network],
                    ..Default::default()
                };
                let mesh = myownmesh_core::Mesh::open_connector_capable_with_identity(
                    cfg.clone(),
                    std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
                    connector_test_policy(),
                )
                .await
                .expect("the inner runtime opens the connector-capable mesh");
                let daemon = start_with_mesh_for_drop_control(
                    cfg,
                    mesh,
                    control::RealtimeAdvert::unsupported(),
                )
                .await
                .expect("the inner runtime starts the live daemon");
                let status = daemon.service_manager.status().await;
                assert!(
                    status.stun.running,
                    "the live STUN service is actually running"
                );
                assert_eq!(
                    daemon.registry.joined_count(),
                    1,
                    "the registry owns one live network"
                );
                let witness = std::sync::Arc::clone(&daemon._task_witness);
                let supervisor = daemon.supervisor().clone();
                let registry = std::sync::Arc::clone(&daemon.registry);
                let services = std::sync::Arc::clone(&daemon.service_manager);
                (daemon, witness, supervisor, registry, services, temp)
            });

        drop(runtime);
        assert!(!supervisor.shutdown_requested());
        drop(daemon);
        assert!(supervisor.shutdown_requested());

        let observer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the outside observer runtime builds");
        observer.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !witness.cleanup_terminal.load(Ordering::SeqCst)
                    || !witness.cleanup_thread_joined.load(Ordering::SeqCst)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the independent custodian joins after cleanup");
            assert_eq!(registry.joined_count(), 0, "Drop drains the live registry");
            assert!(
                !services.status().await.stun.running,
                "Drop drains the live STUN service"
            );
        });
        drop(observer);

        assert_eq!(
            provider
                .pressure(
                    &process_scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    myownmesh_core::ResourceClass::WorkerOrTask,
                )
                .expect("post-cleanup worker pressure")
                .in_use,
            baseline_worker,
        );
        assert_eq!(
            provider
                .pressure(
                    &process_scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                )
                .expect("post-cleanup opaque pressure")
                .in_use,
            baseline_opaque,
        );
        drop(temp);
    }
}
