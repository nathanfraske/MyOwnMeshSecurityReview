//! The pure-Rust discovery backend: a per-driver `mdns-sd` [`ServiceDaemon`]
//! owning its own multicast socket set (SO_REUSEADDR/SO_REUSEPORT), which
//! also lets it coexist with a system avahi/Bonjour daemon. This is the
//! pre-seam behaviour, extracted verbatim.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{debug, trace};

use super::{
    DiscoveryConfig, DiscoveryEvent, DiscoveryEventAdmission, DiscoveryEventCoalescer,
    MAX_DNS_NAME_BYTES, MAX_RESOLVED_ADDRESSES, MAX_TXT_BYTES, MAX_TXT_ENTRIES, MAX_TXT_KEY_BYTES,
    MAX_TXT_VALUE_BYTES,
};
use crate::Error;

pub struct Discovery {
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
    fullname: String,
    pump: Option<JoinHandle<()>>,
    shutdown_request: watch::Sender<bool>,
    shutdown_ack: Arc<Mutex<Option<mdns_sd::Receiver<mdns_sd::DaemonStatus>>>>,
    stopped: AtomicBool,
}

impl Discovery {
    /// Bring the daemon up, start browsing, and hand back the event stream.
    /// Browse starts before the first [`register`](Self::register) so we never
    /// miss a burst of resolves racing our own announce.
    pub fn start(cfg: &DiscoveryConfig) -> crate::Result<(Self, mpsc::Receiver<DiscoveryEvent>)> {
        if !cfg.limits.validate() {
            return Err(Error::Other("invalid discovery limits".into()));
        }
        let daemon = ServiceDaemon::new().map_err(|e| Error::Other(format!("mdns daemon: {e}")))?;

        let host_name = format!("{}.local.", cfg.instance);
        let props: std::collections::HashMap<String, String> = cfg.txt.iter().cloned().collect();
        let service_info = ServiceInfo::new(
            &cfg.service_type,
            &cfg.instance,
            &host_name,
            "",
            cfg.port,
            props,
        )
        .map_err(|e| Error::Other(format!("mdns service info: {e}")))?
        .enable_addr_auto();
        let fullname = service_info.get_fullname().to_string();

        let browse_rx = daemon
            .browse(&cfg.service_type)
            .map_err(|e| Error::Other(format!("mdns browse: {e}")))?;

        let (tx, rx) = mpsc::channel(cfg.limits.event_capacity);
        let (forward_tx, forward_rx) = mpsc::channel(cfg.limits.event_capacity);
        let (progress_tx, progress_rx) = mpsc::channel(1);
        let (stop, stop_rx) = watch::channel(false);
        let discovery_limits = cfg.limits;
        let forwarder = tokio::spawn(async move {
            deliver(forward_rx, tx, progress_tx, stop_rx).await;
        });
        let pump_stop = stop.subscribe();
        let pump = tokio::spawn(async move {
            pump(
                browse_rx,
                forward_tx,
                progress_rx,
                pump_stop,
                discovery_limits,
            )
            .await;
            trace!("mdns embedded browse pump exiting");
        });
        let (shutdown_request, shutdown_request_rx) = watch::channel(false);
        let shutdown_ack: Arc<Mutex<Option<mdns_sd::Receiver<mdns_sd::DaemonStatus>>>> =
            Arc::new(Mutex::new(None));
        let supervisor = tokio::spawn(supervise_shutdown(
            shutdown_request_rx,
            shutdown_ack.clone(),
            stop.clone(),
            pump,
            forwarder,
        ));

        Ok((
            Discovery {
                daemon,
                service_info,
                fullname,
                pump: Some(supervisor),
                shutdown_request,
                shutdown_ack,
                stopped: AtomicBool::new(false),
            },
            rx,
        ))
    }

    /// Attempt (re-)registration — the announce. Repeats are cheap no-ops on
    /// the daemon. `false` = soft failure (e.g. no usable interface yet); the
    /// caller's re-announce tick retries.
    pub fn register(&self) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        match self.daemon.register(self.service_info.clone()) {
            Ok(()) => true,
            Err(e) => {
                debug!("mdns register failed (will retry): {e}");
                false
            }
        }
    }

    /// Withdraw the advertisement (the mDNS goodbye).
    pub fn unregister(&self) {
        let _ = self.daemon.unregister(&self.fullname);
    }

    /// Stop the daemon: closes the browse stream and every socket.
    pub fn shutdown(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(daemon_ack) = self.daemon.shutdown() {
            *self.shutdown_ack.lock().unwrap_or_else(|e| e.into_inner()) = Some(daemon_ack);
        }
        // Keep the browse pump draining terminal dependency events. The
        // supervisor stops it only after observing DaemonStatus::Shutdown.
        let _ = self.shutdown_request.send(true);
    }

    /// Transfer the backend supervisor to the driver owner so the browse pump
    /// and delivery owner can be joined at shutdown. Independent backend users
    /// may retain it; [`shutdown`](Self::shutdown) requests stop and aborts the
    /// delivery owner if it is waiting on a full downstream queue.
    pub fn take_task(&mut self) -> Option<JoinHandle<()>> {
        self.pump.take()
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn pump(
    browse_rx: mdns_sd::Receiver<ServiceEvent>,
    forward_tx: mpsc::Sender<DiscoveryEvent>,
    mut progress_rx: mpsc::Receiver<()>,
    mut stop: watch::Receiver<bool>,
    limits: crate::mdns::discovery::DiscoveryLimits,
) {
    let coalescer = DiscoveryEventCoalescer::with_limits(limits);
    loop {
        if !flush_pending(&coalescer, &forward_tx) {
            break;
        }
        tokio::select! {
            event = browse_rx.recv_async() => {
                let Ok(event) = event else { break };
                match event {
                    ServiceEvent::ServiceResolved(resolved) => {
                        admit_resolved(&coalescer, &forward_tx, *resolved);
                    }
                    ServiceEvent::ServiceRemoved(_ty, fullname) => {
                        admit_removed(&coalescer, &forward_tx, fullname);
                    }
                    _ => {}
                }
            }
            progress = progress_rx.recv() => {
                if progress.is_none() {
                    break;
                }
            }
            changed = stop.changed() => {
                let _ = changed;
                break;
            }
        }
    }
    coalescer.shutdown();
}

struct ForwarderAbortGuard {
    pump: AbortHandle,
    forwarder: AbortHandle,
}

async fn supervise_shutdown(
    mut request: watch::Receiver<bool>,
    shutdown_ack: Arc<Mutex<Option<mdns_sd::Receiver<mdns_sd::DaemonStatus>>>>,
    stop: watch::Sender<bool>,
    pump: JoinHandle<()>,
    forwarder: JoinHandle<()>,
) {
    let _children_guard = ForwarderAbortGuard {
        pump: pump.abort_handle(),
        forwarder: forwarder.abort_handle(),
    };
    let requested = request.changed().await.is_ok() && *request.borrow();
    let acknowledged = if requested {
        let daemon_ack = shutdown_ack
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        match daemon_ack {
            Some(daemon_ack) => shutdown_acknowledged(daemon_ack.recv_async().await.ok()),
            None => false,
        }
    } else {
        false
    };
    stop_and_join_children(stop, acknowledged, pump, forwarder).await;
}

fn shutdown_acknowledged(status: Option<mdns_sd::DaemonStatus>) -> bool {
    matches!(status, Some(mdns_sd::DaemonStatus::Shutdown))
}

impl Drop for ForwarderAbortGuard {
    fn drop(&mut self) {
        self.pump.abort();
        self.forwarder.abort();
    }
}

async fn stop_and_join_children(
    stop: watch::Sender<bool>,
    graceful: bool,
    pump: JoinHandle<()>,
    forwarder: JoinHandle<()>,
) {
    let pump_abort = pump.abort_handle();
    let forwarder_abort = forwarder.abort_handle();
    let _ = stop.send(true);
    if !graceful {
        pump_abort.abort();
        forwarder_abort.abort();
    }
    // Each handle is consumed exactly once. On the graceful path this joins
    // after the daemon acknowledgement; on every other path it observes the
    // abort result before the supervisor returns.
    let _ = pump.await;
    let _ = forwarder.await;
}

fn admit_resolved(
    coalescer: &DiscoveryEventCoalescer,
    forward_tx: &mpsc::Sender<DiscoveryEvent>,
    resolved: mdns_sd::ResolvedService,
) {
    if !resolved.is_valid() {
        return;
    }
    let fullname = resolved.get_fullname();
    if fullname.len() > MAX_DNS_NAME_BYTES {
        return;
    }
    let properties = resolved.get_properties();
    if properties.len() > MAX_TXT_ENTRIES
        || properties.iter().any(|property| {
            property.key().len() > MAX_TXT_KEY_BYTES
                || property.val_str().len() > MAX_TXT_VALUE_BYTES
        })
        || properties
            .iter()
            .map(|property| property.key().len() + property.val_str().len())
            .sum::<usize>()
            > MAX_TXT_BYTES
    {
        return;
    }
    let address_count = resolved
        .get_addresses()
        .iter()
        .filter(|address| matches!(**address, mdns_sd::ScopedIp::V4(_)))
        .count();
    if address_count == 0 || address_count > MAX_RESOLVED_ADDRESSES {
        return;
    }
    let Some(generation) = admit_key(coalescer, fullname) else {
        return;
    };
    // The exact key has been admitted; only now copy the payload fields.
    let txt = properties
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect();
    let addresses = resolved.get_addresses_v4();
    let event = DiscoveryEvent::Resolved {
        generation,
        key: fullname.to_string(),
        addrs: addresses.into_iter().map(IpAddr::V4).collect(),
        port: resolved.get_port(),
        txt,
    };
    if !coalescer.publish(fullname, generation, event) {
        let _ = coalescer.cancel(fullname, generation);
    }
    let _ = flush_pending(coalescer, forward_tx);
}

fn admit_removed(
    coalescer: &DiscoveryEventCoalescer,
    forward_tx: &mpsc::Sender<DiscoveryEvent>,
    fullname: String,
) {
    if fullname.len() > MAX_DNS_NAME_BYTES {
        return;
    }
    let Some(generation) = coalescer.admit_existing(&fullname) else {
        debug!(
            key = %fullname,
            "mdns stale removal refused without an active exact-key generation"
        );
        return;
    };
    if !coalescer.publish(
        &fullname,
        generation,
        DiscoveryEvent::Removed {
            generation,
            key: fullname.clone(),
        },
    ) {
        let _ = coalescer.cancel(&fullname, generation);
    }
    let _ = flush_pending(coalescer, forward_tx);
}

fn admit_key(coalescer: &DiscoveryEventCoalescer, key: &str) -> Option<u64> {
    match coalescer.admit(key) {
        DiscoveryEventAdmission::Started { generation } => Some(generation),
        DiscoveryEventAdmission::Coalesced { generation } => {
            trace!(key = %key, generation, "mdns discovery event coalesced");
            Some(generation)
        }
        DiscoveryEventAdmission::Refused => {
            debug!(key = %key, "mdns discovery event refused at bounded key cap");
            None
        }
    }
}

fn flush_pending(
    coalescer: &DiscoveryEventCoalescer,
    forward_tx: &mpsc::Sender<DiscoveryEvent>,
) -> bool {
    loop {
        let Some((key, generation, event)) = coalescer.take_ready() else {
            return true;
        };
        match forward_tx.try_send(event) {
            Ok(()) => {
                let _ = coalescer.finish(&key, generation);
            }
            Err(mpsc::error::TrySendError::Full(event)) => {
                let _ = coalescer.restore(&key, generation, event);
                trace!(key = %key, "mdns discovery delivery queue full; retaining latest state");
                return true;
            }
            Err(mpsc::error::TrySendError::Closed(event)) => {
                drop(event);
                let _ = coalescer.cancel(&key, generation);
                return false;
            }
        }
    }
}

/// The only task allowed to await downstream capacity. The dependency-facing
/// browse pump remains nonblocking and continues draining mdns-sd into its
/// bounded forwarding queue/coalescer.
async fn deliver(
    mut input: mpsc::Receiver<DiscoveryEvent>,
    output: mpsc::Sender<DiscoveryEvent>,
    progress: mpsc::Sender<()>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let event = tokio::select! {
            event = input.recv() => event,
            changed = stop.changed() => {
                let _ = changed;
                return;
            }
        };
        let Some(event) = event else { return };
        let permit = tokio::select! {
            permit = output.reserve() => permit,
            changed = stop.changed() => {
                let _ = changed;
                return;
            }
        };
        let Ok(permit) = permit else { return };
        permit.send(event);
        let _ = progress.try_send(());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct Terminal(Arc<AtomicUsize>);

    impl Drop for Terminal {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn terminal_child(
        ready: tokio::sync::oneshot::Sender<()>,
        terminals: Arc<AtomicUsize>,
        mut stop: watch::Receiver<bool>,
    ) {
        let _terminal = Terminal(terminals);
        let _ = ready.send(());
        let _ = stop.changed().await;
    }

    async fn run_closed_request_cleanup() -> usize {
        let terminals = Arc::new(AtomicUsize::new(0));
        let (stop, stop_rx) = watch::channel(false);
        let (pump_ready, pump_ready_rx) = tokio::sync::oneshot::channel();
        let (forwarder_ready, forwarder_ready_rx) = tokio::sync::oneshot::channel();
        let pump = tokio::spawn(terminal_child(
            pump_ready,
            terminals.clone(),
            stop_rx.clone(),
        ));
        let forwarder = tokio::spawn(terminal_child(forwarder_ready, terminals.clone(), stop_rx));
        pump_ready_rx.await.expect("pump started");
        forwarder_ready_rx.await.expect("forwarder started");

        let (request, request_rx) = watch::channel(false);
        drop(request);
        supervise_shutdown(
            request_rx,
            Arc::new(Mutex::new(None)),
            stop,
            pump,
            forwarder,
        )
        .await;
        terminals.load(Ordering::SeqCst)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn daemon_shutdown_ack_progresses_while_handoff_is_full() {
        let daemon = ServiceDaemon::new().expect("daemon");
        let browse = daemon.browse("_mesh._tcp.local.").expect("browse");
        let limits = crate::mdns::discovery::DiscoveryLimits {
            max_resolve_owners: 2,
            event_capacity: 3,
            max_event_epochs: 4,
        };
        let (forward_tx, _forward_rx) = mpsc::channel(limits.event_capacity);
        for index in 0..limits.event_capacity {
            forward_tx
                .try_send(DiscoveryEvent::Removed {
                    generation: 1,
                    key: format!("peer-{index}"),
                })
                .expect("fill bounded handoff");
        }
        let (_progress_tx, progress_rx) = mpsc::channel(1);
        let (stop_tx, stop_rx) = watch::channel(false);
        let pump = tokio::spawn(pump(browse, forward_tx, progress_rx, stop_rx, limits));

        let ack = daemon.shutdown().expect("shutdown request");
        assert!(matches!(
            ack.recv_async().await,
            Ok(mdns_sd::DaemonStatus::Shutdown)
        ));
        let _ = stop_tx.send(true);
        pump.await.expect("pump joins after acknowledged shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closed_request_without_ack_observes_both_child_terminals() {
        assert_eq!(run_closed_request_cleanup().await, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unexpected_ack_uses_fail_closed_child_join() {
        assert!(!shutdown_acknowledged(Some(mdns_sd::DaemonStatus::Running)));
        let terminals = Arc::new(AtomicUsize::new(0));
        let (stop, stop_rx) = watch::channel(false);
        let (pump_ready, pump_ready_rx) = tokio::sync::oneshot::channel();
        let (forwarder_ready, forwarder_ready_rx) = tokio::sync::oneshot::channel();
        let pump = tokio::spawn(terminal_child(
            pump_ready,
            terminals.clone(),
            stop_rx.clone(),
        ));
        let forwarder = tokio::spawn(terminal_child(forwarder_ready, terminals.clone(), stop_rx));
        pump_ready_rx.await.expect("pump started");
        forwarder_ready_rx.await.expect("forwarder started");

        stop_and_join_children(stop, false, pump, forwarder).await;
        assert_eq!(terminals.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn only_exact_shutdown_ack_allows_graceful_path() {
        assert!(shutdown_acknowledged(Some(mdns_sd::DaemonStatus::Shutdown)));
        assert!(!shutdown_acknowledged(Some(mdns_sd::DaemonStatus::Running)));
        assert!(!shutdown_acknowledged(None));
    }
}
