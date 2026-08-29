//! The pure-Rust discovery backend: a per-driver `mdns-sd` [`ServiceDaemon`]
//! owning its own multicast socket set (SO_REUSEADDR/SO_REUSEPORT), which
//! also lets it coexist with a system avahi/Bonjour daemon. This is the
//! pre-seam behaviour, extracted verbatim.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace};

use super::{
    DiscoveryConfig, DiscoveryEvent, DISCOVERY_EVENT_CAPACITY, MAX_DNS_NAME_BYTES,
    MAX_RESOLVED_ADDRESSES, MAX_TXT_BYTES, MAX_TXT_ENTRIES, MAX_TXT_KEY_BYTES, MAX_TXT_VALUE_BYTES,
};
use crate::Error;

pub struct Discovery {
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
    fullname: String,
    pump: Option<JoinHandle<()>>,
    stopped: AtomicBool,
}

impl Discovery {
    /// Bring the daemon up, start browsing, and hand back the event stream.
    /// Browse starts before the first [`register`](Self::register) so we never
    /// miss a burst of resolves racing our own announce.
    pub fn start(cfg: &DiscoveryConfig) -> crate::Result<(Self, mpsc::Receiver<DiscoveryEvent>)> {
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

        let (tx, rx) = mpsc::channel(DISCOVERY_EVENT_CAPACITY);
        let pump = tokio::spawn(async move {
            pump(browse_rx, tx).await;
            trace!("mdns embedded browse pump exiting");
        });

        Ok((
            Discovery {
                daemon,
                service_info,
                fullname,
                pump: Some(pump),
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
        let _ = self.daemon.shutdown();
        if let Some(pump) = &self.pump {
            pump.abort();
        }
    }

    /// Transfer the backend pump to the driver owner so it can be joined at
    /// shutdown. Independent backend users retain it and it is aborted by
    /// [`shutdown`](Self::shutdown).
    pub fn take_task(&mut self) -> Option<JoinHandle<()>> {
        self.pump.take()
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn pump(browse_rx: mdns_sd::Receiver<ServiceEvent>, tx: mpsc::Sender<DiscoveryEvent>) {
    loop {
        let event = match browse_rx.recv_async().await {
            Ok(e) => e,
            // Channel closes when the daemon shuts down.
            Err(_) => return,
        };
        match event {
            ServiceEvent::ServiceResolved(resolved) => {
                if !resolved.is_valid() {
                    continue;
                }
                let fullname = resolved.get_fullname();
                if fullname.len() > MAX_DNS_NAME_BYTES {
                    continue;
                }
                // Reserve the bounded driver queue before copying any
                // attacker-controlled TXT/address data.
                let permit = match tx.reserve().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
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
                    continue;
                }
                let addresses = resolved.get_addresses_v4();
                if addresses.len() > MAX_RESOLVED_ADDRESSES {
                    continue;
                }
                let txt = resolved
                    .get_properties()
                    .iter()
                    .map(|p| (p.key().to_string(), p.val_str().to_string()))
                    .collect();
                permit.send(DiscoveryEvent::Resolved {
                    key: fullname.to_string(),
                    addrs: addresses.into_iter().map(IpAddr::V4).collect(),
                    port: resolved.get_port(),
                    txt,
                });
            }
            ServiceEvent::ServiceRemoved(_ty, fullname) => {
                if fullname.len() > MAX_DNS_NAME_BYTES {
                    continue;
                }
                let permit = match tx.reserve().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
                permit.send(DiscoveryEvent::Removed { key: fullname });
            }
            _ => continue,
        }
    }
}
