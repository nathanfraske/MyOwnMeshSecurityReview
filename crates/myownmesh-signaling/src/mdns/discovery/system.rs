//! The system discovery backend: registration + browsing through the
//! platform's own DNS-SD daemon via the stable `dnssd` C API — mDNSResponder
//! on Apple platforms (where the symbols live in libSystem), Avahi's
//! `libdns_sd` compat shim on Linux (where we link `dns_sd`).
//!
//! Why this exists: iOS 14+ blocks raw multicast/broadcast sockets unless the
//! app holds the Apple-granted `com.apple.developer.networking.multicast`
//! entitlement, which rules out the pure-Rust [`super::embedded`] backend
//! there. mDNSResponder performs the multicast on the app's behalf; talking to
//! it needs no entitlement — only the `NSBonjourServices` /
//! `NSLocalNetworkUsageDescription` Info.plist keys. Local claiming on an
//! iPhone rides this.
//!
//! ## Threading model
//!
//! Every `DNSServiceRef` is owned by **exactly one thread**, which polls its
//! socket fd and runs `DNSServiceProcessResult` (callbacks fire synchronously
//! inside that call, on that thread) until it's done or the backend shuts
//! down, then deallocates the ref. Commands (`unregister` / `shutdown`) only
//! flip atomics those threads observe on their next poll tick (≤500 ms).
//! Deallocating a registered ref is what sends the mDNS goodbye.
//!
//! Long-lived refs (the browse, the registration) each get a thread for the
//! driver's lifetime; per-instance resolve + address lookups are short-lived
//! threads that exit once the answer (or a 5 s deadline) arrives.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use super::{
    DiscoveryConfig, DiscoveryEvent, ResolveCompletion, ResolveHint, ResolveLease,
    ResolveOwnership, DISCOVERY_EVENT_CAPACITY, MAX_DNS_NAME_BYTES, MAX_RESOLVED_ADDRESSES,
    MAX_TXT_BYTES, MAX_TXT_ENTRIES, MAX_TXT_KEY_BYTES, MAX_TXT_VALUE_BYTES,
};
use crate::Error;

// ---- the dnssd C API (dns_sd.h) ----------------------------------------

type DNSServiceRef = *mut c_void;
type DNSServiceFlags = u32;
type DNSServiceErrorType = i32;

const NO_ERROR: DNSServiceErrorType = 0;
const FLAG_MORE_COMING: DNSServiceFlags = 0x1;
const FLAG_ADD: DNSServiceFlags = 0x2;
/// "Any interface" for registration/browse.
const INTERFACE_ANY: u32 = 0;

type RegisterReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type BrowseReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type ResolveReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
    *mut c_void,
);
type QueryRecordReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    u16,
    u16,
    u16,
    *const c_void,
    u32,
    *mut c_void,
);

/// DNS A record / IN class, for the address query.
const RR_TYPE_A: u16 = 1;
const RR_CLASS_IN: u16 = 1;

#[cfg_attr(not(target_vendor = "apple"), link(name = "dns_sd"))]
extern "C" {
    fn DNSServiceRegister(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port_network_order: u16,
        txt_len: u16,
        txt_record: *const c_void,
        callback: Option<RegisterReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceBrowse(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        regtype: *const c_char,
        domain: *const c_char,
        callback: Option<BrowseReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceResolve(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        callback: Option<ResolveReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    // NB: the address lookup rides DNSServiceQueryRecord (an A query) rather
    // than the more obvious DNSServiceGetAddrInfo — Avahi's Bonjour compat
    // shim never implemented the latter, and QueryRecord is supported by
    // both mDNSResponder and Avahi.
    fn DNSServiceQueryRecord(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        fullname: *const c_char,
        rr_type: u16,
        rr_class: u16,
        callback: Option<QueryRecordReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> i32;
    fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
    fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
}

/// A `DNSServiceRef` being handed to the thread that will own it.
struct SendRef(DNSServiceRef);
// SAFETY: the ref is created on one thread and then used exclusively by the
// receiving thread (poll + ProcessResult + Deallocate); dnssd refs have no
// thread affinity, only a no-concurrent-use rule, which single ownership
// guarantees.
unsafe impl Send for SendRef {}

// ---- TXT record codec ---------------------------------------------------

/// Encode DNS TXT rdata: length-prefixed `key=value` strings.
fn encode_txt(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in entries {
        let entry = format!("{k}={v}");
        let bytes = entry.as_bytes();
        // A TXT string caps at 255 bytes; our entries (version, room hash,
        // device pubkey) are all far below it. Oversize would be a programmer
        // error — truncate defensively rather than emit corrupt rdata.
        let len = bytes.len().min(255);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out
}

/// Parse DNS TXT rdata into a key→value map (a flag entry maps to "").
fn parse_txt(rdata: &[u8]) -> HashMap<String, String> {
    if rdata.len() > MAX_TXT_BYTES {
        return HashMap::new();
    }
    let mut out = HashMap::new();
    let mut p = 0usize;
    let mut entries = 0usize;
    while p < rdata.len() {
        entries += 1;
        if entries > MAX_TXT_ENTRIES {
            return HashMap::new();
        }
        let len = rdata[p] as usize;
        p += 1;
        let end = (p + len).min(rdata.len());
        if let Ok(s) = std::str::from_utf8(&rdata[p..end]) {
            match s.split_once('=') {
                Some((k, v)) if k.len() <= MAX_TXT_KEY_BYTES && v.len() <= MAX_TXT_VALUE_BYTES => {
                    out.insert(k.to_string(), v.to_string())
                }
                None if !s.is_empty() && s.len() <= MAX_TXT_KEY_BYTES => {
                    out.insert(s.to_string(), String::new())
                }
                None => None,
                Some(_) => None,
            };
        }
        p = end;
    }
    out
}

/// `_myownmesh._tcp.local.` → (`_myownmesh._tcp`, default domain). The dnssd
/// API takes the regtype and domain as separate arguments.
fn regtype_of(service_type: &str) -> String {
    service_type
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

// ---- the ref-processing loop --------------------------------------------

/// Poll `sd_ref`'s fd and run `DNSServiceProcessResult` until `until` says
/// stop, an error surfaces, or (if set) `deadline` passes. Callbacks fire
/// synchronously inside ProcessResult, on this thread.
///
/// SAFETY: caller guarantees exclusive ownership of `sd_ref` and that any
/// callback context outlives the loop.
unsafe fn process_ref(sd_ref: DNSServiceRef, until: impl Fn() -> bool, deadline: Option<Instant>) {
    let fd = DNSServiceRefSockFD(sd_ref);
    if fd < 0 {
        return;
    }
    loop {
        if until() {
            return;
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return;
            }
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = libc::poll(&mut pfd, 1, 500);
        if rc < 0 {
            return;
        }
        if rc == 0 {
            continue; // tick: re-check until()/deadline
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return;
        }
        if DNSServiceProcessResult(sd_ref) != NO_ERROR {
            return;
        }
    }
}

// ---- the backend ---------------------------------------------------------

struct Inner {
    regtype: CString,
    instance: CString,
    port: u16,
    txt: Vec<u8>,
    stopped: AtomicBool,
    /// The live registration's stop flag, if registered.
    registration: Mutex<Option<Arc<AtomicBool>>>,
    /// Exact service-instance resolve ownership. Duplicate per-interface Adds
    /// coalesce into one pending follow-up, and Removed/shutdown invalidates
    /// the active generation before any late result can be published.
    resolving: ResolveOwnership,
    tx: mpsc::Sender<DiscoveryEvent>,
    /// Every native worker is retained until shutdown joins it. This keeps
    /// callback contexts and resolve ownership alive only for their owner.
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

pub struct Discovery {
    inner: Arc<Inner>,
}

impl Discovery {
    /// Connect to the system daemon, start browsing, and hand back the event
    /// stream. Fails fast when the daemon is unreachable (no mDNSResponder /
    /// Avahi) — callers fall back to their other signaling transports.
    pub fn start(cfg: &DiscoveryConfig) -> crate::Result<(Self, mpsc::Receiver<DiscoveryEvent>)> {
        let regtype = CString::new(regtype_of(&cfg.service_type))
            .map_err(|e| Error::Other(format!("service type: {e}")))?;
        let instance = CString::new(cfg.instance.as_str())
            .map_err(|e| Error::Other(format!("instance name: {e}")))?;

        let (tx, rx) = mpsc::channel(DISCOVERY_EVENT_CAPACITY);
        let inner = Arc::new(Inner {
            regtype,
            instance,
            port: cfg.port,
            txt: encode_txt(&cfg.txt),
            stopped: AtomicBool::new(false),
            registration: Mutex::new(None),
            resolving: ResolveOwnership::new(),
            tx,
            workers: Mutex::new(Vec::new()),
        });

        // Browse first (mirrors the embedded backend: never miss resolves
        // racing our own announce). Created here so a daemon-unreachable
        // error surfaces synchronously to the caller.
        let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
        let ctx = Arc::into_raw(inner.clone()) as *mut c_void;
        let err = unsafe {
            DNSServiceBrowse(
                &mut sd_ref,
                0,
                INTERFACE_ANY,
                inner.regtype.as_ptr(),
                std::ptr::null(),
                Some(browse_cb),
                ctx,
            )
        };
        if err != NO_ERROR {
            // Reclaim the context Arc we leaked for the callback.
            unsafe { drop(Arc::from_raw(ctx as *const Inner)) };
            return Err(Error::Other(format!(
                "system dns-sd browse failed (is the mDNS daemon running?): {err}"
            )));
        }

        let browse_inner = inner.clone();
        let browse_ref = SendRef(sd_ref);
        // The callback context crosses into the thread as a plain address;
        // it's the leaked Arc reclaimed at thread exit.
        let ctx_addr = ctx as usize;
        let browse_worker = match std::thread::Builder::new()
            .name("dnssd-browse".into())
            .spawn(move || {
                let browse_ref = browse_ref;
                unsafe {
                    process_ref(
                        browse_ref.0,
                        || browse_inner.stopped.load(Ordering::SeqCst),
                        None,
                    );
                    DNSServiceRefDeallocate(browse_ref.0);
                    // The browse callback's context Arc.
                    drop(Arc::from_raw(ctx_addr as *const Inner));
                }
                trace!("dnssd browse thread exiting");
            }) {
            Ok(worker) => worker,
            Err(e) => {
                unsafe {
                    DNSServiceRefDeallocate(sd_ref);
                    drop(Arc::from_raw(ctx as *const Inner));
                }
                return Err(Error::Other(format!("spawn dnssd browse thread: {e}")));
            }
        };
        inner.workers.lock().push(browse_worker);

        Ok((Discovery { inner }, rx))
    }

    /// Attempt (re-)registration — the announce. Idempotent while registered.
    /// `false` = the daemon refused synchronously; the caller's re-announce
    /// tick retries. Name conflicts are auto-renamed by the daemon.
    pub fn register(&self) -> bool {
        let mut slot = self.inner.registration.lock();
        if slot.is_some() {
            return true;
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            return false;
        }
        let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
        let err = unsafe {
            DNSServiceRegister(
                &mut sd_ref,
                0,
                INTERFACE_ANY,
                self.inner.instance.as_ptr(),
                self.inner.regtype.as_ptr(),
                std::ptr::null(), // default domain
                std::ptr::null(), // default host
                self.inner.port.to_be(),
                self.inner.txt.len() as u16,
                self.inner.txt.as_ptr() as *const c_void,
                Some(register_cb),
                std::ptr::null_mut(),
            )
        };
        if err != NO_ERROR {
            debug!("dnssd register failed (will retry): {err}");
            return false;
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            unsafe { DNSServiceRefDeallocate(sd_ref) };
            return false;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let global = self.inner.clone();
        let reg_ref = SendRef(sd_ref);
        let spawned = std::thread::Builder::new()
            .name("dnssd-register".into())
            .spawn(move || {
                let reg_ref = reg_ref;
                unsafe {
                    process_ref(
                        reg_ref.0,
                        || {
                            thread_stop.load(Ordering::SeqCst)
                                || global.stopped.load(Ordering::SeqCst)
                        },
                        None,
                    );
                    // Deallocating the registered ref sends the goodbye.
                    DNSServiceRefDeallocate(reg_ref.0);
                }
                trace!("dnssd register thread exiting");
            });
        match spawned {
            Ok(worker) => {
                let mut workers = self.inner.workers.lock();
                if self.inner.stopped.load(Ordering::Acquire) {
                    stop.store(true, Ordering::Release);
                    drop(workers);
                    let _ = worker.join();
                    return false;
                }
                *slot = Some(stop);
                workers.retain(|worker| !worker.is_finished());
                workers.push(worker);
                true
            }
            Err(e) => {
                warn!("spawn dnssd register thread: {e}");
                unsafe { DNSServiceRefDeallocate(sd_ref) };
                false
            }
        }
    }

    /// Withdraw the advertisement (the goodbye rides the ref deallocation).
    pub fn unregister(&self) {
        if let Some(stop) = self.inner.registration.lock().take() {
            stop.store(true, Ordering::SeqCst);
        }
    }

    /// Stop everything: the registration (goodbye), the browse, and any
    /// in-flight resolves, within one poll tick.
    pub fn shutdown(&self) {
        self.unregister();
        self.inner.stopped.store(true, Ordering::SeqCst);
        self.inner.resolving.shutdown();
        // Joining the browse worker first closes the only callback path that
        // can enqueue a new resolve worker. Drain in rounds so a callback
        // racing the first take cannot leave an unjoined worker behind.
        loop {
            let workers = std::mem::take(&mut *self.inner.workers.lock());
            if workers.is_empty() {
                break;
            }
            for worker in workers {
                let _ = worker.join();
            }
        }
    }

    /// The system backend owns native worker threads rather than a Tokio pump;
    /// keep the common driver ownership seam explicit.
    pub fn take_task(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        None
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ---- callbacks + the per-instance resolve pipeline -----------------------

unsafe extern "C" fn register_cb(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    error: DNSServiceErrorType,
    name: *const c_char,
    _regtype: *const c_char,
    _domain: *const c_char,
    _ctx: *mut c_void,
) {
    if error != NO_ERROR {
        warn!("dnssd registration error: {error}");
    } else if !name.is_null() {
        trace!(
            instance = %CStr::from_ptr(name).to_string_lossy(),
            "dnssd registration confirmed"
        );
    }
}

unsafe extern "C" fn browse_cb(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    service_name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    ctx: *mut c_void,
) {
    if error != NO_ERROR || service_name.is_null() || regtype.is_null() || domain.is_null() {
        return;
    }
    // Borrow the context Arc without consuming it (the browse thread owns the
    // strong count and reclaims it at exit).
    let inner = &*(ctx as *const Inner);
    let Some(name_bytes) = bounded_cstr(service_name, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Some(regtype_bytes) = bounded_cstr(regtype, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Some(domain_bytes) = bounded_cstr(domain, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Ok(_queue_slot) = inner.tx.try_reserve() else {
        return;
    };
    let Ok(name) = String::from_utf8(name_bytes.to_vec()) else {
        return;
    };

    if flags & FLAG_ADD != 0 {
        // Our own advertisement echoes back; wire::parse_advert drops it by
        // TXT peer id downstream, but skipping the resolve early saves a
        // thread + query per announce.
        if let Ok(ours) = inner.instance.to_str() {
            if name == ours {
                return;
            }
        }
        let lease = match inner.resolving.admit(name) {
            ResolveHint::Started(lease) => lease,
            ResolveHint::Coalesced => return,
            ResolveHint::Refused => {
                debug!("mdns resolve hint refused or shutdown");
                return;
            }
        };
        let name = lease.instance().to_owned();
        let (Ok(regtype), Ok(domain)) = (
            String::from_utf8(regtype_bytes.to_vec()),
            String::from_utf8(domain_bytes.to_vec()),
        ) else {
            let _ = lease.cancel();
            return;
        };
        let inner = {
            // A real clone for the resolve thread to hold.
            Arc::increment_strong_count(ctx as *const Inner);
            Arc::from_raw(ctx as *const Inner)
        };
        match std::thread::Builder::new()
            .name("dnssd-resolve".into())
            .spawn(move || run_resolve(inner, name, regtype, domain, interface_index, lease))
        {
            Ok(worker) => {
                let mut workers = (&*(ctx as *const Inner)).workers.lock();
                workers.retain(|worker| !worker.is_finished());
                workers.push(worker);
            }
            Err(_) => {
                warn!("dnssd resolve thread failed to spawn");
            }
        }
    } else {
        inner.resolving.cancel(&name);
        let _ = inner.tx.try_send(DiscoveryEvent::Removed { key: name });
    }
}

/// Borrow a NUL-terminated C string only after proving its bound. This keeps
/// callbacks from cloning attacker-controlled names before resolve ownership
/// and its bounded queue slot have been admitted.
unsafe fn bounded_cstr<'a>(ptr: *const c_char, max: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    for len in 0..=max {
        if *ptr.add(len) == 0 {
            return Some(std::slice::from_raw_parts(ptr.cast::<u8>(), len));
        }
    }
    None
}

/// One resolved SRV+TXT answer, filled by `resolve_cb`.
#[derive(Default)]
struct ResolveOut {
    done: bool,
    host: Option<String>,
    port: u16,
    txt: HashMap<String, String>,
    interface_index: u32,
}

unsafe extern "C" fn resolve_cb(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    _fullname: *const c_char,
    host_target: *const c_char,
    port_network_order: u16,
    txt_len: u16,
    txt_record: *const u8,
    ctx: *mut c_void,
) {
    let out = &mut *(ctx as *mut ResolveOut);
    out.done = true;
    if error != NO_ERROR || host_target.is_null() {
        return;
    }
    let Some(host_bytes) = bounded_cstr(host_target, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Ok(host) = String::from_utf8(host_bytes.to_vec()) else {
        return;
    };
    out.host = Some(host);
    out.port = u16::from_be(port_network_order);
    out.interface_index = interface_index;
    if !txt_record.is_null() && txt_len > 0 && txt_len as usize <= MAX_TXT_BYTES {
        out.txt = parse_txt(std::slice::from_raw_parts(txt_record, txt_len as usize));
    }
}

/// IPv4 addresses for a resolved host, filled by `addr_cb`.
#[derive(Default)]
struct AddrOut {
    done: bool,
    addrs: Vec<IpAddr>,
}

unsafe extern "C" fn addr_cb(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    _interface_index: u32,
    error: DNSServiceErrorType,
    _fullname: *const c_char,
    rr_type: u16,
    _rr_class: u16,
    rd_len: u16,
    rdata: *const c_void,
    _ttl: u32,
    ctx: *mut c_void,
) {
    let out = &mut *(ctx as *mut AddrOut);
    if error == NO_ERROR
        && flags & FLAG_ADD != 0
        && rr_type == RR_TYPE_A
        && rd_len == 4
        && !rdata.is_null()
    {
        let octets = std::slice::from_raw_parts(rdata as *const u8, 4);
        let ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
        if !out.addrs.contains(&ip) && out.addrs.len() < MAX_RESOLVED_ADDRESSES {
            out.addrs.push(ip);
        }
    }
    if flags & FLAG_MORE_COMING == 0 {
        out.done = true;
    }
}

/// How long a resolve or address query may take before we give up on the
/// instance (it re-resolves on its next announce).
const QUERY_DEADLINE: Duration = Duration::from_secs(5);

fn run_resolve(
    inner: Arc<Inner>,
    name: String,
    regtype: String,
    domain: String,
    interface_index: u32,
    mut lease: ResolveLease,
) {
    loop {
        if inner.stopped.load(Ordering::Acquire) {
            return;
        }
        let result = resolve_instance(&inner, &name, &regtype, &domain, interface_index);
        let completion = lease.complete_with(|| {
            if let Some((addrs, port, txt)) = result {
                let _ = inner.tx.try_send(DiscoveryEvent::Resolved {
                    key: name.clone(),
                    addrs,
                    port,
                    txt,
                });
            }
        });
        match completion {
            ResolveCompletion::Finished => return,
            ResolveCompletion::Followup(next) => lease = next,
        }
    }
}

fn resolve_instance(
    inner: &Arc<Inner>,
    name: &str,
    regtype: &str,
    domain: &str,
    interface_index: u32,
) -> Option<(Vec<IpAddr>, u16, HashMap<String, String>)> {
    let (Ok(c_name), Ok(c_regtype), Ok(c_domain)) = (
        CString::new(name),
        CString::new(regtype),
        CString::new(domain),
    ) else {
        return None;
    };

    // SRV + TXT.
    let mut out = ResolveOut::default();
    let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
    let err = unsafe {
        DNSServiceResolve(
            &mut sd_ref,
            0,
            interface_index,
            c_name.as_ptr(),
            c_regtype.as_ptr(),
            c_domain.as_ptr(),
            Some(resolve_cb),
            &mut out as *mut ResolveOut as *mut c_void,
        )
    };
    if err != NO_ERROR {
        debug!("dnssd resolve of {name} failed: {err}");
        return None;
    }
    unsafe {
        process_ref(
            sd_ref,
            || out.done || inner.stopped.load(Ordering::SeqCst),
            Some(Instant::now() + QUERY_DEADLINE),
        );
        DNSServiceRefDeallocate(sd_ref);
    }
    let host = out.host.clone()?;

    // Address lookup — an A query (v4 only, matching the embedded backend:
    // the exchange dials IPv4 addresses; parity keeps the driver identical).
    let c_host = CString::new(host).ok()?;
    let mut addrs = AddrOut::default();
    let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
    let err = unsafe {
        DNSServiceQueryRecord(
            &mut sd_ref,
            0,
            out.interface_index,
            c_host.as_ptr(),
            RR_TYPE_A,
            RR_CLASS_IN,
            Some(addr_cb),
            &mut addrs as *mut AddrOut as *mut c_void,
        )
    };
    if err != NO_ERROR {
        debug!("dnssd getaddrinfo for {name} failed: {err}");
        return None;
    }
    unsafe {
        process_ref(
            sd_ref,
            || addrs.done || inner.stopped.load(Ordering::SeqCst),
            Some(Instant::now() + QUERY_DEADLINE),
        );
        DNSServiceRefDeallocate(sd_ref);
    }

    Some((addrs.addrs, out.port, out.txt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_codec_round_trips() {
        let entries = vec![
            ("v".to_string(), "1".to_string()),
            ("room".to_string(), "a".repeat(64)),
            ("peer".to_string(), "b".repeat(52)),
        ];
        let rdata = encode_txt(&entries);
        let parsed = parse_txt(&rdata);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed["v"], "1");
        assert_eq!(parsed["room"], "a".repeat(64));
        assert_eq!(parsed["peer"], "b".repeat(52));

        // Flag entries (no '=') parse as empty values; garbage is skipped.
        let parsed = parse_txt(&[4, b'f', b'l', b'a', b'g']);
        assert_eq!(parsed["flag"], "");
        // Truncated length prefixes never panic.
        let parsed = parse_txt(&[200, b'x']);
        assert!(parsed.is_empty() || parsed.contains_key("x"));
    }

    #[test]
    fn regtype_strips_the_local_domain() {
        assert_eq!(regtype_of("_myownmesh._tcp.local."), "_myownmesh._tcp");
        assert_eq!(regtype_of("_myownmesh._tcp"), "_myownmesh._tcp");
    }

    /// End-to-end through the real system daemon: register an instance, browse
    /// it back, check the TXT survives. Needs a running mDNS daemon
    /// (mDNSResponder / avahi with the dns_sd compat lib), so it's ignored by
    /// default: `cargo test --features system-dnssd -- --ignored`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a running system mDNS daemon (mDNSResponder / avahi)"]
    async fn registers_and_browses_via_the_system_daemon() {
        let cfg = DiscoveryConfig {
            service_type: "_momtest._tcp.local.".into(),
            instance: format!("mom-selftest-{}", std::process::id()),
            port: 45454,
            txt: vec![
                ("v".into(), "1".into()),
                ("room".into(), "roomhash".into()),
                ("peer".into(), "peerpubkey".into()),
            ],
        };

        // A browser under a different instance name, so the advertiser's
        // own-echo skip doesn't apply.
        let browser_cfg = DiscoveryConfig {
            instance: "mom-selftest-browser".into(),
            ..cfg.clone()
        };
        let (_browser, mut events) = Discovery::start(&browser_cfg).expect("browser start");

        let (advertiser, _adv_events) = Discovery::start(&cfg).expect("advertiser start");
        assert!(advertiser.register(), "register should be accepted");

        // The browser should resolve the advertiser within a few seconds.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .expect("timed out waiting for the system daemon to resolve our instance");
            let ev = tokio::time::timeout(remaining, events.recv())
                .await
                .expect("timed out")
                .expect("event stream open");
            if let DiscoveryEvent::Resolved { key, port, txt, .. } = ev {
                if key == cfg.instance {
                    assert_eq!(port, 45454);
                    assert_eq!(txt.get("room").map(String::as_str), Some("roomhash"));
                    assert_eq!(txt.get("peer").map(String::as_str), Some("peerpubkey"));
                    break;
                }
            }
        }

        advertiser.shutdown();
    }
}
