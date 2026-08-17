//! Adapter that connects an [`crate::engine::state::NetworkState`]
//! to one or more signaling drivers. The signaling crate emits its
//! own generic [`myownmesh_signaling::SignalingMessage`] type; every
//! inbound pump here hands that shape to the ingress boundary in
//! [`super::signaling_ingress`], which admits it and only then
//! produces the engine's `SignalingInbound`. Outbound, this module
//! still renders the engine's `SignalingOutbound` into each driver's
//! own type.
//!
//! **The pumps no longer parse, and no longer decide.** A pump builds
//! a [`CarrierObservation`] through its own [`CarrierAttach`] and
//! hands it back; the translation into a domain value is private to
//! the ingress module, and de-duplication belongs to
//! the [`SignalingRuntime`] behind the attach. So "admit, then parse"
//! is not a rule this module follows, it is the only sequence
//! available to it - and the carrier and the attach that observed each
//! message reach the engine instead of being forgotten at the
//! boundary.
//!
//! Entry points:
//!
//! - [`attach_signaling`] - the production path: reads the network's
//!   `SignalingConfig` and attaches the remote strategy (`"nostr"` /
//!   `"none"`) plus, when `mdns` is on (the default), the LAN mDNS
//!   driver. With both attached, a fan-out task clones each engine
//!   emission to every driver (the engine's outbound receiver is
//!   single-consumer) and the two attaches share one
//!   [`SignalingRuntime`], which is what lets it see that the two
//!   copies coming back are one emission.
//! - [`attach_nostr`] / [`attach_mdns`] - single-driver attaches for
//!   embedders that pick a transport directly.
//! - [`attach_local`] - an in-process
//!   [`myownmesh_signaling::local::LocalBroker`] (tests and
//!   single-process apps).

use std::sync::Arc;

use myownmesh_signaling::local::{LocalBroker, LocalInbound, LocalOutbound};
use myownmesh_signaling::mdns::{
    self as mdns_driver, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound,
};
use myownmesh_signaling::nostr::driver::{
    self as nostr_driver, NostrDriverConfig, NostrDriverHandle, NostrInbound, NostrOutbound,
};
use myownmesh_signaling::{InboundSink, OutboundSource, SignalingMessage};
use tracing::{trace, warn};

use crate::resource::{ResourceMailboxReceiver, ResourceMailboxSendError, ResourceMailboxSender};

use super::signaling_ingress::{
    outbound_signal, CarrierAttach, CarrierAttribution, CarrierObservation, SignalingCarrier,
    SignalingRuntime,
};
use super::state::{NetworkState, SignalingOutbound};

/// One driver's outbound side: the engine's admitted values, translated on the
/// driver's own pull.
///
/// # What this replaces, and why the thing it replaces was not enough
///
/// There used to be a second queue here. A pump on this side read the engine's
/// funded mailbox, built a driver-shaped message — a peer id, an offer id, a
/// copy of the SDP or candidate — and pushed that translation into a plain
/// unbounded `tokio::mpsc` inside a crate with no resource vocabulary. One
/// standing residual was acquired for "the queue" and held for as long as it
/// could hold anything.
///
/// That named the subsystem without bounding it. The translations are the
/// allocations, the queue's depth is how many of them exist at once, and a
/// single claim says nothing about that number however long it is held. The
/// review asks for every translated value to be admitted before it is queued,
/// and the honest way to satisfy that is the one the inbound side already took:
/// **do not queue it**. The engine's per-driver mailbox is already funded and
/// already admits each `SignalingOutbound` before retaining it; this pulls from
/// that mailbox and builds the driver's type at the moment the driver asks for
/// one. A translation now lives on the driver's own task for exactly as long as
/// the driver is using it, and never longer.
///
/// So there is no queue lease, because there is no queue.
struct TranslatedOutbound<T> {
    /// Something the caller wants published before it drains anything — the
    /// broker join announce. Yielded once and then forgotten.
    first: Option<T>,
    rx: ResourceMailboxReceiver<SignalingOutbound>,
    translate: Box<dyn Fn(&SignalingOutbound) -> T + Send>,
}

#[async_trait::async_trait]
impl<T: Send> OutboundSource<T> for TranslatedOutbound<T> {
    async fn recv(&mut self) -> Option<T> {
        if let Some(first) = self.first.take() {
            return Some(first);
        }
        let delivery = self.rx.recv().await?;
        // Read, not taken apart. The translation is a different type carrying
        // fields the engine never sent, so this was never a forward of the
        // delivered value: the delivery stays whole and is released at the end
        // of this call, still holding its own funding, while what it produced
        // goes to the driver that asked for it.
        Some((self.translate)(delivery.value()))
    }
}

/// The network's local-application scope, or nothing and a reason.
fn local_scope(
    state: &Arc<NetworkState>,
    driver: &str,
) -> Option<crate::resource::LocalApplicationResourceScope> {
    match state.local_application_resource_scope() {
        Ok(scope) => Some(scope),
        Err(error) => {
            warn!(
                network = %state.network_id,
                driver,
                %error,
                "signaling driver not attached: no local application resource scope"
            );
            None
        }
    }
}

/// The ingress runtime for one network, funded by that network's scope.
///
/// The scope is what bounds every record the runtime retains, so a runtime that
/// cannot get one is not built at all rather than built with an invented
/// capacity: there is no unfunded mode to fall back to.
fn signaling_runtime(state: &Arc<NetworkState>, driver: &str) -> Option<Arc<SignalingRuntime>> {
    Some(SignalingRuntime::new(
        state.signaling_inbound_tx.clone(),
        local_scope(state, driver)?,
    ))
}

/// Attach an existing [`NetworkState`] to a [`LocalBroker`] room.
/// Spawns two pump tasks (outbound engine → broker, inbound
/// broker → engine) that live until either side closes its
/// queue. Returns once both pumps are spawned.
pub fn attach_local(state: &Arc<NetworkState>, broker: &LocalBroker) {
    let room = myownmesh_signaling::nostr::handle::derive_room_handle(
        &resolve_app_id(),
        &state.network_id,
    );
    let device_id = state.identity.public_id().to_string();

    // Outbound: engine → broker. Claimed before anything else, so a second
    // attach costs nothing: only one consumer is allowed, and a no-op attach
    // must not join a room or acquire funding it will never use.
    let Some(outbound_rx) = state.take_signaling_outbound_rx() else {
        return;
    };
    // Inbound: broker → engine, through the same ingress boundary the network
    // carriers use. The in-process broker gets the identical typed treatment —
    // admission, provenance, one shared parse — because a local transport that
    // reached the engine by a shorter route would be a second ingress with its
    // own behaviour, and the deterministic suite runs on this one.
    //
    // Its own runtime, because a broker attach is the whole signaling picture
    // for the network it serves: there is no second carrier for it to share
    // de-duplication with. Built before the join, because the join announces:
    // a peer already in the room is told about us inside the call, and there
    // must be somewhere for its reply to land by then.
    let Some(runtime) = signaling_runtime(state, "local") else {
        return;
    };
    // Announce ourselves on join so peers learn we're here even if the engine
    // doesn't emit anything immediately — the source yields it before it drains
    // anything, which is where the pump used to push it.
    let device_id_for_out = device_id.clone();
    broker.join_with_sink(
        &room,
        &device_id,
        Box::new(TranslatedOutbound {
            first: Some(LocalOutbound::Announce {
                device_id: device_id_for_out.clone(),
            }),
            rx: outbound_rx,
            translate: Box::new(move |outbound| match outbound {
                SignalingOutbound::Announce => LocalOutbound::Announce {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Leave => LocalOutbound::Leave {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Offer { device_id: to, sdp } => LocalOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Offer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: new_short_id(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Answer { device_id: to, sdp } => LocalOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Answer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: String::new(),
                        sdp: sdp.clone(),
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    candidate,
                } => LocalOutbound::DirectedToPeer {
                    to: to.clone(),
                    msg: SignalingMessage::Candidate {
                        peer_id: device_id_for_out.clone(),
                        candidate: candidate.candidate.clone(),
                        sdp_mid: candidate.sdp_mid.clone(),
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment.clone(),
                    },
                },
            }),
        }),
        carrier_sink(SignalingRuntime::attach(&runtime, SignalingCarrier::Local)),
    );
}

/// The engine's admission, as the thing a driver hands each report to.
///
/// This is where finding 7's queue used to be. A driver pushed into an unbounded
/// channel, a pump on this side drained it, and the stretch in between was
/// unaccounted memory that an unauthenticated carrier filled at whatever rate it
/// liked. There is no channel and no pump now: the driver's own task carries the
/// value through admission and finds out immediately whether the engine kept it.
///
/// The `false` that stops a driver is the engine being gone — never local
/// pressure, which is a lossy moment a later report recovers from and not a
/// reason to tear down a relay.
fn carrier_sink<R>(attach: CarrierAttach) -> InboundSink<R>
where
    R: Into<CarrierReport> + Send + 'static,
{
    InboundSink::new(move |report: R| {
        let observed = observe(&attach, report.into());
        attach.deliver(observed)
    })
}

/// What a driver reported, in the one shape every driver reports it in.
///
/// The three carrier inbound enums are structurally identical and each is
/// private to its own driver, so this is where they meet. Kept deliberately
/// dumb: it names the three things a carrier can tell us and holds nothing
/// else, because everything downstream of it is the lane boundary's.
enum CarrierReport {
    Announced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Left {
        device_id: String,
        attribution: CarrierAttribution,
    },
    Directed {
        from: String,
        msg: SignalingMessage,
    },
}

impl From<LocalInbound> for CarrierReport {
    fn from(inbound: LocalInbound) -> Self {
        match inbound {
            LocalInbound::PeerAnnounced {
                device_id,
                attribution,
            } => Self::Announced {
                device_id,
                attribution,
            },
            LocalInbound::PeerLeft {
                device_id,
                attribution,
            } => Self::Left {
                device_id,
                attribution,
            },
            LocalInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

impl From<NostrInbound> for CarrierReport {
    fn from(inbound: NostrInbound) -> Self {
        match inbound {
            NostrInbound::PeerAnnounced {
                device_id,
                attribution,
            } => Self::Announced {
                device_id,
                attribution,
            },
            // A relay reported that the peer's signaling socket dropped, or the
            // peer published its own `leave`. Both arrive here as
            // `SenderClaimed`, because either way the device id is one a payload
            // carried and neither the relay nor the event author is
            // authenticated to that device.
            //
            // So this is reachability evidence and nothing more: it may update
            // availability, cancel speculative work, and prompt a look at the
            // connector, and it retires no session in any state. Teardown is
            // exact connector closure, the authenticated
            // `SessionControl::Depart` over the session itself, or the heartbeat.
            // This comment used to say the engine tore the peer down promptly on
            // it, which was true and is not — see `NostrInbound::PeerLeft`.
            NostrInbound::PeerLeft {
                device_id,
                attribution,
            } => Self::Left {
                device_id,
                attribution,
            },
            NostrInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

impl From<MdnsInbound> for CarrierReport {
    fn from(inbound: MdnsInbound) -> Self {
        match inbound {
            MdnsInbound::PeerAnnounced {
                device_id,
                attribution,
            } => Self::Announced {
                device_id,
                attribution,
            },
            MdnsInbound::PeerLeft {
                device_id,
                attribution,
            } => Self::Left {
                device_id,
                attribution,
            },
            MdnsInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

/// Admit one carrier report. The single entry to the ingress boundary, shared
/// by every pump so the carriers cannot drift in how they are admitted.
///
/// The attribution the driver reported is carried across unchanged: this
/// module's job is to hand it on, not to decide it, and the only thing that
/// could honestly decide it is the driver that saw the message arrive.
fn observe(attach: &CarrierAttach, report: CarrierReport) -> CarrierObservation {
    match report {
        CarrierReport::Announced {
            device_id,
            attribution,
        } => attach.presence(device_id, attribution),
        CarrierReport::Left {
            device_id,
            attribution,
        } => attach.withdrawal(device_id, attribution),
        CarrierReport::Directed { from, msg } => attach.directed(from, msg),
    }
}

fn resolve_app_id() -> String {
    std::env::var("MYOWNMESH_TRYSTERO_APP_ID")
        .unwrap_or_else(|_| crate::TRYSTERO_APP_ID.to_string())
}

fn new_short_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}

/// Attach the engine to the production Nostr signaling driver.
/// Returns the driver handle — drop or call `.stop()` to detach.
/// Prefer [`attach_signaling`] unless you specifically want Nostr
/// regardless of the network's configured strategy.
pub fn attach_nostr(state: &Arc<NetworkState>) -> Option<NostrDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let runtime = signaling_runtime(state, "nostr")?;
    attach_nostr_with(
        state,
        outbound_rx,
        SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr),
    )
}

/// [`attach_nostr`] with an explicit outbound receiver + carrier
/// attach, so [`attach_signaling`]'s fan-out can feed several drivers
/// from the one engine receiver and one runtime.
fn attach_nostr_with(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<NostrDriverHandle> {
    let cfg = state.config.read();
    let nostr_cfg = NostrDriverConfig {
        app_id: resolve_app_id(),
        network_id: cfg.network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        servers: cfg.signaling.servers.clone(),
        denylist: cfg.signaling.denylist.clone(),
        redundancy: cfg.signaling.redundancy as usize,
        public_fallback: cfg.signaling.public_fallback,
    };
    let redundancy = nostr_cfg.redundancy;
    drop(cfg);

    let room_handle = myownmesh_signaling::nostr::handle::derive_room_handle(
        &nostr_cfg.app_id,
        &nostr_cfg.network_id,
    );
    state.log_diag(
        crate::events::DiagLevel::Info,
        "signaling",
        format!(
            "online — listening for peers in room {}… ({} relays)",
            &room_handle[..room_handle.len().min(12)],
            redundancy,
        ),
    );

    let device_id = state.identity.public_id().to_string();

    // Outbound: engine SignalingOutbound → NostrOutbound, built when the driver
    // pulls. No explicit startup announce — the Nostr driver's `run_announcer`
    // fires immediately at t=0 and then follows the adaptive backoff schedule
    // (see `upstream.rs` item 7). A second announce from the bridge would just
    // publish a duplicate event (different timestamp → distinct sha256 id, so
    // receiver-side dedup wouldn't collapse it) — wasted relay bandwidth for no
    // benefit.
    let device_id_for_out = device_id.clone();
    let outbound: Box<dyn OutboundSource<NostrOutbound>> = Box::new(TranslatedOutbound {
        first: None,
        rx: outbound_rx,
        translate: Box::new(move |outbound| match outbound {
            SignalingOutbound::Announce => NostrOutbound::Announce,
            SignalingOutbound::Leave => NostrOutbound::Leave,
            SignalingOutbound::Offer { device_id: to, sdp } => NostrOutbound::DirectedToPeer {
                to: to.clone(),
                msg: SignalingMessage::Offer {
                    peer_id: device_id_for_out.clone(),
                    offer_id: new_short_id(),
                    sdp: sdp.clone(),
                },
            },
            SignalingOutbound::Answer { device_id: to, sdp } => NostrOutbound::DirectedToPeer {
                to: to.clone(),
                msg: SignalingMessage::Answer {
                    peer_id: device_id_for_out.clone(),
                    offer_id: String::new(),
                    sdp: sdp.clone(),
                },
            },
            SignalingOutbound::Candidate {
                device_id: to,
                candidate,
            } => NostrOutbound::DirectedToPeer {
                to: to.clone(),
                msg: SignalingMessage::Candidate {
                    peer_id: device_id_for_out.clone(),
                    candidate: candidate.candidate.clone(),
                    sdp_mid: candidate.sdp_mid.clone(),
                    sdp_mline_index: candidate.sdp_mline_index,
                    username_fragment: candidate.username_fragment.clone(),
                },
            },
        }),
    });

    // Inbound: NostrInbound → engine SignalingInbound on the driver's own task,
    // through this carrier's attach on the shared runtime.
    let handle = nostr_driver::start(nostr_cfg, outbound, carrier_sink(attach));
    // Hand the engine the force-reconnect signal so resume-from-sleep
    // (and any other recovery path) can make every relay redial at
    // once instead of waiting out a zombie socket. See
    // `wake::on_wake` and `NetworkState::request_relay_reconnect`.
    state.set_relay_reconnect(handle.reconnect_signal());
    // …and the relay-connected signal, so a network-change renegotiation can
    // wait for signaling to actually come back before it offers (see
    // `network_watch::on_network_change`).
    state.set_relay_connected_signal(handle.connected_signal());
    Some(handle)
}

/// Attach the engine to the LAN mDNS signaling driver. Returns the
/// driver handle — drop or call `.stop()` to withdraw the DNS-SD
/// advertisement and detach. `None` if another consumer already took
/// the engine's outbound receiver, or if the mDNS daemon / exchange
/// listener couldn't come up (no usable socket, no multicast).
/// Prefer [`attach_signaling`] unless you specifically want mDNS
/// regardless of the network's configured strategy.
pub fn attach_mdns(state: &Arc<NetworkState>) -> Option<MdnsDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let runtime = signaling_runtime(state, "mdns")?;
    attach_mdns_with(
        state,
        outbound_rx,
        SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns),
    )
}

/// [`attach_mdns`] with an explicit outbound receiver + carrier
/// attach — the fan-out building block. On driver-start failure the
/// receiver is dropped (a fan-out sender to it becomes a no-op) and
/// a warning names the network.
fn attach_mdns_with(
    state: &Arc<NetworkState>,
    outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<MdnsDriverHandle> {
    let mdns_cfg = MdnsDriverConfig {
        app_id: resolve_app_id(),
        network_id: state.config.read().network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        service_port: 0,
    };

    let device_id = state.identity.public_id().to_string();

    // Outbound: engine SignalingOutbound → MdnsOutbound, built when the driver
    // pulls. The driver's registration doubles as the announce, so Announce is
    // a cheap idempotent nudge.
    let outbound: Box<dyn OutboundSource<MdnsOutbound>> = Box::new(TranslatedOutbound {
        first: None,
        rx: outbound_rx,
        translate: Box::new(move |outbound| match outbound {
            SignalingOutbound::Announce => MdnsOutbound::Announce,
            SignalingOutbound::Leave => MdnsOutbound::Leave,
            SignalingOutbound::Offer { device_id: to, sdp } => MdnsOutbound::DirectedToPeer {
                to: to.clone(),
                msg: SignalingMessage::Offer {
                    peer_id: device_id.clone(),
                    offer_id: new_short_id(),
                    sdp: sdp.clone(),
                },
            },
            SignalingOutbound::Answer { device_id: to, sdp } => MdnsOutbound::DirectedToPeer {
                to: to.clone(),
                msg: SignalingMessage::Answer {
                    peer_id: device_id.clone(),
                    offer_id: String::new(),
                    sdp: sdp.clone(),
                },
            },
            SignalingOutbound::Candidate {
                device_id: to,
                candidate,
            } => MdnsOutbound::DirectedToPeer {
                to: to.clone(),
                msg: SignalingMessage::Candidate {
                    peer_id: device_id.clone(),
                    candidate: candidate.candidate.clone(),
                    sdp_mid: candidate.sdp_mid.clone(),
                    sdp_mline_index: candidate.sdp_mline_index,
                    username_fragment: candidate.username_fragment.clone(),
                },
            },
        }),
    });

    // The driver's setup is synchronously fallible (mDNS daemon, TCP listener),
    // unlike Nostr's lazy socket dials, so it starts here and a failure returns
    // before anything else is consumed. Reports in both directions ride the
    // driver's own task; there is no queue on either side.
    let handle = match mdns_driver::start(mdns_cfg, outbound, carrier_sink(attach)) {
        Ok(h) => h,
        Err(e) => {
            warn!(network = %state.network_id, "mdns signaling unavailable: {e}");
            return None;
        }
    };

    state.log_diag(
        crate::events::DiagLevel::Info,
        "signaling",
        "LAN signaling online — advertising on this network via mDNS".to_string(),
    );

    Some(handle)
}

/// Every signaling driver attached to one network, plus the fan-out
/// task feeding them. Stop-on-drop: the fan-out is aborted and each
/// driver handle's own `Drop` detaches it — so the registry tears
/// signaling down for a network by dropping this value, exactly as
/// it did with the bare Nostr handle before mDNS existed.
pub struct SignalingDrivers {
    nostr: Option<NostrDriverHandle>,
    mdns: Option<MdnsDriverHandle>,
    fanout: Option<tokio::task::JoinHandle<()>>,
}

impl SignalingDrivers {
    /// Which drivers are live — for logs/diagnostics.
    pub fn describe(&self) -> String {
        match (&self.nostr, &self.mdns) {
            (Some(_), Some(_)) => "nostr+mdns".into(),
            (Some(_), None) => "nostr".into(),
            (None, Some(_)) => "mdns".into(),
            (None, None) => "none".into(),
        }
    }
}

impl Drop for SignalingDrivers {
    fn drop(&mut self) {
        if let Some(fanout) = self.fanout.take() {
            fanout.abort();
        }
        // nostr / mdns handles stop via their own Drop impls.
    }
}

/// Attach the signaling driver(s) a network's `SignalingConfig`
/// selects — the production entry point used by the daemon:
///
/// - `strategy`: `""`/`"nostr"` → the Nostr relay driver; `"none"` →
///   no remote driver; anything else → **no remote driver, loudly**
///   (never a silent Nostr fallback).
/// - `mdns: true` (default) additionally attaches the LAN mDNS
///   driver.
///
/// With two drivers, a fan-out task clones each engine emission to
/// both (the engine's outbound receiver is single-consumer) and the
/// one [`SignalingRuntime`] behind both attaches is what lets it see
/// that the two copies coming back are one emission.
///
/// Returns `None` when the outbound receiver was already taken by an
/// earlier attach. A `Some` whose every driver failed (e.g. mdns-only
/// config in a multicast-less environment) still drains the engine's
/// outbound queue so it can't grow unboundedly — the network is
/// simply unreachable, and warnings say so.
pub fn attach_signaling(state: &Arc<NetworkState>) -> crate::Result<Option<SignalingDrivers>> {
    let (strategy, mdns_on) = {
        let cfg = state.config.read();
        (cfg.signaling.strategy.clone(), cfg.signaling.mdns)
    };
    let want_nostr = match strategy.as_str() {
        "" | "nostr" => true,
        "none" => false,
        other => {
            warn!(
                network = %state.network_id,
                strategy = %other,
                "unknown signaling strategy — attaching NO remote driver \
                 (no silent Nostr fallback); check the network's signaling config"
            );
            false
        }
    };

    let Some(outbound_rx) = state.take_signaling_outbound_rx() else {
        return Ok(None);
    };
    // One runtime for the network, one attach per carrier. Sharing it is what
    // makes cross-carrier de-duplication possible at all: two runtimes would
    // each see half the traffic and each swallow nothing.
    let runtime = SignalingRuntime::new(
        state.signaling_inbound_tx.clone(),
        state.local_application_resource_scope()?,
    );

    let drivers = match (want_nostr, mdns_on) {
        (true, true) => {
            let (nostr_tx, nostr_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let (mdns_tx, mdns_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let fanout = spawn_fanout(state.clone(), outbound_rx, vec![nostr_tx, mdns_tx]);
            let nostr = attach_nostr_with(
                state,
                nostr_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr),
            );
            let mdns = attach_mdns_with(
                state,
                mdns_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns),
            );
            SignalingDrivers {
                nostr,
                mdns,
                fanout: Some(fanout),
            }
        }
        (true, false) => SignalingDrivers {
            nostr: attach_nostr_with(
                state,
                outbound_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Nostr),
            ),
            mdns: None,
            fanout: None,
        },
        (false, true) => {
            let mdns = attach_mdns_with(
                state,
                outbound_rx,
                SignalingRuntime::attach(&runtime, SignalingCarrier::Mdns),
            );
            if mdns.is_none() {
                warn!(
                    network = %state.network_id,
                    "mdns-only signaling failed to start — this network has NO signaling \
                     and is invisible to peers until it is re-joined"
                );
            }
            SignalingDrivers {
                nostr: None,
                mdns,
                fanout: None,
            }
        }
        (false, false) => {
            warn!(
                network = %state.network_id,
                "signaling fully disabled (strategy off and mdns off) — \
                 this network is invisible to peers"
            );
            // Drain the engine's outbound queue so it can't grow
            // unboundedly against a receiver nobody holds.
            SignalingDrivers {
                nostr: None,
                mdns: None,
                fanout: Some(spawn_fanout(state.clone(), outbound_rx, Vec::new())),
            }
        }
    };
    Ok(Some(drivers))
}

/// Clone every engine emission to each driver's queue. A closed
/// driver queue is skipped silently (its driver failed or detached);
/// the task exits when the engine side closes. This is also the one
/// place every outbound signaling event passes exactly once, so the
/// per-network traffic accounting counts publishes here — per logical
/// event, not per driver copy.
fn spawn_fanout(
    state: Arc<NetworkState>,
    mut outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    driver_txs: Vec<ResourceMailboxSender<SignalingOutbound>>,
) -> tokio::task::JoinHandle<()> {
    // While stood-down (signed-evicted), announces are suppressed — but
    // not forever silenced: one probe per this interval still goes out, so
    // a device that gets RE-ADMITTED in place (a fresh signed grant, no
    // re-claim flow) isn't deaf to its own pardon. The probe costs one
    // handshake+deny per interval while still evicted; the moment the
    // members' verdict clears, that same probe is what revives the links.
    const EVICTED_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
    let mut last_evicted_probe: Option<std::time::Instant> = None;
    tokio::spawn(async move {
        while let Some(delivery) = outbound_rx.recv().await {
            // Read, never taken apart. Every driver copy below is separately
            // admitted through its own `ResourceMailboxSender`, so this pump
            // never owns a translated allocation of its own and has no reason
            // to hold the delivered value away from what funds it.
            let msg = delivery.value();
            // A stood-down engine stops advertising itself: an announce is
            // an invitation to dial us, and every member would answer it
            // with a denial. Directed signaling (offers/answers already in
            // flight) still passes — only the broadcast self-advertisement
            // is throttled, to the slow re-admit probe above.
            if matches!(msg, SignalingOutbound::Announce)
                && state.self_evicted.load(std::sync::atomic::Ordering::SeqCst)
            {
                let due = last_evicted_probe
                    .map(|at| at.elapsed() >= EVICTED_PROBE_INTERVAL)
                    .unwrap_or(true);
                if !due {
                    continue;
                }
                last_evicted_probe = Some(std::time::Instant::now());
            }
            state
                .traffic
                .record_signaling_tx(matches!(msg, SignalingOutbound::Announce));
            // The outbound half of the ingress boundary. Nothing routes on
            // it — every emission is transport control — but a dropped copy is
            // named by the signal kind it carried as well as its variant, and
            // the admission is exhaustive, so an emission that is not ephemeral
            // transport control cannot be added without deciding that here.
            let signal = outbound_signal(msg).name();
            for tx in &driver_txs {
                let kind = match msg {
                    SignalingOutbound::Announce => "announce",
                    SignalingOutbound::Leave => "leave",
                    SignalingOutbound::Offer { .. } => "offer",
                    SignalingOutbound::Answer { .. } => "answer",
                    SignalingOutbound::Candidate { .. } => "candidate",
                };
                match tx.send(msg.clone()) {
                    Ok(()) | Err(ResourceMailboxSendError::Closed(_)) => {}
                    Err(ResourceMailboxSendError::Pressure { error, .. }) => {
                        warn!(
                            kind,
                            signal,
                            ?error,
                            "signaling driver copy dropped under declared resource pressure"
                        );
                    }
                    Err(ResourceMailboxSendError::Claim { error, .. }) => {
                        warn!(kind, signal, %error, "unrepresentable signaling driver copy dropped");
                    }
                }
            }
        }
        trace!("signaling fan-out exiting");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::signaling_ingress::{self, EphemeralSignal};

    /// **Every carrier reaches the engine through the ingress boundary, and the
    /// engine can still tell which one it was and what the report was worth.**
    ///
    /// The three drivers report the same three things in three private enums;
    /// this is the control that says all nine paths converge on one admission
    /// and keep their provenance. Asserted per carrier rather than once, because
    /// "the field exists" is not the property — "the three are distinguishable
    /// at the far end" is.
    ///
    /// The attribution half is the discriminating part: it is the one thing this
    /// module must carry across without deciding, and a pump that dropped it
    /// would silently turn a payload's claim into a carrier's observation.
    #[test]
    fn every_carrier_report_is_admitted_with_its_provenance_and_attribution() {
        for carrier in [
            SignalingCarrier::Local,
            SignalingCarrier::Nostr,
            SignalingCarrier::Mdns,
        ] {
            let (runtime, _rx) = signaling_ingress::tests::runtime_with_rx();
            let attach = SignalingRuntime::attach(&runtime, carrier);
            let every_report = [
                (
                    CarrierReport::Announced {
                        device_id: "peer-a".into(),
                        attribution: CarrierAttribution::CarrierObserved,
                    },
                    EphemeralSignal::Presence,
                    CarrierAttribution::CarrierObserved,
                ),
                (
                    CarrierReport::Left {
                        device_id: "peer-a".into(),
                        attribution: CarrierAttribution::SenderClaimed,
                    },
                    EphemeralSignal::Withdrawal,
                    CarrierAttribution::SenderClaimed,
                ),
                (
                    CarrierReport::Directed {
                        from: "peer-a".into(),
                        msg: SignalingMessage::Offer {
                            peer_id: "peer-a".into(),
                            offer_id: "offer-1".into(),
                            sdp: "sdp-1".into(),
                        },
                    },
                    EphemeralSignal::ConnectIntent,
                    CarrierAttribution::SenderClaimed,
                ),
            ];
            for (report, signal, attribution) in every_report {
                let admitted = observe(&attach, report).into_ingress();
                assert_eq!(admitted.carrier(), carrier);
                assert_eq!(admitted.signal(), signal);
                assert_eq!(
                    admitted.attribution(),
                    attribution,
                    "the driver decides what its report was worth; the bridge \
                     carries it across"
                );
            }
        }
    }
}
