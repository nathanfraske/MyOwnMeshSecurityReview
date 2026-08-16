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
//! the ingress module, and de-duplication and availability belong to
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
use myownmesh_signaling::SignalingMessage;
use tokio::sync::mpsc;
use tracing::{trace, warn};

use crate::resource::{ResourceMailboxReceiver, ResourceMailboxSendError, ResourceMailboxSender};

use super::signaling_ingress::{
    outbound_signal, CarrierAttach, CarrierAttribution, CarrierObservation, SignalingCarrier,
    SignalingRuntime,
};
use super::state::{NetworkState, SignalingOutbound};

/// What one signaling driver's outbound queue costs the engine, as a single
/// standing residual rather than a charge per message.
///
/// **This is deliberately broader than exact accounting, and saying so is part
/// of it.** An outbound pump does not forward the engine's own value — it
/// translates it, building a driver-shaped message with a peer id, an offer id
/// and a copy of the SDP or candidate the engine handed over. Those are new
/// allocations that live in a plain `tokio::mpsc` queue inside a crate with no
/// resource vocabulary, for as long as the driver takes to drain them.
///
/// The two honest ways to cover that were to make the driver queues themselves
/// admitted — which means teaching `myownmesh-signaling` about the accountant,
/// in a crate that is also used standalone — or to name the subsystem once and
/// hold that name for as long as the queues can hold anything. This is the
/// second. It does not claim to measure the traffic; it claims that the engine
/// has acknowledged the queue exists and has kept something live for exactly as
/// long as it does. What it replaces claimed neither.
const SIGNALING_DRIVER_QUEUE_CLAIM: crate::resource::ResourceClaim =
    crate::resource::ResourceClaim::single(
        crate::resource::ResourceClass::OpaqueDependencyResidual,
        1,
    );

/// Acquire the residual for one driver's outbound queue, before anything is
/// translated into it.
///
/// `None` is a refusal, and the caller must not attach — a driver started
/// without this would translate into a queue nothing accounts for, which is
/// the state this exists to end.
///
/// The lease is returned by value and travels by value: the driver stores it
/// inline in its own state, so nothing is allocated to carry it. That is not
/// incidental tidiness. The obvious alternative, an erased
/// `Box<dyn Send + Sync>`, allocates something the engine would then have to
/// account for, and `Box` drops its payload before it frees its allocation —
/// so a boxed lease would release this very claim and only then deallocate the
/// box that claim was covering. A false release, produced by the mechanism
/// meant to prevent one.
fn acquire_driver_queue_owner(
    state: &Arc<NetworkState>,
    driver: &str,
) -> Option<crate::resource::ResourceLease> {
    let scope = match state.local_application_resource_scope() {
        Ok(scope) => scope,
        Err(error) => {
            warn!(
                network = %state.network_id,
                driver,
                %error,
                "signaling driver not attached: no local application resource scope"
            );
            return None;
        }
    };
    match scope.acquire(SIGNALING_DRIVER_QUEUE_CLAIM) {
        Ok(lease) => Some(lease),
        Err(error) => {
            warn!(
                network = %state.network_id,
                driver,
                ?error,
                "signaling driver not attached: its outbound queue was not funded"
            );
            None
        }
    }
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
    let Some(mut outbound_rx) = state.take_signaling_outbound_rx() else {
        return;
    };
    // Then the queue owner, before the room exists — joining creates the queue
    // this pays for, and the first thing the pump does is push an announce
    // into it.
    let Some(queue_owner) = acquire_driver_queue_owner(state, "local") else {
        return;
    };
    let (out_tx, mut in_rx) = broker.join_with_queue_owner(&room, &device_id, queue_owner);

    let device_id_for_out = device_id.clone();
    tokio::spawn(async move {
        // Announce ourselves on join so peers learn we're here
        // even if the engine doesn't emit anything immediately.
        let _ = out_tx.send(LocalOutbound::Announce {
            device_id: device_id_for_out.clone(),
        });
        while let Some(delivery) = outbound_rx.recv().await {
            // Read, not taken apart. What goes into the broker's queue is a
            // *translation* — a different type, with a peer id and an offer id
            // the engine never sent — so this was never a forward of the
            // delivered value in the first place. The copies it makes are what
            // the queue owner acquired above stands for; the delivery itself
            // stays whole and is released at the end of the iteration, still
            // holding its own funding.
            let msg = match delivery.value() {
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
            };
            if out_tx.send(msg).is_err() {
                break;
            }
        }
        trace!("outbound pump exiting");
    });

    // Inbound: broker → engine, through the same ingress boundary the network
    // carriers use. The in-process broker gets the identical typed treatment —
    // admission, provenance, one shared parse — because a local transport that
    // reached the engine by a shorter route would be a second ingress with its
    // own behaviour, and the deterministic suite runs on this one.
    //
    // Its own runtime, because a broker attach is the whole signaling picture
    // for the network it serves: there is no second carrier for it to share
    // availability or de-duplication with.
    let runtime = SignalingRuntime::new(state.signaling_inbound_tx.clone());
    let attach = SignalingRuntime::attach(&runtime, SignalingCarrier::Local);
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let observed = observe(&attach, inbound.into());
            if !attach.deliver(observed) {
                break;
            }
        }
        trace!("inbound pump exiting");
    });
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
    let runtime = SignalingRuntime::new(state.signaling_inbound_tx.clone());
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
    mut outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<NostrDriverHandle> {
    // First, and before the channels exist: the pump below translates into a
    // queue this pays for, and a refusal here has to stop the attach rather
    // than proceed unfunded.
    let queue_owner = acquire_driver_queue_owner(state, "nostr")?;
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

    let (out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<NostrInbound>();

    let device_id = state.identity.public_id().to_string();

    // Outbound pump: engine SignalingOutbound → NostrOutbound.
    let device_id_for_out = device_id.clone();
    tokio::spawn(async move {
        // No explicit startup announce here — the Nostr driver's
        // `run_announcer` fires immediately at t=0 and then follows
        // the adaptive backoff schedule (see
        // `upstream.rs` item 7). A second announce from the bridge
        // would just publish a duplicate event (different timestamp
        // → distinct sha256 id, so receiver-side dedup wouldn't
        // collapse it) — wasted relay bandwidth for no benefit.
        while let Some(delivery) = outbound_rx.recv().await {
            // Read, not taken apart — see the local pump for why a translation
            // was never a forward, and what the driver's queue owner covers.
            let translated = match delivery.value() {
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
            };
            if out_tx.send(translated).is_err() {
                break;
            }
        }
        trace!("nostr outbound pump exiting");
    });

    // Inbound pump: NostrInbound → engine SignalingInbound, through this
    // carrier's attach on the shared runtime.
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let observed = observe(&attach, inbound.into());
            if !attach.deliver(observed) {
                break;
            }
        }
        trace!("nostr inbound pump exiting");
    });

    let handle = nostr_driver::start_with_queue_owner(nostr_cfg, out_rx, in_tx, queue_owner);
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
    let runtime = SignalingRuntime::new(state.signaling_inbound_tx.clone());
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
    mut outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    attach: CarrierAttach,
) -> Option<MdnsDriverHandle> {
    // First, and before the channels exist — same reason as the Nostr path.
    let queue_owner = acquire_driver_queue_owner(state, "mdns")?;
    let mdns_cfg = MdnsDriverConfig {
        app_id: resolve_app_id(),
        network_id: state.config.read().network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        service_port: 0,
    };

    let (out_tx, out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<MdnsInbound>();

    // Start the driver before consuming anything else — its setup is
    // synchronously fallible (mDNS daemon, TCP listener), unlike
    // Nostr's lazy socket dials.
    let handle = match mdns_driver::start_with_queue_owner(mdns_cfg, out_rx, in_tx, queue_owner) {
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

    let device_id = state.identity.public_id().to_string();

    // Outbound pump: engine SignalingOutbound → MdnsOutbound. The
    // driver's registration doubles as the announce, so Announce is
    // a cheap idempotent nudge.
    tokio::spawn(async move {
        while let Some(delivery) = outbound_rx.recv().await {
            // Read, not taken apart — see the local pump for why a translation
            // was never a forward, and what the driver's queue owner covers.
            let translated = match delivery.value() {
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
            };
            if out_tx.send(translated).is_err() {
                break;
            }
        }
        trace!("mdns outbound pump exiting");
    });

    // Inbound pump: MdnsInbound → engine, through this carrier's attach.
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let observed = observe(&attach, inbound.into());
            if !attach.deliver(observed) {
                break;
            }
        }
        trace!("mdns inbound pump exiting");
    });

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
    // makes cross-carrier de-duplication and availability possible at all: two
    // runtimes would each see half the evidence.
    let runtime = SignalingRuntime::new(state.signaling_inbound_tx.clone());

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
    use crate::engine::signaling_ingress::{EphemeralIngress, EphemeralSignal};

    fn funded_runtime() -> (
        Arc<SignalingRuntime>,
        ResourceMailboxReceiver<EphemeralIngress>,
    ) {
        let grant = crate::resource::ResourceClaim::try_from_entries(
            crate::resource::ResourceClass::ALL.map(|dimension| (dimension, 1_000_000)),
        )
        .expect("test grant is representable");
        let provider = crate::resource::ResourceProviderPort::new(
            crate::resource::FiniteResourceProvider::new(grant),
        )
        .expect("test grant funds process bookkeeping");
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_local_application_provider(provider)
            .expect("isolated root accepts its provider");
        let (tx, rx) = crate::resource::resource_mailbox(
            root.issue_local_application_scope()
                .expect("test local-application scope"),
        )
        .expect("test mailbox");
        (SignalingRuntime::new(tx), rx)
    }

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
            let (runtime, _rx) = funded_runtime();
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
