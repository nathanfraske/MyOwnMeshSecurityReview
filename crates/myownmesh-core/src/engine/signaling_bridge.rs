//! Adapter that connects an [`crate::engine::state::NetworkState`]
//! to one or more signaling drivers. The signaling crate emits its
//! own generic [`myownmesh_signaling::SignalingMessage`] type; every
//! inbound pump here hands that shape to the lane boundary in
//! [`super::signaling_lane`], which classifies it and only then
//! produces the engine's `SignalingInbound`. Outbound, this module
//! still renders the engine's `SignalingOutbound` into each driver's
//! own type.
//!
//! **The pumps no longer parse.** A pump builds a
//! [`CarrierObservation`] naming its own carrier and hands it on; the
//! translation into a domain value is private to the lane module and
//! reachable only through that value. So "classify, then parse" is
//! not a rule this module follows, it is the only sequence available
//! to it — and the carrier that observed each message reaches the
//! engine instead of being forgotten at the boundary.
//!
//! Entry points:
//!
//! - [`attach_signaling`] — the production path: reads the network's
//!   `SignalingConfig` and attaches the remote strategy (`"nostr"` /
//!   `"none"`) plus, when `mdns` is on (the default), the LAN mDNS
//!   driver. With both attached, a fan-out task clones each engine
//!   emission to every driver (the engine's outbound receiver is
//!   single-consumer) and an [`InboundGate`] drops the cross-driver
//!   duplicate Offer/Answer/Candidate deliveries — applying the same
//!   remote description twice wedges WebRTC permanently, the exact
//!   failure the Nostr driver's per-event dedup guards against
//!   within one transport.
//! - [`attach_nostr`] / [`attach_mdns`] — single-driver attaches for
//!   embedders that pick a transport directly.
//! - [`attach_local`] — an in-process
//!   [`myownmesh_signaling::local::LocalBroker`] (tests and
//!   single-process apps).

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use myownmesh_signaling::local::{LocalBroker, LocalInbound, LocalOutbound};
use myownmesh_signaling::mdns::{
    self as mdns_driver, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound,
};
use myownmesh_signaling::nostr::driver::{
    self as nostr_driver, NostrDriverConfig, NostrDriverHandle, NostrInbound, NostrOutbound,
};
use myownmesh_signaling::SignalingMessage;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{trace, warn};

use crate::resource::{ResourceMailboxReceiver, ResourceMailboxSendError, ResourceMailboxSender};

use super::signaling_lane::{outbound_lane, CarrierObservation, LaneDelivery, SignalingCarrier};
use super::state::{NetworkState, SignalingInbound, SignalingOutbound};

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

    // Inbound: broker → engine, through the same lane boundary the network
    // carriers use. The in-process broker gets the identical typed treatment —
    // classification, provenance, one shared parse — because a local transport
    // that reached the engine by a shorter route would be a second ingress with
    // its own behaviour, and the deterministic suite runs on this one.
    //
    // What it does not get is the cross-driver [`InboundGate`]: that gate exists
    // because one engine emission fanned out to Nostr *and* mDNS arrives twice
    // with different envelopes, and a broker attach has no second transport for
    // that to happen across. De-duplicating here would silently swallow a
    // genuine repeat send instead.
    let inbound_tx = state.signaling_inbound_tx.clone();
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let observed = observe(SignalingCarrier::Local, inbound.into());
            if !deliver_inbound_lossy(&inbound_tx, observed.into_delivery()) {
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
    Announced { device_id: String },
    Left { device_id: String },
    Directed { from: String, msg: SignalingMessage },
}

impl From<LocalInbound> for CarrierReport {
    fn from(inbound: LocalInbound) -> Self {
        match inbound {
            LocalInbound::PeerAnnounced { device_id } => Self::Announced { device_id },
            LocalInbound::PeerLeft { device_id } => Self::Left { device_id },
            LocalInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

impl From<NostrInbound> for CarrierReport {
    fn from(inbound: NostrInbound) -> Self {
        match inbound {
            NostrInbound::PeerAnnounced { device_id } => Self::Announced { device_id },
            // An intelligent relay told us the peer's signaling socket dropped —
            // tear the peer down now rather than waiting for the heartbeat
            // timeout. Still only a carrier observation: it ends a session, not
            // a membership.
            NostrInbound::PeerLeft { device_id } => Self::Left { device_id },
            NostrInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

impl From<MdnsInbound> for CarrierReport {
    fn from(inbound: MdnsInbound) -> Self {
        match inbound {
            MdnsInbound::PeerAnnounced { device_id } => Self::Announced { device_id },
            MdnsInbound::PeerLeft { device_id } => Self::Left { device_id },
            MdnsInbound::Message { from, msg } => Self::Directed { from, msg },
        }
    }
}

/// Classify one carrier report. The single entry to the lane boundary, shared
/// by every pump so the carriers cannot drift in how they classify.
fn observe(carrier: SignalingCarrier, report: CarrierReport) -> CarrierObservation {
    match report {
        CarrierReport::Announced { device_id } => CarrierObservation::presence(carrier, device_id),
        CarrierReport::Left { device_id } => CarrierObservation::withdrawal(carrier, device_id),
        CarrierReport::Directed { from, msg } => CarrierObservation::directed(carrier, from, msg),
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

/// Window of the cross-driver dedup ring. Same order of magnitude as
/// the Nostr driver's per-event ring — comfortably covers the
/// busiest realistic mesh without unbounded growth.
const GATE_SEEN_CAPACITY: usize = 2048;

/// Engine-facing delivery gate shared by every driver pump attached
/// to one network. Announces and departures pass through untouched
/// (the engine is idempotent on those — repeats are its retry
/// pacing). Offer/Answer/Candidate are deduped **by content**: with
/// Nostr and mDNS attached concurrently, one engine emission fans
/// out to both transports and arrives twice at the peer, and each
/// driver stamps its own envelope (different Nostr event id,
/// different offer_id) — so only the payload identifies the
/// duplicate, and applying it twice via `set_remote_description`
/// wedges WebRTC permanently.
struct InboundGate {
    tx: ResourceMailboxSender<LaneDelivery>,
    seen: Mutex<VecDeque<u64>>,
}

impl InboundGate {
    fn new(tx: ResourceMailboxSender<LaneDelivery>) -> Arc<Self> {
        Arc::new(Self {
            tx,
            seen: Mutex::new(VecDeque::with_capacity(GATE_SEEN_CAPACITY)),
        })
    }

    /// Deliver to the engine unless it's a cross-driver duplicate.
    /// Returns `false` once the engine side is gone (pump exits).
    fn deliver(&self, msg: LaneDelivery) -> bool {
        let kind = msg.kind_name();
        if let Some(key) = dedup_key(&msg) {
            let mut seen = self.seen.lock();
            if seen.contains(&key) {
                trace!(kind = msg.kind_name(), "cross-driver duplicate dropped");
                return true;
            }
            return match self.tx.send(msg) {
                Ok(()) => {
                    if seen.len() >= GATE_SEEN_CAPACITY {
                        seen.pop_front();
                    }
                    seen.push_back(key);
                    true
                }
                Err(ResourceMailboxSendError::Closed(_)) => false,
                Err(ResourceMailboxSendError::Pressure { error, .. }) => {
                    warn!(
                        kind,
                        ?error,
                        "inbound signaling dropped under declared resource pressure"
                    );
                    true
                }
                Err(ResourceMailboxSendError::Claim { error, .. }) => {
                    warn!(kind, %error, "unrepresentable inbound signaling dropped");
                    true
                }
            };
        }
        deliver_inbound_lossy(&self.tx, msg)
    }
}

/// Signaling ingress is explicitly lossy under local resource pressure. A
/// closed mailbox stops its pump; a measured-but-unfunded or unrepresentable
/// value is dropped and the driver continues so a later bounded event can
/// recover the connection.
fn deliver_inbound_lossy(tx: &ResourceMailboxSender<LaneDelivery>, msg: LaneDelivery) -> bool {
    let kind = msg.kind_name();
    match tx.send(msg) {
        Ok(()) => true,
        Err(ResourceMailboxSendError::Closed(_)) => false,
        Err(ResourceMailboxSendError::Pressure { error, .. }) => {
            warn!(
                kind,
                ?error,
                "inbound signaling dropped under declared resource pressure"
            );
            true
        }
        Err(ResourceMailboxSendError::Claim { error, .. }) => {
            warn!(kind, %error, "unrepresentable inbound signaling dropped");
            true
        }
    }
}

/// Content key for the gate. `None` = never deduped.
///
/// **Keyed on the message content and deliberately not on the carrier.** The
/// duplicate this gate exists to catch is one engine emission that fanned out
/// to Nostr and mDNS and came back over both, so the two copies differ in
/// exactly the field a carrier-aware key would separate them by. Retained
/// provenance is for the engine to read, not for the gate to key on; the first
/// carrier to arrive is the one whose provenance is delivered.
fn dedup_key(msg: &LaneDelivery) -> Option<u64> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match msg.inbound() {
        SignalingInbound::Offer { device_id, sdp } => {
            (1u8, device_id, sdp).hash(&mut h);
        }
        SignalingInbound::Answer { device_id, sdp } => {
            (2u8, device_id, sdp).hash(&mut h);
        }
        SignalingInbound::Candidate {
            device_id,
            candidate,
        } => {
            (
                3u8,
                device_id,
                &candidate.candidate,
                &candidate.sdp_mid,
                &candidate.sdp_mline_index,
                &candidate.username_fragment,
            )
                .hash(&mut h);
        }
        SignalingInbound::PeerAnnounced { .. } | SignalingInbound::PeerLeft { .. } => return None,
    }
    Some(h.finish())
}

/// Attach the engine to the production Nostr signaling driver.
/// Returns the driver handle — drop or call `.stop()` to detach.
/// Prefer [`attach_signaling`] unless you specifically want Nostr
/// regardless of the network's configured strategy.
pub fn attach_nostr(state: &Arc<NetworkState>) -> Option<NostrDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let gate = InboundGate::new(state.signaling_inbound_tx.clone());
    attach_nostr_with(state, outbound_rx, gate)
}

/// [`attach_nostr`] with an explicit outbound receiver + delivery
/// gate, so [`attach_signaling`]'s fan-out can feed several drivers
/// from the one engine receiver.
fn attach_nostr_with(
    state: &Arc<NetworkState>,
    mut outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    gate: Arc<InboundGate>,
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

    // Inbound pump: NostrInbound → engine SignalingInbound, through
    // the shared gate (cross-driver dedup when mDNS is also attached).
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let observed = observe(SignalingCarrier::Nostr, inbound.into());
            if !gate.deliver(observed.into_delivery()) {
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
    let gate = InboundGate::new(state.signaling_inbound_tx.clone());
    attach_mdns_with(state, outbound_rx, gate)
}

/// [`attach_mdns`] with an explicit outbound receiver + delivery
/// gate — the fan-out building block. On driver-start failure the
/// receiver is dropped (a fan-out sender to it becomes a no-op) and
/// a warning names the network.
fn attach_mdns_with(
    state: &Arc<NetworkState>,
    mut outbound_rx: ResourceMailboxReceiver<SignalingOutbound>,
    gate: Arc<InboundGate>,
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

    // Inbound pump: MdnsInbound → engine, through the shared gate.
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let observed = observe(SignalingCarrier::Mdns, inbound.into());
            if !gate.deliver(observed.into_delivery()) {
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
/// shared [`InboundGate`] drops cross-driver duplicate deliveries.
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
    let gate = InboundGate::new(state.signaling_inbound_tx.clone());

    let drivers = match (want_nostr, mdns_on) {
        (true, true) => {
            let (nostr_tx, nostr_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let (mdns_tx, mdns_rx) =
                crate::resource::resource_mailbox(state.local_application_resource_scope()?)?;
            let fanout = spawn_fanout(state.clone(), outbound_rx, vec![nostr_tx, mdns_tx]);
            let nostr = attach_nostr_with(state, nostr_rx, gate.clone());
            let mdns = attach_mdns_with(state, mdns_rx, gate);
            SignalingDrivers {
                nostr,
                mdns,
                fanout: Some(fanout),
            }
        }
        (true, false) => SignalingDrivers {
            nostr: attach_nostr_with(state, outbound_rx, gate),
            mdns: None,
            fanout: None,
        },
        (false, true) => {
            let mdns = attach_mdns_with(state, outbound_rx, gate);
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
            // The outbound half of the lane boundary. Nothing routes on it yet
            // — every current emission is transport control — but a dropped
            // copy is named by the lane it was on as well as its kind, and the
            // classifier is exhaustive, so an emission that belongs on the
            // durable lane cannot be added without deciding that here.
            let lane = outbound_lane(msg).name();
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
                            lane,
                            ?error,
                            "signaling driver copy dropped under declared resource pressure"
                        );
                    }
                    Err(ResourceMailboxSendError::Claim { error, .. }) => {
                        warn!(kind, lane, %error, "unrepresentable signaling driver copy dropped");
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
    use crate::engine::signaling_lane::{SignalingEffect, SignalingLane};
    use std::time::{Duration, Instant};

    fn gate_with_rx() -> (
        Arc<InboundGate>,
        crate::resource::ResourceMailboxReceiver<LaneDelivery>,
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
        (InboundGate::new(tx), rx)
    }

    /// Everything below builds its input the way a pump does — a carrier
    /// report, classified, then parsed — rather than assembling a domain value
    /// directly. A control that skipped the boundary would be testing a path
    /// production no longer has.
    fn reported(carrier: SignalingCarrier, report: CarrierReport) -> LaneDelivery {
        observe(carrier, report).into_delivery()
    }

    fn offer_from(carrier: SignalingCarrier, from: &str, sdp: &str) -> LaneDelivery {
        reported(
            carrier,
            CarrierReport::Directed {
                from: from.into(),
                msg: SignalingMessage::Offer {
                    peer_id: from.into(),
                    offer_id: "offer-1".into(),
                    sdp: sdp.into(),
                },
            },
        )
    }

    fn offer(from: &str, sdp: &str) -> LaneDelivery {
        offer_from(SignalingCarrier::Nostr, from, sdp)
    }

    fn candidate_from(carrier: SignalingCarrier, from: &str, mid: Option<&str>) -> LaneDelivery {
        reported(
            carrier,
            CarrierReport::Directed {
                from: from.into(),
                msg: SignalingMessage::Candidate {
                    peer_id: from.into(),
                    candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                    sdp_mid: mid.map(str::to_string),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                },
            },
        )
    }

    /// Every carrier reaches the engine through the lane boundary, and the
    /// engine can tell which one it was.
    ///
    /// The three drivers report the same three things in three private enums;
    /// this is the control that says all nine paths converge on one
    /// classification and keep their provenance. Asserted per carrier rather
    /// than once, because "the field exists" is not the property — "the three
    /// are distinguishable at the far end" is.
    #[test]
    fn every_carrier_delivers_a_classified_and_attributed_value() {
        for carrier in [
            SignalingCarrier::Local,
            SignalingCarrier::Nostr,
            SignalingCarrier::Mdns,
        ] {
            let every_report = [
                CarrierReport::Announced {
                    device_id: "peer-a".into(),
                },
                CarrierReport::Left {
                    device_id: "peer-a".into(),
                },
                CarrierReport::Directed {
                    from: "peer-a".into(),
                    msg: SignalingMessage::Offer {
                        peer_id: "peer-a".into(),
                        offer_id: "offer-1".into(),
                        sdp: "sdp-1".into(),
                    },
                },
            ];
            for report in every_report {
                let delivered = reported(carrier, report);
                assert_eq!(delivered.carrier(), carrier);
                assert_eq!(delivered.lane(), SignalingLane::EphemeralTransport);
            }
        }
    }

    /// The cross-driver wedge case: the same offer content delivered
    /// once per transport must reach the engine exactly once —
    /// applying it twice via `set_remote_description` wedges WebRTC.
    ///
    /// Delivered over two *different* carriers, which is the situation the gate
    /// exists for and the one a carrier-aware dedup key would fail: the copies
    /// differ in provenance and in nothing else that matters.
    #[test]
    fn duplicate_offer_content_is_delivered_once() {
        let (gate, mut rx) = gate_with_rx();
        assert!(gate.deliver(offer_from(SignalingCarrier::Nostr, "peer-a", "sdp-1")));
        assert!(gate.deliver(offer_from(SignalingCarrier::Mdns, "peer-a", "sdp-1")));
        let first = rx.try_recv().expect("first delivery lands");
        assert_eq!(
            first.value().carrier(),
            SignalingCarrier::Nostr,
            "the carrier that got there first is the provenance the engine sees"
        );
        assert!(rx.try_recv().is_none(), "duplicate swallowed");
    }

    /// Distinct negotiations (different SDP — every ICE restart or
    /// renegotiation changes it) must all pass.
    #[test]
    fn distinct_offers_all_pass() {
        let (gate, mut rx) = gate_with_rx();
        assert!(gate.deliver(offer("peer-a", "sdp-1")));
        assert!(gate.deliver(offer("peer-a", "sdp-2")));
        assert!(gate.deliver(offer("peer-b", "sdp-1"))); // same sdp, other peer
        for _ in 0..3 {
            rx.try_recv().expect("each distinct offer delivered");
        }
    }

    /// A carrier may reorder, so the boundary must not care what order it sees.
    ///
    /// The candidates for an attempt arriving ahead of the offer they belong to
    /// is ordinary on a relay, and each one is still distinct content that has
    /// to reach the engine. Nothing here is deduped and nothing is held back
    /// waiting for a predecessor — the gate keys on content, not on sequence.
    #[test]
    fn out_of_order_arrivals_all_reach_the_engine() {
        let (gate, mut rx) = gate_with_rx();
        assert!(gate.deliver(candidate_from(SignalingCarrier::Mdns, "peer-a", Some("1"))));
        assert!(gate.deliver(candidate_from(SignalingCarrier::Mdns, "peer-a", Some("0"))));
        assert!(gate.deliver(offer_from(SignalingCarrier::Mdns, "peer-a", "sdp-1")));
        for expected in ["candidate", "candidate", "offer"] {
            let delivered = rx.try_recv().expect("every distinct arrival is delivered");
            assert_eq!(
                delivered.value().kind_name(),
                expected,
                "and in arrival order"
            );
        }
    }

    /// Announces and departures are the engine's retry pacing —
    /// repeats must never be swallowed.
    #[test]
    fn announces_and_leaves_are_never_deduped() {
        let (gate, mut rx) = gate_with_rx();
        for _ in 0..3 {
            assert!(gate.deliver(reported(
                SignalingCarrier::Nostr,
                CarrierReport::Announced {
                    device_id: "peer-a".into(),
                }
            )));
        }
        assert!(gate.deliver(reported(
            SignalingCarrier::Nostr,
            CarrierReport::Left {
                device_id: "peer-a".into(),
            }
        )));
        for _ in 0..4 {
            rx.try_recv().expect("every announce/leave delivered");
        }
    }

    /// Candidates dedup on their full content, not just the string.
    #[test]
    fn candidate_dedup_keys_on_full_content() {
        let (gate, mut rx) = gate_with_rx();
        let cand = |mid: Option<&str>| candidate_from(SignalingCarrier::Nostr, "peer-a", mid);
        assert!(gate.deliver(cand(Some("0"))));
        assert!(gate.deliver(cand(Some("0")))); // exact duplicate — dropped
        assert!(gate.deliver(cand(Some("1")))); // differing mid — passes
        assert!(rx.try_recv().is_some());
        assert!(rx.try_recv().is_some());
        assert!(rx.try_recv().is_none());
    }

    /// The seen-ring is bounded; ancient entries roll off and may
    /// legitimately re-deliver.
    #[test]
    fn gate_ring_is_bounded() {
        let (gate, mut rx) = gate_with_rx();
        for i in 0..(GATE_SEEN_CAPACITY + 10) {
            assert!(gate.deliver(offer("peer-a", &format!("sdp-{i}"))));
            rx.try_recv()
                .expect("each distinct offer reaches the engine mailbox");
        }
        assert_eq!(gate.seen.lock().len(), GATE_SEEN_CAPACITY);
    }

    /// How many samples the characterization below takes per carrier.
    ///
    /// Large enough that one scheduler hiccup does not become "the" number,
    /// small enough that the run finishes instantly. **It is not a capacity, a
    /// threshold, an admissible-object count, or a claim about how much
    /// anything can carry** — it is how many times a stopwatch is started.
    const CHARACTERIZATION_SAMPLES: usize = 64;

    /// Pull deliveries until one produces `wanted`, and say how long that took.
    ///
    /// The effect selects the delivery rather than being asserted about it: the
    /// negotiation frame between the announce and the candidate is drained and
    /// dropped on the way past, exactly as the driver would step over it while
    /// waiting for the thing it is timing.
    ///
    /// The panic is a guard on the *measurement*, not a claim about the
    /// boundary. A characterization that reports a number it never took is
    /// worse than one that reports nothing, so an empty queue fails here
    /// instead of printing a default.
    fn elapsed_until(
        rx: &mut crate::resource::ResourceMailboxReceiver<LaneDelivery>,
        started: Instant,
        wanted: SignalingEffect,
        what: &str,
    ) -> Duration {
        while let Some(delivered) = rx.try_recv() {
            if delivered.value().effect() == wanted {
                return started.elapsed();
            }
        }
        panic!("the fixture produced no {what}; there is no measurement to report");
    }

    /// Print one event's observed sample range. Sorted in place; no value here
    /// is derived from, compared against, or used to set anything.
    fn report_samples(carrier: SignalingCarrier, event: &str, samples: &mut [Duration]) {
        samples.sort_unstable();
        let n = samples.len();
        println!(
            "lane-boundary characterization | carrier={carrier} | {event} | \
             n={n} min={min:?} median={median:?} max={max:?}",
            carrier = carrier.name(),
            min = samples[0],
            median = samples[n / 2],
            max = samples[n - 1],
        );
    }

    /// **§8.5 characterization: time to first hint and time to first candidate,
    /// measured at the lane boundary. Not a control.**
    ///
    /// `TRANSITION-PLAYBOOK.md` §8.5 requires both of these to be measured and
    /// says omitting them is a defect. It says three other things just as
    /// plainly, and this test is built around them: the measurements **are
    /// never capacity**, they may not "set, justify, or imply a grant, ceiling,
    /// budget, or admissible-object count", and performance characterization
    /// **is not correctness evidence**. So nothing here asserts a duration,
    /// compares one against a threshold, or derives a limit from what it saw.
    /// It starts a stopwatch, prints what it read, and stops.
    ///
    /// # What is actually being timed
    ///
    /// One carrier report entering the lane boundary and reaching the point
    /// where the engine could take it off its mailbox: classify, parse into the
    /// domain value, cross-carrier de-duplication, resource admission, queue.
    /// The sequence per sample is the realistic one — a peer is heard from
    /// (the hint), then a negotiation frame, then a candidate — and the second
    /// figure is cumulative from the same start, because "time to first
    /// candidate" is time from the beginning, not time since the offer.
    ///
    /// # What is not being timed, and the number is useless without this
    ///
    /// **No carrier, no socket, no relay, no multicast, no WebRTC, no peer.**
    /// Everything is in-process against an isolated resource root. A deployment's
    /// time-to-first-hint is dominated by relay dial, subscription replay and
    /// mDNS query timing, and none of that exists here. What this reports is
    /// **the lane boundary's own contribution** to those two figures — the part
    /// this unit added and is therefore answerable for.
    ///
    /// That is also why all three carriers are measured and are expected to
    /// look alike. Identical numbers across `local`, `nostr` and `mdns` are the
    /// honest finding: the boundary costs the same whatever observed the
    /// message, and the difference between carriers lives in the part of the
    /// path this fixture does not touch. The deployment-level figures belong to
    /// the §8.4 integration matrix, which this unit does not run.
    ///
    /// Ignored by default because its output *is* its purpose: it needs
    /// `--nocapture` to say anything, and a suite run would otherwise carry a
    /// test that passes without reporting.
    #[test]
    #[ignore = "§8.5 characterization, not a control: reports lane-boundary \
                timings and asserts no threshold. Run with \
                `--ignored --nocapture`"]
    fn v4_m2_u1_lane_boundary_time_to_first_hint_and_first_candidate() {
        for carrier in [
            SignalingCarrier::Local,
            SignalingCarrier::Nostr,
            SignalingCarrier::Mdns,
        ] {
            let (gate, mut rx) = gate_with_rx();
            let mut to_first_hint = Vec::with_capacity(CHARACTERIZATION_SAMPLES);
            let mut to_first_candidate = Vec::with_capacity(CHARACTERIZATION_SAMPLES);

            for sample in 0..CHARACTERIZATION_SAMPLES {
                // A fresh peer per sample, so the gate's content ring never
                // swallows a repeat and every sample measures a first arrival
                // rather than a de-duplicated one.
                let peer = format!("characterization-peer-{sample}");
                let started = Instant::now();

                let _ = gate.deliver(reported(
                    carrier,
                    CarrierReport::Announced {
                        device_id: peer.clone(),
                    },
                ));
                to_first_hint.push(elapsed_until(
                    &mut rx,
                    started,
                    SignalingEffect::CarrierPresence,
                    "hint",
                ));

                let _ = gate.deliver(offer_from(carrier, &peer, &format!("sdp-{sample}")));
                let _ = gate.deliver(candidate_from(carrier, &peer, Some("0")));
                to_first_candidate.push(elapsed_until(
                    &mut rx,
                    started,
                    SignalingEffect::TransportCandidate,
                    "candidate",
                ));
            }

            report_samples(carrier, "time to first hint", &mut to_first_hint);
            report_samples(carrier, "time to first candidate", &mut to_first_candidate);
        }
    }
}
