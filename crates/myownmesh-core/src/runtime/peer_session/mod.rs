//! What one promoted peer session owns on the application side.
//!
//! Everything here is reachable only through a live [`SessionCapability`], and
//! everything here dies when that session does. Both halves of that sentence are
//! load-bearing.
//!
//! The record has no key. It is a field of the promoted session, so a
//! replacement cannot name its predecessor's record any more than it can name
//! its predecessor's authority, and there is no map an operation could reach one
//! through.
//!
//! # The boundary between the children
//!
//! Three sub-responsibilities, one per module, none of which needs to read the
//! others' state:
//!
//! * [`slot`] — the promoted session bundle and the one slot a peer entry holds
//!   it in, with the install, reuse and revocation rules that govern it.
//! * [`reliable`] — acknowledged-delivery state: the frames retained until the
//!   peer acknowledges them, and the mark recording what this side has accepted.
//! * [`capabilities`] — what the peer advertised over this session, and whether
//!   this session still owes the peer the local advertisement.
//!
//! [`PeerSessionState`] below is the composition point and nothing more. It owns
//! one value from each child and forwards to it; the rules themselves live with
//! the state they govern, so a change to acknowledgement cannot silently alter
//! what an advertisement costs.
//!
//! The contract that follows, structurally rather than by discipline:
//!
//! * **Submission requires a current session.** The record does not exist until
//!   promotion creates it, so a caller whose peer has no live session is told
//!   that rather than parked against a session that may never exist.
//! * **Every retained frame holds its exact lease.** The bound is the provider
//!   refusing the next frame's own claim. Nothing is retained unpaid, and
//!   releasing a frame releases everything that frame was costing.
//! * **Revocation, replacement, retirement and shutdown resolve the caller.**
//!   All four are one act — dropping the promoted session — and the retained
//!   frame's own `Drop` is what answers the waits.
//! * **A peer that does not speak the acknowledged contract is refused.** An
//!   acknowledged-delivery wait is resolved by an acknowledgement or by nothing.

mod capabilities;
mod reliable;
mod slot;

use tokio::sync::oneshot;

use crate::error::{Error, Result};
use crate::protocol::CapabilityAdvert;
use crate::runtime::session_broker::SessionCapability;

pub(crate) use reliable::{InboundOutcome, UnsentFrame};
pub(crate) use slot::{PromotedSession, PromotedSessionSlot, Reuse};

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) use capabilities::{
    encoded_advert_len_for_test, retained_advert_reservation_charge_for_test,
};
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) use reliable::{
    retained_frame_reservation_charge_for_test, transient_frame_reservation_charge_for_test,
};

/// The application state one promoted session owns.
///
/// Created by promotion, dropped with the session. Not `Clone` and not
/// serializable: a copy would be a second retained truth about a peer, which is
/// what having one owner exists to prevent.
pub(crate) struct PeerSessionState {
    reliable: reliable::ReliableState,
    /// Locally-originated RPC operations filed through this exact session.
    /// Dropping the promoted-session bundle drops every sender and lease.
    rpc: crate::rpc::SessionRpcState,
    /// What the peer advertised over this session.
    peer_advert: capabilities::RetainedAdvert,
    /// Whether this session still owes the peer the local advertisement.
    local_advert: capabilities::LocalAdvertDebt,
}

impl PeerSessionState {
    /// Infallible, and every field starts at the value promotion means: an empty
    /// reliable stream, no advertisement heard, and the local advertisement
    /// owed. Nothing here allocates or reserves, which is what lets installation
    /// be the step after promotion's last fallible one.
    pub(crate) fn new() -> Self {
        Self {
            reliable: reliable::ReliableState::new(),
            rpc: crate::rpc::SessionRpcState::new(),
            peer_advert: capabilities::RetainedAdvert::default(),
            local_advert: capabilities::LocalAdvertDebt::new(),
        }
    }

    pub(crate) fn rpc_mut(&mut self) -> &mut crate::rpc::SessionRpcState {
        &mut self.rpc
    }

    /// The peer's advertisement as heard over **this** session.
    pub(crate) fn capabilities(&self) -> Option<CapabilityAdvert> {
        self.peer_advert.decoded()
    }

    /// Record what the peer advertised over this session, replacing any earlier
    /// advertisement it made over the same one.
    ///
    /// On refusal nothing changes and the caller must announce nothing.
    pub(crate) fn set_capabilities(
        &mut self,
        session: &SessionCapability,
        advert: &CapabilityAdvert,
    ) -> Result<()> {
        self.peer_advert.replace(session, advert)
    }

    /// Whether this session still owes its peer the current local advertisement.
    pub(crate) fn local_advert_owed(&self) -> bool {
        self.local_advert.owed()
    }

    /// Record that the peer has been told, after a send that actually
    /// succeeded.
    ///
    /// Read, send, then clear — never take-then-send, so a failed send leaves
    /// the debt owed rather than losing the advertisement.
    pub(crate) fn clear_local_advert_debt(&mut self) {
        self.local_advert.clear();
    }

    /// Frames retained and not yet acknowledged.
    pub(crate) fn pending(&self) -> usize {
        self.reliable.pending()
    }

    /// Retain one frame for acknowledged delivery, or tell the caller why not.
    pub(crate) fn submit(
        &mut self,
        session: &SessionCapability,
        channel: &str,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    ) {
        self.reliable.submit(session, channel, payload, reply);
    }

    /// Whether this session still owes the wire anything.
    pub(crate) fn has_unsent(&mut self) -> bool {
        self.reliable.has_unsent()
    }

    /// The next frame this session owes the wire, with the write's copy funded
    /// for exactly as long as it exists.
    pub(crate) fn next_unsent(&mut self, session: &SessionCapability) -> Option<UnsentFrame> {
        self.reliable.next_unsent(session)
    }

    /// Record that `seq` reached the wire under this session.
    pub(crate) fn mark_sent(&mut self, seq: u64) {
        self.reliable.mark_sent(seq);
    }

    /// Settle the contiguous front prefix this acknowledgement genuinely covers,
    /// resolving each caller in place, and answer how many were settled.
    pub(crate) fn acknowledge(&mut self, stream: u64, up_to: u64) -> usize {
        self.reliable.acknowledge(stream, up_to)
    }

    /// Accept one inbound frame, advancing only after its gateway handoff.
    pub(crate) fn try_receive<E>(
        &mut self,
        stream: u64,
        seq: u64,
        payload: serde_json::Value,
        deliver: impl FnOnce(serde_json::Value) -> std::result::Result<(), E>,
    ) -> std::result::Result<InboundOutcome, E> {
        self.reliable.try_receive(stream, seq, payload, deliver)
    }

    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn receive(
        &mut self,
        stream: u64,
        seq: u64,
        payload: serde_json::Value,
        deliver: impl FnOnce(serde_json::Value),
    ) -> InboundOutcome {
        self.reliable.receive(stream, seq, payload, deliver)
    }

    /// This session's send-side stream id.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn stream_for_test(&self) -> u64 {
        self.reliable.stream_for_test()
    }
}

/// Why a reliable submission reached no session.
///
/// One value, deliberately: the caller learns that no current session would
/// carry the frame, and nothing finer. Distinguishing "no session" from "policy
/// refused" from "connector superseded" here would republish, to the
/// application, exactly the admission detail the session boundary exists to keep
/// inside the mesh.
pub(crate) fn no_session_error(peer: &str) -> Error {
    Error::Transport(format!(
        "no live promoted session to carry a reliable send to {peer}"
    ))
}

/// Why a reliable submission was refused for a peer that has a session.
///
/// The peer's build does not speak the acknowledged contract. Refused rather
/// than downgraded: a local send succeeding is an answer about this process's
/// socket, and this caller asked about the peer's application layer.
pub(crate) fn unsupported_error(peer: &str) -> Error {
    Error::Transport(format!(
        "peer {peer} does not support acknowledged channel delivery"
    ))
}
