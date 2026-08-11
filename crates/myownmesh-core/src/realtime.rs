//! The **basal** realtime vocabulary: what is true of any flow, on any provider.
//!
//! A basal flow is a labelled, directed stream of opaque byte units inside a
//! session. Direction, refusal, the fact that a flow closed, and the leases on a
//! session's streams need no clock, no codec and no transport to mean something.
//!
//! Anything that does — media kind, MIME, clock rate, channels, pacing
//! duration, RTP timestamp, marker — belongs to the provider that negotiates
//! the clock making it readable. [`crate::transport::webrtc`] declares those,
//! and they cross at the `*_webrtc_realtime` methods on
//! [`crate::JoinedNetwork`].
//!
//! The invariant here is about vocabulary, not dependencies: nothing public in
//! this module exposes or interprets provider metadata, and nothing here
//! converts between the two vocabularies. The stream leases do hold a
//! provider's reader in a private field — that is the generic claim-once
//! lifetime mechanism, carrying no media meaning of its own.
//!
//! There is therefore no configuration channel here: no opaque blob, no
//! key-value map, no purpose or authority string. A provider declares its types
//! rather than describing itself at runtime, and the method carrying them says
//! whose they are in its name — so nothing is left to validate and nothing in a
//! payload can name an authority.
//!
//! A label here is a bounded opaque name: 1..=255 bytes the application chose,
//! carried verbatim and never interpreted. Bounded because that is what the
//! encoded frame can spell, opaque because nothing on this side reads it, and
//! session-scoped because it means something only against the flow set that
//! accepted it.
//!
//! Publishing the connector's leased label, flow handles or ports would invite
//! reading one as a handle that grants something. What crosses instead is a
//! copy of the bytes, and it grants nothing: every operation resolves a live
//! session first, and the copy owns no part of the session's accounting for the
//! name it spells.

use serde::{Deserialize, Serialize};

/// The largest label the encoded frame can carry.
///
/// **A representation fact, not a policy ceiling and not tunable.** The frame's
/// label is prefixed by one length byte, so this is the width of that field and
/// nothing more. It bounds one label's size and says nothing about how many
/// labels may exist at once — that is admission's question, and admission
/// answers it with leases.
///
/// It lives in the basal vocabulary because the daemon, the provider edge and
/// the connector all have to agree on it, and three copies of `255` would agree
/// until one of them was changed. Anything that speaks the wire refers to this
/// one constant.
pub const MAX_REALTIME_FLOW_LABEL_BYTES: usize = u8::MAX as usize;

/// Which way units travel on one flow.
///
/// One direction per flow. A bidirectional application opens two.
///
/// Serialized because the daemon's control request carries it verbatim. One
/// definition rather than a daemon-local mirror: two enums over the same two
/// cases would agree until one gained a variant, and the wire spelling is the
/// contract, so it belongs beside the type it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeFlowDirection {
    /// This endpoint sends; the peer receives.
    Outbound,
    /// This endpoint receives; the peer sends.
    Inbound,
}

/// A flow of this session went away.
///
/// One variant, and that is the whole vocabulary.
///
/// There is deliberately **no open variant**. A flow exists only because this
/// side's authenticated application asked for one, and that ask is already
/// answered by the response to its own request — an event would be a second,
/// weaker account of something the caller was told directly, and two accounts
/// can disagree. An open event is also the shape a peer-minted flow would
/// arrive in, and a peer cannot mint one: inbound negotiation may only attach
/// to a flow this side already opened. Publishing the variant would advertise a
/// capability that does not exist.
///
/// There is deliberately **no retirement variant** either. A session ending is
/// the stream ending — `None` from the awaiting call — not an item on it. An
/// item would have to be delivered by something that outlived the session,
/// which is exactly the retention this design removes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealtimeFlowEvent {
    /// The flow under this name is gone and the name is free to claim again.
    ///
    /// A copy of the bytes, not the connector's leased label: a consumer
    /// holding the label itself would be an untracked holder of the session's
    /// lease, and this event routinely outlives the flow it reports.
    Closed { label: Vec<u8> },
}

/// An exclusive lease on one session's whole inbound stream.
///
/// One consumer at a time, held for as long as the handle is: a request made
/// while another handle is alive answers `None`, because two consumers parked
/// on one signal would each take wakes meant for the other.
///
/// Dropping the handle releases the lease, and the stream can be claimed again
/// while the session is still current. That is deliberate rather than
/// incidental — a consumer that panics or is cancelled would otherwise make its
/// session unreadable for the rest of its life, with no way to recover short of
/// tearing down a session that is working. Nothing is lost across the gap that
/// would not also have been lost with the consumer stalled: a fresh handle
/// drains what is already queued before it awaits anything.
///
/// The session ending is still terminal and is not a release. There is no
/// handle to re-claim with, because there is no stream.
///
/// The handle grants nothing. It cannot reach a flow, a port, or a session; the
/// only thing it can do is be handed back to
/// [`JoinedNetwork::recv_webrtc_realtime_any`](crate::JoinedNetwork::recv_webrtc_realtime_any),
/// which resolves the session again before it takes anything. It also carries
/// the selector it was claimed for, so a handle for one peer can never be used
/// to receive another's units, and it names the exact stream it was claimed on,
/// so a handle outliving a replacement cannot receive the *next* session's
/// units under a label that meant something else on the previous one.
///
/// Holding one does not keep a session alive. When the session ends the stream
/// ends — the awaiting call answers `None`, permanently — and that is the only
/// notification of the end there is.
pub struct RealtimeInboundStream {
    peer: String,
    reader: crate::transport::webrtc::RealtimeInboundArrivals,
}

impl RealtimeInboundStream {
    pub(crate) fn new(
        peer: String,
        reader: crate::transport::webrtc::RealtimeInboundArrivals,
    ) -> Self {
        Self { peer, reader }
    }

    pub(crate) fn peer(&self) -> &str {
        &self.peer
    }

    pub(crate) fn reader(&self) -> &crate::transport::webrtc::RealtimeInboundArrivals {
        &self.reader
    }
}

/// An exclusive lease on one session's flow-close stream.
///
/// Exclusive, releasable on drop, and inert for the same reasons as
/// [`RealtimeInboundStream`]: one consumer at a time, a second request while a
/// handle is alive answers `None`, dropping the handle lets the stream be
/// claimed again while the session is current, and the session ending is
/// terminal rather than a release.
///
/// A separate lease from the inbound one, not a second view of it, because one
/// signal wakes one waiter — a lifecycle consumer sharing the inbound stream
/// would take wakes the receiver needed.
pub struct RealtimeFlowEventStream {
    reader: crate::transport::webrtc::RealtimeFlowEvents,
}

impl RealtimeFlowEventStream {
    pub(crate) fn new(reader: crate::transport::webrtc::RealtimeFlowEvents) -> Self {
        Self { reader }
    }

    pub(crate) fn reader(&self) -> &crate::transport::webrtc::RealtimeFlowEvents {
        &self.reader
    }
}

/// Why a realtime operation was refused.
///
/// Four cases, each a distinct fact a client can act on. There is deliberately
/// no "unknown peer" variant: an unknown selector, a replaced installation and
/// an unpromoted peer are one fact from the caller's side — there is no live
/// session — and separating them would report peer existence to a caller that
/// has proved nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealtimeRefusal {
    /// No live session for that selector: absent, replaced, retired, or the
    /// process restarted. Never re-bound — open a flow on a fresh session.
    #[error("no current session for this peer")]
    SessionNotCurrent,
    /// The session already holds a flow under that label.
    #[error("flow label is already in use on this session")]
    LabelInUse,
    /// The connector refused the flow: its own ceiling, or resources.
    #[error("the connector refused the flow")]
    FlowRefused,
    /// The provider's own configuration for the flow was unusable, or matched
    /// nothing it had registered.
    ///
    /// Basal deliberately says nothing about *what* was wrong. Core does not
    /// know what a provider's configuration means — that is the whole point of
    /// the split — so naming an encoding here would be core claiming knowledge
    /// it does not have. The provider validates its own vocabulary and this
    /// reports only that it refused.
    #[error("the provider's configuration for this flow is not usable")]
    ProviderConfigurationInvalid,
}

/// The stable machine-readable code for one refusal.
///
/// Separate from the `Display` message, which is for humans and is never parsed.
impl RealtimeRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::SessionNotCurrent => "session_not_current",
            Self::LabelInUse => "label_in_use",
            Self::FlowRefused => "flow_refused",
            Self::ProviderConfigurationInvalid => "provider_configuration_invalid",
        }
    }
}

// ---- provider values becoming basal values ----------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc05_the_daemon_wire_spelling_of_direction_is_pinned() {
        // These two strings are the control-request wire contract for the one
        // field of it that is basal. A rename is silently accepted by a
        // Rust-side refactor and breaks every client already speaking the old
        // spelling, so they are asserted literally rather than round-tripped.
        // The provider's own field is pinned beside its own type.
        for (value, spelling) in [
            (RealtimeFlowDirection::Outbound, "\"outbound\""),
            (RealtimeFlowDirection::Inbound, "\"inbound\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), spelling);
            assert_eq!(
                serde_json::from_str::<RealtimeFlowDirection>(spelling).unwrap(),
                value
            );
        }

        // Non-vacuity: the spellings really are distinguishing, and an
        // unrecognised one is refused rather than defaulted onto a variant.
        assert!(serde_json::from_str::<RealtimeFlowDirection>("\"both\"").is_err());
        assert!(serde_json::from_str::<RealtimeFlowDirection>("\"Inbound\"").is_err());
    }
}
