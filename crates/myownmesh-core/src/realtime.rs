//! The **basal** realtime vocabulary: what is true of any flow, on any provider.
//!
//! A basal flow is a labelled, directed stream of opaque byte units inside a
//! session. Direction, refusal, and the lease on a session's inbound stream
//! need no clock, no codec and no transport to mean something.
//!
//! A flow ending is not among them, and that is a contract rather than an
//! omission. A close is the result of the local operation that performed it,
//! returned to that caller; a session ending is the inbound stream ending. So
//! there is nothing left for a lifecycle event to say that its reader was not
//! already told, and an event naming only a reusable name could not say it
//! unambiguously anyway.
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
/// which takes from the one queue this handle already names.
///
/// **Naming the stream is what binds it, and nothing else needs to.** The reader
/// holds a weak reference to the exact queue the claiming session's flow set
/// owns, so a handle can only ever take units that set put there: not another
/// peer's, and not those of a session that replaced it under the same selector.
/// A retained copy of the selector would be a second fact saying the same thing,
/// and the two could only ever agree or be a bug.
///
/// Holding one does not keep a session alive. When the session ends the stream
/// ends — the awaiting call answers `None`, permanently — and that is the only
/// notification of the end there is.
pub struct RealtimeInboundStream {
    reader: crate::transport::webrtc::RealtimeInboundArrivals,
}

impl RealtimeInboundStream {
    pub(crate) fn new(reader: crate::transport::webrtc::RealtimeInboundArrivals) -> Self {
        Self { reader }
    }

    pub(crate) fn reader(&self) -> &crate::transport::webrtc::RealtimeInboundArrivals {
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
