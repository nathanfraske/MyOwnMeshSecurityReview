//! The Semantic Node's ingress: durable facts, and only from a session that
//! earned the right to state one.
//!
//! # Two ingresses, and why they are two
//!
//! `signaling_ingress` admits **ephemeral transport signals** — presence,
//! withdrawal, and the offer/answer/candidate exchange — from carriers nobody
//! authenticated. Everything it can emit is reachability evidence about one
//! connection attempt, and the closure of that union is what makes a relay
//! unable to touch a durable fact however it is fed.
//!
//! This module is the other half, and it is deliberately *not* a second lane on
//! the same carrier. Its input arrives on a promoted Peer Session, after
//! endpoint authentication, under the exact [`PeerOwnerToken`] that session
//! belongs to. That token is the whole difference: a durable fact is worth
//! acting on because of who stated it, and on the signaling side there is no
//! "who".
//!
//! So the two ownerships are disjoint by construction rather than by
//! convention:
//!
//! | | ephemeral carrier ingress | durable semantic ingress |
//! |---|---|---|
//! | arrives on | any carrier, unauthenticated | a promoted, authenticated session |
//! | knows the sender | no — a claim or a medium's observation | yes — the session's own owner |
//! | may change the roster | never | that is what it is for |
//! | admitted by | [`super::signaling_ingress`] | [`admit`] |
//!
//! There is no `SignalingMessage` variant for any of this, and adding one would
//! be the defect: it would put a durable fact on a carrier that cannot say who
//! sent it.
//!
//! # What "closed" means here
//!
//! [`DurableSemanticIngress`] wraps a private enum. Nothing outside this module
//! can name a variant, so nothing outside can build one — the only way to
//! obtain the type is [`admit`], which takes a [`MeshMessage`] that by
//! construction came off an authenticated session's decoded frame. A future
//! durable message added to `MeshMessage` reaches this module or it reaches
//! nothing: `admit` hands back what it does not recognise, and the engine's own
//! match is exhaustive.
//!
//! # Why the outcome is its own enum and not a `Result`
//!
//! "Not a durable fact" is not an error — it is the ordinary case, and the frame
//! comes back whole for the engine to dispatch. A `Result` would have said the
//! opposite, and it would also have put a `MeshMessage` in an `Err`, which is
//! large: every non-durable live frame would pay for the widest variant on its
//! way past. Boxing it would have traded that for an allocation on every such
//! frame, which is worse — this classifier sits in front of the entire inbound
//! path. [`SemanticAdmission`] is two named outcomes, moves the frame, and
//! allocates nothing.

use std::sync::Arc;

use tracing::trace;

use crate::protocol::{
    MeshMessage, NetworkStateAckMessage, NetworkStateBroadcast, NetworkStateProposeMessage,
    NetworkStateSplitMessage, RosterEntriesMessage, RosterRequestMessage, RosterSummaryMessage,
};

use super::governance;
use super::peer_registry::PeerOwnerToken;
use super::state::NetworkState;

/// One durable fact, stated by an authenticated session.
///
/// The private field is the point: see the module documentation for why this
/// type is obtainable only through [`admit`].
pub(crate) struct DurableSemanticIngress {
    fact: DurableFact,
}

/// The closed set of durable facts a peer may state.
///
/// Every one of these mutates something pubkey-keyed and long-lived — the
/// transition log, the roster — or asks for the same. Nothing here is a
/// transport concern, and nothing on the transport side can produce one.
enum DurableFact {
    /// A full network-state broadcast.
    StateBroadcast(NetworkStateBroadcast),
    /// A proposed transition, awaiting acknowledgement.
    Propose(NetworkStateProposeMessage),
    /// An acknowledgement of one.
    Ack(NetworkStateAckMessage),
    /// A divergence report between two views of the log.
    Split(NetworkStateSplitMessage),
    /// A digest of the sender's roster, for comparison.
    RosterSummary(RosterSummaryMessage),
    /// A request for rows the sender is missing.
    RosterRequest(RosterRequestMessage),
    /// The rows themselves.
    RosterEntries(RosterEntriesMessage),
}

/// What one decoded frame turned out to be.
///
/// Two outcomes, neither of them a failure. See the module documentation for why
/// this is not a `Result`.
pub(crate) enum SemanticAdmission {
    /// A durable fact, for [`reduce`].
    Durable(DurableSemanticIngress),
    /// Not this module's, handed back whole and unmodified.
    NotDurable(MeshMessage),
}

/// Admit a decoded frame as a durable fact, or hand it straight back.
///
/// Written as a total function over `MeshMessage` with no `_` arm, so a new
/// variant is a compile error here and has to be classified deliberately rather
/// than silently falling out of the durable set.
pub(crate) fn admit(message: MeshMessage) -> SemanticAdmission {
    let fact = match message {
        MeshMessage::NetworkState(m) => DurableFact::StateBroadcast(m),
        MeshMessage::NetworkStatePropose(m) => DurableFact::Propose(m),
        MeshMessage::NetworkStateAck(m) => DurableFact::Ack(m),
        MeshMessage::NetworkStateSplit(m) => DurableFact::Split(m),
        MeshMessage::RosterSummary(m) => DurableFact::RosterSummary(m),
        MeshMessage::RosterRequest(m) => DurableFact::RosterRequest(m),
        MeshMessage::RosterEntries(m) => DurableFact::RosterEntries(m),
        other @ (MeshMessage::Ping(_)
        | MeshMessage::Pong(_)
        | MeshMessage::Hello(_)
        | MeshMessage::AuthResponse(_)
        | MeshMessage::Approve(_)
        | MeshMessage::Deny(_)
        | MeshMessage::Shelve(_)
        | MeshMessage::Unshelve(_)
        | MeshMessage::SessionControl(_)
        | MeshMessage::CapabilitiesUpdate(_)
        | MeshMessage::RpcRequest(_)
        | MeshMessage::RpcResponse(_)
        | MeshMessage::RpcStreamChunk(_)
        | MeshMessage::RpcStreamEnd(_)
        | MeshMessage::Channel { .. }
        | MeshMessage::ChannelSeq { .. }
        | MeshMessage::ChannelAck { .. }) => return SemanticAdmission::NotDurable(other),
    };
    SemanticAdmission::Durable(DurableSemanticIngress { fact })
}

impl DurableSemanticIngress {
    /// The fact's kind, for diagnostics. Names the shape and never the content.
    pub(crate) fn kind_name(&self) -> &'static str {
        match self.fact {
            DurableFact::StateBroadcast(_) => "state_broadcast",
            DurableFact::Propose(_) => "propose",
            DurableFact::Ack(_) => "ack",
            DurableFact::Split(_) => "split",
            DurableFact::RosterSummary(_) => "roster_summary",
            DurableFact::RosterRequest(_) => "roster_request",
            DurableFact::RosterEntries(_) => "roster_entries",
        }
    }
}

/// The Semantic Node's reducer: apply one durable fact.
///
/// # Why the owner token comes with it and is not looked up
///
/// Four of these arms need only the sender's mesh identity — the transition log
/// and the roster are keyed by public key, not by which installation happened
/// to deliver the row — and they take `owner.device_id()` for exactly that.
/// The two roster arms reply to the sender, so they take the token itself and
/// send back over the installation the request arrived on. Neither shape
/// re-resolves the peer by id, which is what keeps a replacement that landed
/// mid-reduction from receiving an answer to a question the previous
/// installation asked.
pub(crate) async fn reduce(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    ingress: DurableSemanticIngress,
) {
    trace!(
        peer = %owner.device_id(),
        kind = ingress.kind_name(),
        "reducing a durable semantic fact"
    );
    match ingress.fact {
        DurableFact::StateBroadcast(m) => governance::on_state_broadcast(state, owner, m).await,
        DurableFact::Propose(m) => governance::on_propose(state, owner.device_id(), m).await,
        DurableFact::Ack(m) => governance::on_ack(state, owner.device_id(), m).await,
        DurableFact::Split(m) => governance::on_split(state, owner.device_id(), m).await,
        DurableFact::RosterSummary(m) => governance::on_roster_summary(state, owner, m).await,
        DurableFact::RosterRequest(m) => governance::on_roster_request(state, owner, m).await,
        DurableFact::RosterEntries(m) => {
            governance::on_roster_entries(state, owner.device_id(), m).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every durable message is admitted here, and nothing else is.**
    ///
    /// The two halves are one control because each is the other's non-vacuity: a
    /// classifier that admitted everything would pass the first alone, and one
    /// that admitted nothing would pass the second.
    #[test]
    fn the_durable_set_is_exactly_the_facts_a_session_may_state() {
        let durable = [
            MeshMessage::NetworkState(NetworkStateBroadcast {
                kind: crate::network_state::NetworkKind::Closed,
                transitions_count: 0,
                member_log_count: 0,
                roster_root: String::new(),
            }),
            MeshMessage::NetworkStatePropose(NetworkStateProposeMessage {
                proposal_id: String::new(),
                variant: crate::network_state::TransitionVariant::KindChange {
                    to: crate::network_state::NetworkKind::Closed,
                },
                proposer: String::new(),
                created_at: 0,
                signature: String::new(),
            }),
            MeshMessage::NetworkStateAck(NetworkStateAckMessage {
                proposal_id: String::new(),
                signer: String::new(),
                decision: crate::protocol::AckDecision::Sign,
                at: 0,
                signature: String::new(),
            }),
            MeshMessage::NetworkStateSplit(NetworkStateSplitMessage {
                parent_proposal_id: String::new(),
                new_network_id: String::new(),
                members: Vec::new(),
                proposer: String::new(),
                at: 0,
                signature: String::new(),
            }),
            MeshMessage::RosterSummary(RosterSummaryMessage {
                root: String::new(),
                count: 0,
                last_edit_ts: 0,
            }),
            MeshMessage::RosterRequest(RosterRequestMessage::default()),
            MeshMessage::RosterEntries(RosterEntriesMessage {
                entries: Vec::new(),
                transitions: Vec::new(),
                member_log: Vec::new(),
            }),
        ];
        for message in durable {
            assert!(
                matches!(admit(message), SemanticAdmission::Durable(_)),
                "a durable fact must reach the Semantic Node's reducer"
            );
        }

        // A transport control and an application frame: neither is a durable
        // fact, and both must come back untouched for the engine's own match.
        let transport = MeshMessage::SessionControl(crate::protocol::SessionControl::Depart);
        assert!(
            matches!(admit(transport), SemanticAdmission::NotDurable(_)),
            "a session-lifecycle control is the Peer Session owner's, not the \
             Semantic Node's"
        );
        let application = MeshMessage::Channel {
            channel: "chat".into(),
            payload: serde_json::Value::Null,
        };
        assert!(
            matches!(admit(application), SemanticAdmission::NotDurable(_)),
            "an application frame carries no durable fact"
        );
    }
}
