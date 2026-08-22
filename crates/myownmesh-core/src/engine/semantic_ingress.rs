//! The Semantic Node's ingress: one transport-independent port for durable
//! semantic exchange.
//!
//! # Two ingresses, and why they are two
//!
//! `signaling_ingress` admits **ephemeral transport signals** — presence,
//! withdrawal, and the offer/answer/candidate exchange — from carriers nobody
//! authenticated. Everything it can emit is reachability evidence about one
//! connection attempt, and the closure of that union is what makes a relay
//! unable to touch a durable fact however it is fed.
//!
//! This module is the other half. It is not "the authenticated lane": it is the
//! lane where the *content* carries its own authority.
//!
//! | | ephemeral carrier ingress | durable semantic exchange |
//! |---|---|---|
//! | what it carries | evidence about one attempt | facts, bundles, inventories, requests |
//! | what makes it actionable | nothing — it grants nothing | the embedded author, signature and domain context |
//! | who may deliver it | any carrier | any carrier, cache, file or medium |
//! | may change the roster | never | that is what it is for |
//! | admitted by | [`super::signaling_ingress`] | [`admit`] |
//!
//! # Fact authority is content, not carrier
//!
//! ```text
//! fact authority = canonical content
//!                + embedded author and signature
//!                + exact mesh/domain context
//!                + causal/domain validation
//!
//! fact authority != the current carrier
//!                != the current session sender
//! ```
//!
//! An earlier revision of this module said the opposite — that a durable fact is
//! worth acting on because of *who stated it* — and the reducers enforced it:
//! a proposal, ack or split whose embedded author differed from the delivering
//! session's own pubkey was refused. That made a peer unable to relay a valid
//! signed fact authored by a Device this node cannot reach, and it made a cache,
//! a file, a serial link, removable media or a future durable carrier unable to
//! feed the same reducer without first minting a Peer Session. Endpoint
//! authentication protects a live session; it was never what makes a fact true.
//!
//! So [`reduce`] takes the session — when there is one — as a **reply route and
//! nothing else**. For [`Exchange::SignedFact`] that is a type property rather
//! than a promise: those arms are never handed the token, so the compiler is
//! what enforces it (see [`Exchange`]). [`Exchange::FactBundle`] does receive a
//! device id derived from the route, and it is diagnostics only — a
//! session-scoped label on a trace and a log line, never consulted to decide
//! whether the bundle is true. The bundle authenticates itself the same way a
//! single fact does.
//!
//! **What would be a defect, stated precisely.** Adding a durable body to the
//! *ephemeral* union would be one: it would put a fact on a carrier that cannot
//! say who sent it and has no signature to check. Adding a separate typed
//! durable-exchange carrier — a cache adapter, a file replay, a store — is the
//! opposite, and is the architecture this port exists to make possible.
//!
//! # What "closed" means here
//!
//! [`DurableSemanticExchange`] wraps a private enum. Nothing outside this module
//! can name a variant, so nothing outside can build one — the only way to obtain
//! the type is [`admit`], which is total over [`MeshMessage`] with no `_` arm. A
//! future durable message reaches this module or it reaches nothing.
//!
//! # Why the outcome is its own enum and not a `Result`
//!
//! "Not a durable exchange" is not an error — it is the ordinary case, and the
//! frame comes back whole for the engine to dispatch. A `Result` would have said
//! the opposite, and it would also have put a `MeshMessage` in an `Err`, which is
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
use super::peer_registry::LogicalSessionOperation;
use super::state::NetworkState;

/// One admitted durable semantic exchange.
///
/// The private field is the point: see the module documentation for why this
/// type is obtainable only through [`admit`].
pub(crate) struct DurableSemanticExchange {
    exchange: Exchange,
}

/// The closed set of things a durable semantic exchange can be.
///
/// Four classes, because these seven messages are not one semantic kind and
/// calling them all "facts" hid the difference that matters: only two of these
/// classes are things to content-address, store, compact or project, and only
/// the other two have anyone to answer.
///
/// **The split is load-bearing for the reply route.** [`reduce`] hands the
/// optional [`LogicalSessionOperation`] itself to the inventory and request
/// arms only. The operation exposes only its workerless owner to governance.
/// [`Self::SignedFact`] is not merely trusted not to read it — it is never
/// passed it, so for signed facts "a fact does not depend on its courier" is
/// checked by the compiler rather than by review.
///
/// [`Self::FactBundle`] is the one arm where that is a review property instead
/// of a type property, and the difference is worth stating plainly rather than
/// rounding off. It is passed a `&str` device id read off the route, which
/// reaches `governance::on_roster_entries` as a diagnostic label: it names who
/// handed the bundle over, in a trace and in a log line, and scopes that name to
/// the session it arrived on. It is not an input to verification, not compared
/// against any author, and not able to make a bundle acceptable or
/// unacceptable — the log walk from genesis decides that alone.
enum Exchange {
    /// A fact that carries its own author, signature and domain context.
    ///
    /// Verified by [`super::governance`] against the embedded signature over a
    /// canonical payload that names this network and the state signing domain.
    /// Nothing about the delivery is consulted.
    SignedFact(SignedFact),
    /// A bundle of facts: the signed governance and member transition logs.
    ///
    /// Self-authenticating the same way, in bulk — `verify_log` and
    /// `verify_member_log` walk it from genesis, and a fork or a bad signature
    /// rejects the whole bundle rather than part of it.
    ///
    /// **One honest impurity, named rather than hidden.** The same message also
    /// carries an unsigned `entries` list. On a closed network it is not a trust
    /// input at all and is ignored. On an open or silent network — where
    /// membership is permissionless by design and no per-entry signature exists
    /// on the wire to verify — it is merged additively as a hint: never stored
    /// as a fact, never compacted, and unable to rewrite an entry this node
    /// already holds or its own. Giving it a signature is a wire and product
    /// change, and inventing one here would have been the dishonest option.
    FactBundle(RosterEntriesMessage),
    /// A summary of what the sender has, so the two sides can find a difference.
    ///
    /// Counts and digests. Nothing here is stored or projected; its whole use is
    /// deciding whether to ask for something, which is why it needs a route back
    /// and a fact does not.
    Inventory(Inventory),
    /// A request for what the sender is missing.
    ///
    /// Carries no content to validate. It exists to be answered, so the reply
    /// route is the only thing it needs — and the answer must go to the exact
    /// installation that asked, not to whoever holds that device id by the time
    /// the reply is built.
    DependencyRequest(DependencyRequest),
}

/// A single self-authenticating fact.
enum SignedFact {
    /// A proposed transition, awaiting acknowledgement.
    Propose(NetworkStateProposeMessage),
    /// An acknowledgement of one.
    Ack(NetworkStateAckMessage),
    /// A divergence report between two views of the log.
    Split(NetworkStateSplitMessage),
}

/// A summary of the sender's state, for comparison.
enum Inventory {
    /// The sender's view of governance: kind, counts, membership root.
    NetworkState(NetworkStateBroadcast),
    /// A digest of the sender's roster.
    Roster(RosterSummaryMessage),
}

/// A request for rows the sender is missing.
enum DependencyRequest {
    /// The full roster and the signed logs behind it.
    Roster(RosterRequestMessage),
}

/// What one decoded frame turned out to be.
///
/// Two outcomes, neither of them a failure. See the module documentation for why
/// this is not a `Result`.
pub(crate) enum SemanticAdmission {
    /// A durable semantic exchange, for [`reduce`].
    Durable(DurableSemanticExchange),
    /// Not this module's, handed back whole and unmodified.
    NotDurable(MeshMessage),
}

/// Admit a decoded frame as a durable semantic exchange, or hand it straight
/// back.
///
/// Written as a total function over `MeshMessage` with no `_` arm, so a new
/// variant is a compile error here and has to be classified deliberately rather
/// than silently falling out of the durable set — and, now that the set has four
/// classes, classified into the right one rather than into a single bucket.
pub(crate) fn admit(message: MeshMessage) -> SemanticAdmission {
    let exchange = match message {
        MeshMessage::NetworkStatePropose(m) => Exchange::SignedFact(SignedFact::Propose(m)),
        MeshMessage::NetworkStateAck(m) => Exchange::SignedFact(SignedFact::Ack(m)),
        MeshMessage::NetworkStateSplit(m) => Exchange::SignedFact(SignedFact::Split(m)),
        MeshMessage::RosterEntries(m) => Exchange::FactBundle(m),
        MeshMessage::NetworkState(m) => Exchange::Inventory(Inventory::NetworkState(m)),
        MeshMessage::RosterSummary(m) => Exchange::Inventory(Inventory::Roster(m)),
        MeshMessage::RosterRequest(m) => Exchange::DependencyRequest(DependencyRequest::Roster(m)),
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
    SemanticAdmission::Durable(DurableSemanticExchange { exchange })
}

/// What a delivery is called in a log line when no session carried it.
///
/// A cache replay, a file, a future durable carrier: there is a source, but not
/// a peer. Diagnostics need a word for it; nothing reads it.
const NO_SESSION: &str = "(no session)";

impl DurableSemanticExchange {
    /// The exchange's kind, for diagnostics. Names the shape and never the
    /// content.
    pub(crate) fn kind_name(&self) -> &'static str {
        match self.exchange {
            Exchange::SignedFact(SignedFact::Propose(_)) => "propose",
            Exchange::SignedFact(SignedFact::Ack(_)) => "ack",
            Exchange::SignedFact(SignedFact::Split(_)) => "split",
            Exchange::FactBundle(_) => "fact_bundle",
            Exchange::Inventory(Inventory::NetworkState(_)) => "state_inventory",
            Exchange::Inventory(Inventory::Roster(_)) => "roster_inventory",
            Exchange::DependencyRequest(DependencyRequest::Roster(_)) => "roster_request",
        }
    }
}

/// The Semantic Node's reducer: apply one durable semantic exchange.
///
/// # The route is optional, and the facts cannot see it
///
/// `reply` is where an answer would go, and it is the exact logical session the
/// input arrived on — not a device id to re-resolve, so a replacement that
/// landed mid-reduction does not receive the answer to a question its
/// predecessor asked. It is `Option` because a durable exchange does not need
/// one: a fact replayed from a cache or a file has nobody to answer, and that is
/// an ordinary case rather than an error. Governance receives only the
/// operation's workerless owner; channel identity never enters this reducer.
///
/// It is **not** authority. The [`Exchange::SignedFact`] arms below are not
/// passed it at all, which is the whole reason [`Exchange`] separates them:
/// for those, transport-independence is checked by the compiler here rather
/// than asserted in a comment.
///
/// [`Exchange::FactBundle`] is passed a device id derived from the route, and
/// only as a diagnostic label scoped to the logical session it arrived on. Nothing in
/// the bundle's acceptance reads it, so the property still holds there — it is
/// simply held by the reducer rather than by the type, and that distinction is
/// stated instead of glossed.
///
/// An inventory or a request that arrives with no route back is dropped with a
/// trace. There is nothing else honest to do with "tell me what you have" when
/// there is no-one to tell.
pub(super) async fn reduce(
    state: &Arc<NetworkState>,
    exchange: DurableSemanticExchange,
    reply: Option<&LogicalSessionOperation>,
) {
    let kind = exchange.kind_name();
    trace!(
        source = reply
            .map(|route| route.owner().device_id())
            .unwrap_or(NO_SESSION),
        kind,
        "reducing a durable semantic exchange"
    );
    match exchange.exchange {
        // Signed facts. No route, by construction — these three arms cannot
        // name `reply`, so the compiler is what keeps a courier out of the
        // decision.
        Exchange::SignedFact(SignedFact::Propose(m)) => governance::on_propose(state, m).await,
        Exchange::SignedFact(SignedFact::Ack(m)) => governance::on_ack(state, m).await,
        Exchange::SignedFact(SignedFact::Split(m)) => governance::on_split(state, m).await,
        // The bundle does see a device id off the route — as a label for the
        // trace and the log, scoped to this session, and never as a reason to
        // accept or reject anything. `on_roster_entries` verifies the logs from
        // genesis; `source` does not appear in that decision.
        Exchange::FactBundle(m) => {
            let source = reply
                .map(|route| route.owner().device_id())
                .unwrap_or(NO_SESSION);
            governance::on_roster_entries(state, source, m).await
        }
        // Comparisons and questions. These are the ones with somebody to answer.
        Exchange::Inventory(inventory) => {
            let Some(route) = reply else {
                trace!(
                    kind,
                    "inventory with no route back; nothing to compare against"
                );
                return;
            };
            let owner = route.owner();
            match inventory {
                Inventory::NetworkState(m) => governance::on_state_broadcast(state, owner, m).await,
                Inventory::Roster(m) => governance::on_roster_summary(state, owner, m).await,
            }
        }
        Exchange::DependencyRequest(DependencyRequest::Roster(m)) => {
            let Some(route) = reply else {
                trace!(kind, "request with no route back; nothing to answer");
                return;
            };
            let owner = route.owner();
            governance::on_roster_request(state, owner, m).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The class [`admit`] put a message in, as a comparable word.
    fn class(message: MeshMessage) -> &'static str {
        match admit(message) {
            SemanticAdmission::Durable(exchange) => match exchange.exchange {
                Exchange::SignedFact(_) => "signed_fact",
                Exchange::FactBundle(_) => "fact_bundle",
                Exchange::Inventory(_) => "inventory",
                Exchange::DependencyRequest(_) => "dependency_request",
            },
            SemanticAdmission::NotDurable(_) => "not_durable",
        }
    }

    /// **Every durable message is admitted here, into the class it actually
    /// belongs to, and nothing else is admitted at all.**
    ///
    /// The classification half is the correction. All seven used to be called
    /// facts, which is why the reducer could take a session token for all seven
    /// and nobody noticed that four of them were being handed one they had no
    /// business needing. An inventory is a comparison and a request is a
    /// question; neither is something to content-address, store or project, and
    /// the two that are carry their own signatures.
    ///
    /// The closure half is the other's non-vacuity: a classifier that admitted
    /// everything would pass the first alone, and one that admitted nothing
    /// would pass the second.
    #[test]
    fn the_durable_set_is_classified_by_what_authenticates_each_message() {
        let expected = [
            (
                "signed_fact",
                MeshMessage::NetworkStatePropose(NetworkStateProposeMessage {
                    proposal_id: String::new(),
                    variant: crate::network_state::TransitionVariant::KindChange {
                        to: crate::network_state::NetworkKind::Closed,
                    },
                    proposer: String::new(),
                    created_at: 0,
                    signature: String::new(),
                }),
            ),
            (
                "signed_fact",
                MeshMessage::NetworkStateAck(NetworkStateAckMessage {
                    proposal_id: String::new(),
                    signer: String::new(),
                    decision: crate::protocol::AckDecision::Sign,
                    at: 0,
                    signature: String::new(),
                }),
            ),
            (
                "signed_fact",
                MeshMessage::NetworkStateSplit(NetworkStateSplitMessage {
                    parent_proposal_id: String::new(),
                    new_network_id: String::new(),
                    members: Vec::new(),
                    proposer: String::new(),
                    at: 0,
                    signature: String::new(),
                }),
            ),
            (
                "fact_bundle",
                MeshMessage::RosterEntries(RosterEntriesMessage {
                    entries: Vec::new(),
                    transitions: Vec::new(),
                    member_log: Vec::new(),
                }),
            ),
            (
                "inventory",
                MeshMessage::NetworkState(NetworkStateBroadcast {
                    kind: crate::network_state::NetworkKind::Closed,
                    transitions_count: 0,
                    member_log_count: 0,
                    roster_root: String::new(),
                }),
            ),
            (
                "inventory",
                MeshMessage::RosterSummary(RosterSummaryMessage {
                    root: String::new(),
                    count: 0,
                    last_edit_ts: 0,
                }),
            ),
            (
                "dependency_request",
                MeshMessage::RosterRequest(RosterRequestMessage::default()),
            ),
        ];
        for (want, message) in expected {
            assert_eq!(
                class(message),
                want,
                "a durable message must reach the Semantic Node in the class \
                 that says what authenticates it"
            );
        }

        // A transport control and an application frame: neither is a durable
        // exchange, and both must come back untouched for the engine's own match.
        assert_eq!(
            class(MeshMessage::SessionControl(
                crate::protocol::SessionControl::Depart
            )),
            "not_durable",
            "a session-lifecycle control is the Peer Session owner's, not the \
             Semantic Node's"
        );
        assert_eq!(
            class(MeshMessage::Channel {
                channel: "chat".into(),
                payload: serde_json::Value::Null,
            }),
            "not_durable",
            "an application frame carries no durable content"
        );
    }
}
