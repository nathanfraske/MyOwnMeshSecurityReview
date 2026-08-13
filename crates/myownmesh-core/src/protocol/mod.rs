//! Wire protocol for peer connections.
//!
//! Every frame on the WebRTC data channel is one of the variants
//! below, serialized as a JSON object with a `kind` discriminator.
//! The pre-active phases are:
//!
//!   1. `hello` — each side announces its claimed Device ID, a random
//!      nonce, a verification code, and its supported feature ids.
//!      Sent immediately on channel open. It carries no application
//!      capability advertisement: a Hello is admitted before any
//!      session exists, so a blob here would be attacker-controlled
//!      application metadata arriving ahead of the boundary that
//!      admits application payload. See [`handshake::HelloMessage`].
//!   2. `auth_response` — each side returns its proof over the one
//!      domain-separated endpoint-auth transcript. That transcript binds the
//!      mesh context and profile, signer role, both Device IDs, both fresh
//!      contributions, and both certificate fingerprints. Receiving a valid
//!      proof authenticates the peer's key while binding it to this exact
//!      endpoint-auth context; a nonce-only signature is not accepted.
//!
//! After mutual auth verification, the receiver side either
//! auto-accepts (peer is in the roster) or queues the request for
//! user approval. The receiver sends `approve` once cleared; the
//! connection becomes ACTIVE on both sides at that point.
//!
//! Post-active, peers exchange:
//!   - `capabilities_update` whenever local capabilities change
//!   - `shelve` / `unshelve` to negotiate topology
//!   - `ping` / `pong` for keepalive
//!   - `rpc_request` / `rpc_response` / `rpc_stream_chunk` /
//!     `rpc_stream_end` for embedder-defined request/response calls
//!   - Application data over typed user-defined channels (see
//!     [`crate::events`])
//!
//! The frame set is closed. A receiver getting a `kind` this build
//! does not implement refuses it — the frame fails to deserialize and
//! reaches no handler — so there is no revision-tolerance to rely on.
//! There is no optional feature negotiation or mixed-version mode in this
//! alpha. `hello.features` carries only the closed endpoint-authentication
//! profile required before any post-active frame is admitted.

pub mod features;
pub mod governance;
pub mod handshake;
pub mod keepalive;
pub mod rpc;
pub mod topology;

pub use features::{Feature, ADVERTISED_FEATURES};
pub use governance::{
    AckDecision, NetworkStateAckMessage, NetworkStateBroadcast, NetworkStateProposeMessage,
    NetworkStateSplitMessage, RosterEntriesMessage, RosterEntry, RosterRequestMessage,
    RosterSummaryMessage,
};
pub use handshake::{
    ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage, DENY_REASON_EVICTED,
};
pub use keepalive::{PingMessage, PongMessage};
pub use rpc::{
    CapabilitiesUpdateMessage, CapabilityAdvert, RpcRequestMessage, RpcResponseMessage,
    RpcStreamChunkMessage, RpcStreamEndMessage,
};
pub use topology::{ShelveMessage, UnshelveMessage};

use serde::{Deserialize, Serialize};

/// First-stage classification obtained from the small leading JSON tag only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameAdmission {
    Protocol,
    Application,
}

/// What this side owes when a frame of this kind cannot be carried.
///
/// Read from the same bounded leading tag as [`FrameAdmission`], and read there
/// for the same reason: the path that most needs the answer is the one where the
/// frame was *never decoded*. A frame the resource owner will not fund is
/// refused before its bytes are parsed, so a receiver that wants to distinguish
/// "lost one datagram" from "stranded a caller" cannot ask the decoded message —
/// asking it would mean parsing exactly the payload the refusal exists to avoid
/// parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailurePolicy {
    /// Dropping this frame settles nothing and strands nobody. Nothing local is
    /// waiting on it, and the sender's contract for it is best-effort, so the
    /// loss is the whole of the damage and the session carries on.
    DropFrame,
    /// This frame is the completion something local is waiting for, or is
    /// itself a delivery contract. Dropping it leaves that waiter with nothing
    /// else coming — the peer has already sent its one answer — so the session
    /// that could not carry it ends, and the ending is what resolves the waiter.
    EndSession,
}

/// A frame's admission phase and its failure policy, both from the leading tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassifiedFrame {
    pub(crate) admission: FrameAdmission,
    pub(crate) on_failure: FailurePolicy,
}

/// Parse only the canonical leading `kind` envelope emitted by this protocol.
///
/// Mixed-version support is intentionally absent. A peer that reorders the tag
/// behind attacker-controlled payload is malformed rather than making the
/// classifier scan or deserialize that payload before admission.
///
/// **The failure policy defaults to [`FailurePolicy::EndSession`]**, including
/// for a kind that is in the closed set but not named below and for one that is
/// not in it at all. That is the fail-closed direction here: ending a session
/// this side could not serve is the existing behaviour of every refusal site, so
/// an unnamed kind keeps it, and only a kind proved to strand nobody is
/// downgraded. A default of `DropFrame` would silently make some future
/// completion-bearing variant lose its caller.
pub(crate) fn classify_frame(bytes: &[u8]) -> Option<ClassifiedFrame> {
    const PREFIX: &[u8] = br#"{"kind":""#;
    const MAX_KIND_BYTES: usize = 32;
    let rest = bytes.strip_prefix(PREFIX)?;
    let end = rest
        .iter()
        .take(MAX_KIND_BYTES + 1)
        .position(|byte| *byte == b'"')?;
    if end > MAX_KIND_BYTES {
        return None;
    }
    let kind = std::str::from_utf8(&rest[..end]).ok()?;
    Some(match kind {
        // The four pre-admission frames. Their policy is never read: they are
        // handled before any session exists, so there is none to end. Named
        // `EndSession` anyway rather than given a third variant meaning
        // "inapplicable", which would be a value every consumer had to handle
        // and no consumer could act on.
        "hello" | "auth_response" | "approve" | "deny" => ClassifiedFrame {
            admission: FrameAdmission::Protocol,
            on_failure: FailurePolicy::EndSession,
        },
        // The one best-effort application delivery. A plain `Channel` frame
        // carries no sequence, is acknowledged by nobody, and resolves no local
        // wait: `MeshMessage::Channel` is delivered to whatever subscribers
        // exist and forgotten. Its acknowledged counterpart is `ChannelSeq`,
        // which is *not* named here — a sender retains that one until it is
        // acked, so losing it silently is a hole in the contract this side
        // publishes.
        //
        // This is the kind a peer can make expensive at will, and so the one a
        // peer could otherwise use to end a session on demand by sending
        // payload the owner will not fund. Backpressure is not a reason to
        // destroy a session that is working.
        "channel" => ClassifiedFrame {
            admission: FrameAdmission::Application,
            on_failure: FailurePolicy::DropFrame,
        },
        _ => ClassifiedFrame {
            admission: FrameAdmission::Application,
            on_failure: FailurePolicy::EndSession,
        },
    })
}

/// Tagged union of every wire frame the mesh transport carries.
///
/// The set is closed. There is no catch-all variant and no
/// `serde(other)`, so a frame whose `kind` is not one of these fails
/// to deserialize and is refused before any handler sees it. That is
/// the point rather than an omission: tolerating a kind this build
/// does not implement is mixed-version operation, which this protocol
/// no longer offers. Frames are discrete, so refusing one costs
/// nothing but that frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshMessage {
    Hello(HelloMessage),
    AuthResponse(AuthResponseMessage),
    Approve(ApproveMessage),
    Deny(DenyMessage),
    Ping(PingMessage),
    Pong(PongMessage),
    CapabilitiesUpdate(CapabilitiesUpdateMessage),
    Shelve(ShelveMessage),
    Unshelve(UnshelveMessage),
    RpcRequest(RpcRequestMessage),
    RpcResponse(RpcResponseMessage),
    RpcStreamChunk(RpcStreamChunkMessage),
    RpcStreamEnd(RpcStreamEndMessage),

    // -- closed-network governance --
    /// Sender's snapshot of the network's governance state.
    /// Broadcast on ACTIVE; receivers compare against their own to
    /// detect drift.
    NetworkState(NetworkStateBroadcast),
    /// In-flight transition awaiting signatures. The proposer signs
    /// at issue time; co-signers respond with `NetworkStateAck`.
    NetworkStatePropose(NetworkStateProposeMessage),
    /// Sign-or-deny response to a `NetworkStatePropose`.
    NetworkStateAck(NetworkStateAckMessage),
    /// Proposer-initiated split fallback after the consent timeout
    /// expires on a stuck close. Spawns a derived closed network
    /// containing the signers the proposer had so far.
    NetworkStateSplit(NetworkStateSplitMessage),

    // -- roster gossip --
    /// Merkle-root summary of the sender's roster. Triggers a
    /// `RosterRequest` from receivers whose root disagrees.
    RosterSummary(RosterSummaryMessage),
    /// "Send me the entries I'm missing." Carried alone on a
    /// targeted reply to a `RosterSummary`.
    RosterRequest(RosterRequestMessage),
    /// Roster entries the responder is sharing. Receivers verify
    /// each entry's authority chain before merging.
    RosterEntries(RosterEntriesMessage),

    /// Application payload on a user-defined typed channel. The
    /// `channel` name is the embedder's identifier; `payload` is the
    /// raw serialized message body. Receivers route to the matching
    /// `Channel<T>` registration or discard.
    Channel {
        channel: String,
        /// Opaque to the mesh — embedders decide their own framing.
        /// `serde_json::Value` rather than `Bytes` so the entire
        /// frame stays JSON-encodable; embedders wanting binary
        /// efficiency can base64-encode into a string field.
        payload: serde_json::Value,
    },

    // -- reliable channel delivery --
    /// A channel frame under the acknowledged-delivery contract: one
    /// entry of the sender's per-session reliable stream. `stream` is
    /// minted once per promoted session (a fresh session = a fresh
    /// stream) so the receiver can tell a retransmit from a reset; `seq`
    /// is strictly increasing within a stream. Receivers deliver exactly
    /// once (dropping seqs at or below their high-water mark), then
    /// acknowledge cumulatively with [`Self::ChannelAck`]. Senders retain
    /// each entry for the life of the session that queued it, until it is
    /// acked or that session ends. See `engine::reliable`.
    ChannelSeq {
        stream: u64,
        seq: u64,
        channel: String,
        payload: serde_json::Value,
    },
    /// Cumulative acknowledgement for [`Self::ChannelSeq`]: every entry
    /// of `stream` with `seq <= up_to` has been delivered to the
    /// receiver's channel router.
    ChannelAck {
        stream: u64,
        up_to: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_leading_tag_classifies_without_parsing_application_payload() {
        // Every payload below is unparseable JSON, and every answer is
        // nonetheless exact: the classifier reads the tag and stops. That is
        // the property both fields depend on, since the frame whose policy
        // matters most is the one whose bytes are never decoded.
        assert_eq!(
            classify_frame(br#"{"kind":"hello","payload":[}}"#),
            Some(ClassifiedFrame {
                admission: FrameAdmission::Protocol,
                on_failure: FailurePolicy::EndSession,
            })
        );
        assert_eq!(
            classify_frame(br#"{"kind":"channel","payload":[}}"#),
            Some(ClassifiedFrame {
                admission: FrameAdmission::Application,
                on_failure: FailurePolicy::DropFrame,
            })
        );
        assert_eq!(classify_frame(br#"{"payload":[],"kind":"hello"}"#), None);
    }

    /// Only the best-effort delivery is droppable, and the acknowledged one is
    /// not.
    ///
    /// The discrimination the policy exists for, at the level it is decided.
    /// `channel` and `channel_seq` share a prefix, a shape and a payload field;
    /// they differ in that a `ChannelSeq` sender retains its frame until this
    /// side acknowledges it. A policy that read the shape rather than the tag —
    /// or that matched on a prefix — would give both the same answer, and one of
    /// those answers is a silent hole in an acknowledged-delivery contract.
    #[test]
    fn only_the_best_effort_channel_frame_is_droppable() {
        let policy = |raw: &str| {
            classify_frame(raw.as_bytes())
                .expect("a canonical envelope classifies")
                .on_failure
        };
        assert_eq!(
            policy(r#"{"kind":"channel","x":1}"#),
            FailurePolicy::DropFrame
        );
        for completion_bearing in [
            r#"{"kind":"channel_seq","x":1}"#,
            r#"{"kind":"channel_ack","x":1}"#,
            r#"{"kind":"rpc_response","x":1}"#,
            r#"{"kind":"rpc_stream_chunk","x":1}"#,
            r#"{"kind":"rpc_stream_end","x":1}"#,
        ] {
            assert_eq!(
                policy(completion_bearing),
                FailurePolicy::EndSession,
                "a frame something local is waiting on is never silently lost: \
                 {completion_bearing}"
            );
        }
        // And the fail-closed default: a kind this build does not implement is
        // not a licence to drop frames quietly.
        assert_eq!(
            policy(r#"{"kind":"definitely_not_a_real_kind","x":1}"#),
            FailurePolicy::EndSession
        );
    }

    #[test]
    fn unknown_kind_is_refused() {
        let raw = r#"{"kind":"definitely_not_a_real_kind","whatever":1}"#;
        assert!(serde_json::from_str::<MeshMessage>(raw).is_err());
    }

    #[test]
    fn hello_round_trips() {
        let msg = MeshMessage::Hello(HelloMessage {
            protocol: crate::PROTOCOL_VERSION,
            device_id: "peer1".into(),
            label: "Laptop".into(),
            nonce: "noncexyz".into(),
            verification_code: "abc123".into(),
            features: vec![Feature::ENDPOINT_AUTH_V1.into()],
        });
        let s = serde_json::to_string(&msg).unwrap();
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::Hello(h) => {
                assert_eq!(h.device_id, "peer1");
                assert_eq!(h.nonce, "noncexyz");
            }
            _ => panic!("did not round-trip as Hello"),
        }
    }

    #[test]
    fn network_state_broadcast_round_trips() {
        use crate::network_state::NetworkKind;
        let msg = MeshMessage::NetworkState(NetworkStateBroadcast {
            kind: NetworkKind::Closed,
            transitions_count: 4,
            member_log_count: 2,
            roster_root: "abcdefghij".into(),
        });
        let s = serde_json::to_string(&msg).unwrap();
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::NetworkState(b) => {
                assert_eq!(b.kind, NetworkKind::Closed);
                assert_eq!(b.transitions_count, 4);
                assert_eq!(b.member_log_count, 2);
                assert_eq!(b.roster_root, "abcdefghij");
            }
            _ => panic!("did not round-trip as NetworkState"),
        }
    }

    #[test]
    fn network_state_kind_discriminator_is_snake_case() {
        // Wire-level kind tag must be snake_case so the JS GUI's
        // existing dispatch tables don't need a special case for
        // these. Pinning here so a future #[serde(rename_all)]
        // tweak doesn't silently break interop.
        let msg = MeshMessage::NetworkState(NetworkStateBroadcast {
            kind: crate::network_state::NetworkKind::Open,
            transitions_count: 0,
            member_log_count: 0,
            roster_root: "x".into(),
        });
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""kind":"network_state""#));
    }

    #[test]
    fn ack_decision_round_trips() {
        let msg = MeshMessage::NetworkStateAck(NetworkStateAckMessage {
            proposal_id: "prop_x".into(),
            signer: "alice".into(),
            decision: AckDecision::Deny,
            at: 42,
            signature: "sig".into(),
        });
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""decision":"deny""#));
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::NetworkStateAck(a) => {
                assert_eq!(a.decision, AckDecision::Deny);
                assert_eq!(a.signer, "alice");
            }
            _ => panic!("did not round-trip as NetworkStateAck"),
        }
    }

    #[test]
    fn roster_summary_round_trips() {
        let msg = MeshMessage::RosterSummary(RosterSummaryMessage {
            root: "merkle_root".into(),
            count: 3,
            last_edit_ts: 1700000000,
        });
        let s = serde_json::to_string(&msg).unwrap();
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, MeshMessage::RosterSummary(_)));
    }

    #[test]
    fn roster_request_defaults_clean() {
        // include_all + subtree_hashes are #[serde(default)] so an
        // empty request frame parses without per-field nulls. v1
        // peers send `{ "kind": "roster_request" }` literally.
        let raw = r#"{"kind":"roster_request"}"#;
        let msg: MeshMessage = serde_json::from_str(raw).unwrap();
        match msg {
            MeshMessage::RosterRequest(r) => {
                assert!(!r.include_all);
                assert!(r.subtree_hashes.is_empty());
            }
            _ => panic!("did not parse as RosterRequest"),
        }
    }

    #[test]
    fn a_governance_kind_this_build_implements_decodes_and_a_future_one_is_refused() {
        // A supported peer decodes this exact frame.
        let raw = r#"{"kind":"network_state_propose","proposal_id":"x","variant":{"kind":"role_grant","target":"a","role":"member"},"proposer":"b","created_at":0,"signature":"s"}"#;
        let msg: MeshMessage = serde_json::from_str(raw).unwrap();
        assert!(matches!(msg, MeshMessage::NetworkStatePropose(_)));
        // The inverse fails closed: there is no mixed-version live fallback.
        let raw_future = r#"{"kind":"network_state_some_future_thing","whatever":1}"#;
        assert!(serde_json::from_str::<MeshMessage>(raw_future).is_err());
    }
}
