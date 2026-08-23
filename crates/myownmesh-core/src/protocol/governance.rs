//! Governance inventory and dependency-exchange wire frames.
//!
//! These messages help peers discover which signed V4 facts they need.  They
//! are not authority: canonical governance state travels as [`crate::protocol::SignedFact`]
//! or [`crate::protocol::FactBundleMessage`], and every fact is independently
//! content-address and signature verified by the semantic reducer.

use serde::{Deserialize, Serialize};

use crate::network_state::NetworkKind;
use crate::roster::AuthorizedPeer;

/// A non-authoritative snapshot used to detect governance drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateBroadcast {
    #[serde(rename = "network_kind")]
    pub kind: NetworkKind,
    /// Number of canonical semantic heads known to the sender.
    pub fact_heads_count: u32,
    pub roster_root: String,
}

/// Merkle-root summary for roster/discovery exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterSummaryMessage {
    pub root: String,
    pub count: u32,
    pub last_edit_ts: u64,
}

/// Request for roster entries under a summary or subtree hash.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RosterRequestMessage {
    #[serde(default)]
    pub include_all: bool,
    #[serde(default)]
    pub subtree_hashes: Vec<String>,
}

/// Unsigned roster discovery data. This is an exchange response only; it is
/// never a governance fact bundle and cannot authorize membership or roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterEntriesMessage {
    pub entries: Vec<RosterEntry>,
}

/// A roster hint exchanged after a summary/request mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterEntry {
    pub device_id: String,
    pub label: String,
    pub approved_at: u64,
    pub role: crate::network_state::Role,
    #[serde(default)]
    pub granted_by: String,
}

impl From<&AuthorizedPeer> for RosterEntry {
    fn from(peer: &AuthorizedPeer) -> Self {
        Self {
            device_id: peer.device_id.clone(),
            label: peer.label.clone(),
            approved_at: peer.approved_at,
            role: peer.role,
            granted_by: String::new(),
        }
    }
}
