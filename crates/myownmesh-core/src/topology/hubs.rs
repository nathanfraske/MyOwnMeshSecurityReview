//! Hub-tier topology: a small set of config-named hubs full-meshes
//! among itself; every other member (a spoke) connects to a few of the
//! hubs and reaches the rest of the network through them.
//!
//! Spoke→hub assignment is **rendezvous hashing** over `(spoke, hub)`:
//! every node computes the same ranking with no coordination, and a
//! hub joining or leaving only moves the spokes that ranked it —
//! nobody else re-homes. Redundancy is the top-`spoke_redundancy`
//! hubs of the ranking.
//!
//! Connection counts: a spoke holds `spoke_redundancy` connections; a
//! hub holds (other hubs + the spokes that ranked it). Nothing pays
//! N². Broadcasts flood spoke → its hubs → all hubs → their spokes
//! with per-node dedup; directed frames route the same path (see
//! `engine::routing`).

use std::collections::{BTreeSet, HashSet};

use sha2::{Digest, Sha256};

use super::Topology;
use crate::identity::DeviceId;
use crate::signing;

#[derive(Debug, Clone)]
pub struct HubsSelector {
    pub hubs: Vec<DeviceId>,
    /// How many hubs each spoke connects to (≥ 1; clamped to the hub
    /// count at evaluation time).
    pub spoke_redundancy: u32,
}

impl HubsSelector {
    fn redundancy_limit(&self) -> usize {
        usize::try_from(self.spoke_redundancy).unwrap_or(usize::MAX)
    }

    fn is_hub(&self, id: &str) -> bool {
        let id = signing::pubkey_part(id);
        self.hubs.iter().any(|h| signing::pubkey_part(h) == id)
    }

    fn unique_hub_count(&self) -> usize {
        self.hubs
            .iter()
            .enumerate()
            .filter(|(index, hub)| {
                let key = signing::pubkey_part(hub);
                !self.hubs[..*index]
                    .iter()
                    .any(|previous| signing::pubkey_part(previous) == key)
            })
            .count()
    }

    /// Return a configured hub's zero-based rendezvous rank without
    /// materializing the complete ranking. Duplicate configured spellings
    /// are ignored at their first canonical pubkey occurrence.
    fn rendezvous_rank(&self, spoke: &str, hub: &str) -> Option<usize> {
        let hub = signing::pubkey_part(hub);
        let target_score = rendezvous_score(spoke, hub);
        let mut rank = 0usize;
        let mut found = false;
        for (index, configured) in self.hubs.iter().enumerate() {
            let candidate = signing::pubkey_part(configured);
            if self.hubs[..index]
                .iter()
                .any(|previous| signing::pubkey_part(previous) == candidate)
            {
                continue;
            }
            if candidate == hub {
                found = true;
                continue;
            }
            let candidate_score = rendezvous_score(spoke, candidate);
            if candidate_score > target_score
                || (candidate_score == target_score && candidate < hub)
            {
                rank = rank.saturating_add(1);
            }
        }
        found.then_some(rank)
    }

    /// The hubs `spoke` should attach to: the top-`spoke_redundancy`
    /// of the rendezvous ranking. Pure and total — defined even for
    /// ids nobody has seen yet, which is what keeps every node's
    /// answer identical during membership churn.
    fn ranked_hubs_for(&self, spoke: &str) -> Vec<String> {
        let spoke = signing::pubkey_part(spoke);
        let unique_hubs: BTreeSet<String> = self
            .hubs
            .iter()
            .map(|hub| signing::pubkey_part(hub).to_string())
            .collect();
        let mut ranked: Vec<(u64, String)> = unique_hubs
            .into_iter()
            .map(|hub| (rendezvous_score(spoke, &hub), hub))
            .collect();
        // Highest score first; the hub id breaks exact ties so the
        // order is total.
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        ranked.into_iter().map(|(_, hub)| hub).collect()
    }

    fn hubs_for(&self, spoke: &str) -> Vec<String> {
        self.ranked_hubs_for(spoke)
            .into_iter()
            .take(self.spoke_redundancy.max(1) as usize)
            .collect()
    }

    fn next_hops_with_limit(
        &self,
        self_id: &str,
        dest: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        let dest_key = signing::pubkey_part(dest);
        let source_key = signing::pubkey_part(self_id);
        let target = limit.min(self.redundancy_limit());
        if target == 0 {
            return Vec::new();
        }

        // Retain only the best target candidates. An observed peer that
        // cannot enter this bounded set needs no retained state; duplicate
        // observations of a retained canonical pubkey only update its
        // deterministic spelling.
        let preferred_prefix = if self.is_hub(dest_key) {
            1
        } else {
            self.redundancy_limit().min(self.unique_hub_count())
        };
        let destination_is_hub = self.is_hub(dest_key);
        let mut candidates = Vec::<RankedCandidate>::new();
        for peer in connected {
            let key = signing::pubkey_part(peer);
            if key == source_key {
                continue;
            }
            let Some(rank) = self.rendezvous_rank(dest_key, key) else {
                continue;
            };
            let priority = if destination_is_hub {
                if key == dest_key {
                    0
                } else {
                    1usize.saturating_add(rank)
                }
            } else if rank < self.redundancy_limit() {
                rank
            } else {
                preferred_prefix.saturating_add(rank)
            };
            let candidate = RankedCandidate {
                priority,
                key: key.to_string(),
                peer: peer.clone(),
            };
            if let Some(existing) = candidates.iter_mut().find(|item| item.key == candidate.key) {
                if candidate.peer < existing.peer {
                    existing.peer = candidate.peer;
                }
                continue;
            }
            candidates.push(candidate);
            candidates.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.key.cmp(&b.key)));
            if candidates.len() > target {
                candidates.pop();
            }
        }
        candidates
            .into_iter()
            .map(|candidate| candidate.peer)
            .collect()
    }
}

/// The rendezvous (highest-random-weight) score of a `(spoke, hub)`
/// pair: the first 8 bytes of `SHA-256(spoke ‖ ":" ‖ hub)`.
fn rendezvous_score(spoke: &str, hub: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(spoke.as_bytes());
    hasher.update(b":");
    hasher.update(hub.as_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

impl Topology for HubsSelector {
    fn select_preferred(&self, self_id: &str, peer_ids: &[String]) -> HashSet<String> {
        // Frames flow exactly where connections exist.
        peer_ids
            .iter()
            .filter(|p| self.edge(self_id, p, peer_ids))
            .cloned()
            .collect()
    }

    fn edge(&self, a: &str, b: &str, _all: &[String]) -> bool {
        match (self.is_hub(a), self.is_hub(b)) {
            // The hub tier is a full mesh among itself.
            (true, true) => true,
            // A spoke connects to exactly the hubs its ranking names.
            (false, true) => self
                .hubs_for(a)
                .iter()
                .any(|h| h == signing::pubkey_part(b)),
            (true, false) => self
                .hubs_for(b)
                .iter()
                .any(|h| h == signing::pubkey_part(a)),
            // Spokes never connect to each other.
            (false, false) => false,
        }
    }

    fn prunes(&self) -> bool {
        true
    }

    fn forwards(&self, self_id: &str, _all: &[String]) -> bool {
        self.is_hub(self_id)
    }

    fn next_hops(
        &self,
        self_id: &str,
        dest: &str,
        connected: &[String],
        limit: usize,
    ) -> Vec<String> {
        self.next_hops_with_limit(self_id, dest, connected, limit)
    }

    fn flood_ttl(&self) -> u8 {
        // spoke → hub → hub → spoke, plus one spare for a transient.
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(hubs: &[&str], redundancy: u32) -> HubsSelector {
        HubsSelector {
            hubs: hubs.iter().map(|h| h.to_string()).collect(),
            spoke_redundancy: redundancy,
        }
    }

    fn s(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn hubs_full_mesh_and_spokes_attach_to_ranked_hubs() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 2);
        let all: Vec<String> = ["hub-a", "hub-b", "hub-c", "s1", "s2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(t.edge("hub-a", "hub-b", &all), "hub tier is a full mesh");
        assert!(!t.edge("s1", "s2", &all), "spokes never interconnect");
        // A spoke has exactly `redundancy` hub edges.
        let hub_edges = ["hub-a", "hub-b", "hub-c"]
            .iter()
            .filter(|h| t.edge("s1", h, &all))
            .count();
        assert_eq!(hub_edges, 2);
    }

    #[test]
    fn edge_is_symmetric_and_deterministic() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 1);
        let all: Vec<String> = vec![];
        for spoke in ["s1", "s2", "s3", "s4"] {
            for hub in ["hub-a", "hub-b", "hub-c"] {
                assert_eq!(
                    t.edge(spoke, hub, &all),
                    t.edge(hub, spoke, &all),
                    "edge({spoke},{hub}) must be symmetric"
                );
            }
            assert_eq!(t.hubs_for(spoke), t.hubs_for(spoke), "stable ranking");
        }
    }

    #[test]
    fn hub_departure_only_rehomes_its_own_spokes() {
        // Rendezvous property: removing hub-c changes assignments only
        // for spokes whose top pick was hub-c.
        let with_c = sel(&["hub-a", "hub-b", "hub-c"], 1);
        let without_c = sel(&["hub-a", "hub-b"], 1);
        for i in 0..64 {
            let spoke = format!("spoke-{i}");
            let before = with_c.hubs_for(&spoke);
            let after = without_c.hubs_for(&spoke);
            if before[0] != "hub-c" {
                assert_eq!(before, after, "{spoke} must not re-home");
            }
        }
    }

    #[test]
    fn redundancy_clamps_to_hub_count() {
        let t = sel(&["hub-a", "hub-b"], 5);
        assert_eq!(
            t.hubs_for("s1").len(),
            2,
            "can't attach to more hubs than exist"
        );
    }

    #[test]
    fn spoke_routes_via_destinations_hubs_first() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 1);
        // s2's home hub, per the same ranking every node computes.
        let s2_hub = t.hubs_for("s2")[0].clone();
        // A hub connected to everything routes an s2-bound frame to
        // s2's home hub when it isn't s2's neighbor itself.
        let connected: Vec<String> = ["hub-a", "hub-b", "hub-c"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let hops = t.next_hops("hub-x-not-real", "s2", &connected, 1);
        assert_eq!(hops, vec![s2_hub]);
        // With none of the destination's hubs connected, any hub will do.
        let connected: Vec<String> = vec!["hub-a".into()];
        let t2 = sel(&["hub-a", "hub-b"], 1);
        let hops = t2.next_hops("s1", "s2", &connected, 1);
        assert!(hops == vec!["hub-a".to_string()] || hops.is_empty());
    }

    #[test]
    fn only_hubs_forward() {
        let t = sel(&["hub-a"], 1);
        assert!(t.forwards("hub-a", &[]));
        assert!(!t.forwards("s1", &[]));
    }

    #[test]
    fn preferred_matches_edges() {
        let t = sel(&["hub-a", "hub-b"], 1);
        let peers: Vec<String> = ["hub-a", "hub-b", "s2", "s3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let picks = t.select_preferred("s1", &peers);
        let expected: HashSet<String> = peers
            .iter()
            .filter(|p| t.edge("s1", p, &peers))
            .cloned()
            .collect();
        assert_eq!(picks, expected);
    }

    #[test]
    fn next_hops_are_bounded_stable_and_self_free_with_duplicate_input() {
        let t = sel(&["hub-a", "hub-b", "hub-c"], 2);
        let first = vec![
            "hub-a".to_string(),
            "hub-a".to_string(),
            "hub-b".to_string(),
            "spoke".to_string(),
        ];
        let mut reordered = first.clone();
        reordered.reverse();
        let a = t.next_hops("spoke", "destination", &first, 2);
        let b = t.next_hops("spoke", "destination", &reordered, 2);
        assert_eq!(a, b, "connected input order must not affect failover");
        assert!(a.len() <= 2);
        assert!(a.iter().all(|hop| signing::pubkey_part(hop) != "spoke"));
        assert_eq!(
            a.iter()
                .map(|hop| signing::pubkey_part(hop))
                .collect::<BTreeSet<_>>()
                .len(),
            a.len()
        );
    }

    #[test]
    fn next_hops_respects_explicit_limit_without_growing_with_connected_input() {
        let t = sel(&["hub-a", "hub-b", "hub-c", "hub-d"], 3);
        let connected = s(&["hub-a", "hub-b", "hub-c", "hub-d", "hub-a-display", "spoke"]);
        let one = t.next_hops_with_limit("spoke", "destination", &connected, 1);
        assert_eq!(one.len(), 1);
        assert!(one.iter().all(|hop| signing::pubkey_part(hop) != "spoke"));
        let zero = t.next_hops_with_limit("spoke", "destination", &connected, 0);
        assert!(zero.is_empty());
        let over = t.next_hops_with_limit("spoke", "destination", &connected, 99);
        assert!(over.len() <= 3);
    }
}

struct RankedCandidate {
    priority: usize,
    key: String,
    peer: String,
}
