//! Tier 6 — user-driven configuration edits. Decides, when the user
//! edits a network's config at runtime, whether the change can be
//! applied in place ([`apply_hot`]) or genuinely needs the transport
//! torn down and rebuilt ([`requires_restart`], orchestrated by the
//! bin's serve loop — the engine task stops cleanly via Shutdown).
//!
//! Why STUN/TURN are *not* a restart
//! ---------------------------------
//! A full restart drops every live peer, including healthy *direct*
//! WebRTC links. That's a sledgehammer for STUN/TURN: those servers
//! only matter while *gathering candidates for a new connection* —
//! an already-connected data channel never touches them again. And
//! [`super::ensure_peer_session`] reads `stun_servers` / `turn_servers`
//! fresh from `state.config` every time it opens a peer, so a hot
//! update reaches every *future* connection (and every reconnect)
//! without disturbing the ones already up. So a STUN/TURN edit —
//! including a venue rotating its time-limited TURN credentials, which
//! otherwise churned the link on every refresh — applies in place.
//!
//! What still needs a restart
//! --------------------------
//! - `network_id`: a different wire-level network entirely (different
//!   room, identity context) — nothing to preserve.
//! - `signaling`: the Nostr driver binds its relay set at start and has
//!   no in-place "switch relays" path (the bridge's outbound receiver is
//!   taken once), so changing relays means recreating the driver. Rare —
//!   venues keep a stable relay set and rotate only credentials.

use std::sync::Arc;

use crate::config::NetworkConfig;
use crate::error::{Error, Result};

use super::state::NetworkState;

/// Returns `true` when the new config differs from the current one in a
/// way that can't be applied to a running network — `network_id`
/// (a different network), `signaling` (the relay set the Nostr driver
/// is bound to), `closed_relay` (the provider-backed runtime profile), or
/// any construction-time scheduler/broadcast capacity. STUN/TURN, topology,
/// label, roster, and auto-approve are all applied in place by [`apply_hot`]
/// without dropping peers.
/// Changes to `closed_relay` require restart because its provider-backed
/// runtime profile is fixed when `NetworkState` is constructed.
pub fn requires_restart(current: &NetworkConfig, next: &NetworkConfig) -> bool {
    current.network_id != next.network_id
        || current.signaling != next.signaling
        || current.closed_relay != next.closed_relay
        || current.scheduler != next.scheduler
        || current.event_capacity != next.event_capacity
        || current.connection_trace_capacity != next.connection_trace_capacity
}

/// Apply the hot-reloadable subset of config without tearing down
/// sessions: STUN/TURN servers (picked up by the next connection),
/// topology, label, roster path, and auto-approve. Anything left to a
/// restart is gated by [`requires_restart`].
pub fn apply_hot(state: &Arc<NetworkState>, next: NetworkConfig) -> Result<()> {
    {
        let mut cfg = state.config.write();
        if requires_restart(&cfg, &next) {
            return Err(Error::Config(
                "network config change requires an exact runtime replacement".into(),
            ));
        }
        cfg.label = next.label;
        cfg.topology = next.topology.clone();
        cfg.auto_approve = next.auto_approve;
        cfg.roster_path = next.roster_path;
        // ICE servers are read fresh per `open_peer`, so updating them
        // here is enough — live peers keep their current connection and
        // the next connect/reconnect uses the new servers.
        cfg.stun_servers = next.stun_servers;
        cfg.turn_servers = next.turn_servers;
    }
    // Topology is connector/deployment policy, not semantic authority. A
    // hot config edit updates the local runtime directly.
    let effective = next.topology;
    {
        let mut topo = state.topology.write();
        *topo = effective.clone();
    }
    {
        let mut sel = state.topology_impl.write();
        *sel = crate::topology::from_mode(&effective);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StunServer, TurnServer};

    fn base_config() -> NetworkConfig {
        NetworkConfig::from_network_id("test-id", "test-net")
    }

    #[test]
    fn stun_turn_changes_do_not_require_restart() {
        let current = base_config();
        let mut next = current.clone();
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:example.com:3478".into()],
        }];
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:example.com:3478".into()],
            username: Some("user".into()),
            credential: Some("rotated-secret".into()),
        }];
        assert!(
            !requires_restart(&current, &next),
            "STUN/TURN edits (incl. rotated credentials) must apply in place, not restart"
        );
    }

    #[test]
    fn signaling_and_network_id_changes_require_restart() {
        let current = base_config();

        let mut diff_net = current.clone();
        diff_net.network_id = "other-net".into();
        assert!(requires_restart(&current, &diff_net));

        let mut diff_sig = current.clone();
        diff_sig.signaling.servers = vec!["wss://relay.example.com".into()];
        assert!(requires_restart(&current, &diff_sig));
    }

    #[test]
    fn closed_relay_profile_changes_require_restart() {
        let current = base_config();
        let mut next = current.clone();
        next.closed_relay.enabled = !current.closed_relay.enabled;
        assert!(requires_restart(&current, &next));
    }

    #[test]
    fn construction_time_runtime_resources_require_exact_replacement() {
        let current = base_config();

        let mut scheduler = current.clone();
        scheduler.scheduler.heartbeat_interval_ms += 1;
        assert!(requires_restart(&current, &scheduler));

        let mut events = current.clone();
        events.event_capacity += 1;
        assert!(requires_restart(&current, &events));

        let mut traces = current.clone();
        traces.connection_trace_capacity += 1;
        assert!(requires_restart(&current, &traces));
    }

    #[test]
    fn label_only_hot_update_keeps_runtime_identity() {
        let state = super::super::build_test_state("reconcile-label");
        let current = state.config.read().clone();
        let mut next = current.clone();
        next.label = "updated-label".into();
        assert!(!requires_restart(&current, &next));
        let state_identity = Arc::as_ptr(&state);

        apply_hot(&state, next).expect("label-only apply_hot");

        assert_eq!(Arc::as_ptr(&state), state_identity);
        assert_eq!(state.config.read().label, "updated-label");
    }

    #[test]
    fn construction_time_change_is_refused_by_hot_path() {
        let state = super::super::build_test_state("reconcile-capacity");
        let current = state.config.read().clone();
        let mut next = current.clone();
        next.event_capacity += 1;

        assert!(apply_hot(&state, next).is_err());
        assert_eq!(state.config.read().event_capacity, current.event_capacity);
    }

    #[test]
    fn apply_hot_updates_ice_servers_in_place() {
        let state = super::super::build_test_state("reconcile-hot");
        let state_identity = Arc::as_ptr(&state);
        let mut next = state.config.read().clone();
        next.label = "updated-label".into();
        next.turn_servers = vec![TurnServer {
            urls: vec!["turn:fresh.example.com:3478".into()],
            username: Some("user".into()),
            credential: Some("fresh-secret".into()),
        }];
        next.stun_servers = vec![StunServer {
            urls: vec!["stun:fresh.example.com:3478".into()],
        }];

        apply_hot(&state, next).expect("apply_hot");

        assert_eq!(
            Arc::as_ptr(&state),
            state_identity,
            "label-only hot updates preserve the existing runtime Arc"
        );

        let cfg = state.config.read();
        assert_eq!(cfg.turn_servers.len(), 1);
        assert_eq!(
            cfg.turn_servers[0].credential.as_deref(),
            Some("fresh-secret")
        );
        assert_eq!(cfg.stun_servers[0].urls[0], "stun:fresh.example.com:3478");
    }
}
