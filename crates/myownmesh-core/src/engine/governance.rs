//! Engine half of closed-network governance.
//!
//! Canonical governance ingress and projection.
//!
//! Signed V4 facts are admitted into the one bootstrap-bound `FactGraph`,
//! projected into compatibility snapshots, and broadcast with their exact
//! content address. Legacy proposal/ratification records remain only as a
//! read-only migration shape until the external control surface is migrated.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::events::DropReason;
use crate::network_state::{self, NetworkKind, Role, TransitionVariant};
use crate::protocol::{
    FactBundleMessage, FactInventory, FactRequest, MeshMessage, NetworkStateBroadcast,
    RosterEntriesMessage, RosterEntry, RosterRequestMessage, RosterSummaryMessage,
};
use crate::semantic::{DeviceId, FactBody, FactContent, FactId, SignedFact};

use super::connection::PeerStatus;
use super::peer_registry::{LogicalSessionOperation, PeerOwnerToken};
use super::state::NetworkState as EngineState;

// ---- helpers --------------------------------------------------------

fn canonical_device(value: &str) -> Result<DeviceId> {
    DeviceId::from_canonical_str(value)
        .map_err(|error| Error::Other(format!("noncanonical DeviceId: {error}")))
}

fn fact_body(variant: &TransitionVariant) -> Result<FactBody> {
    match variant {
        TransitionVariant::RoleGrant { target, role } => Ok(FactBody::RoleGrant {
            target: canonical_device(target)?,
            role: match role {
                Role::Member => crate::semantic::Role::Member,
                Role::Controller => crate::semantic::Role::Controller,
                Role::Owner => crate::semantic::Role::Owner,
            },
        }),
        TransitionVariant::RoleRevoke { target } => Ok(FactBody::RoleRevoke {
            target: canonical_device(target)?,
        }),
        TransitionVariant::Evict { target } => Ok(FactBody::Evict {
            target: canonical_device(target)?,
        }),
        TransitionVariant::KindChange { .. }
        | TransitionVariant::Split { .. }
        | TransitionVariant::TopologyChange { .. } => Err(Error::Other(
            "legacy transition is not a canonical V4 durable fact".into(),
        )),
    }
}

fn causal_parents(
    state: &Arc<EngineState>,
    body: &FactBody,
    mut extra: Vec<FactId>,
) -> Vec<FactId> {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    for cell in body.exclusive_cells() {
        extra.extend(graph.cell_heads(&cell));
    }
    extra.sort();
    extra.dedup();
    extra
}

fn signed_fact(
    state: &Arc<EngineState>,
    body: FactBody,
    extra_parents: Vec<FactId>,
) -> Result<SignedFact> {
    let parents = causal_parents(state, &body, extra_parents);
    SignedFact::sign(
        FactContent::new(
            body.domain(),
            state.mesh_context_id(),
            body,
            canonical_device(state.identity.public_id())?,
            parents,
        ),
        state.identity.signing_key(),
    )
    .map_err(|error| Error::Other(format!("semantic fact rejected: {error}")))
}

fn admit_authored_fact(state: &Arc<EngineState>, fact: &SignedFact) -> Result<()> {
    let graph = state.authoritative_fact_graph();
    let admission = graph
        .write()
        .admit(fact.clone())
        .map_err(|error| Error::Other(format!("semantic fact rejected: {error}")))?;
    if matches!(admission, crate::semantic::Admission::Quarantined { .. }) {
        return Err(Error::Other(
            "authored semantic fact is missing a causal parent".into(),
        ));
    }
    Ok(())
}

/// Strip the display suffix (`-XXXXX`) from a Device ID. The
/// governance store keys everything on the bare pubkey.
fn pk(device_id: &str) -> String {
    crate::signing::pubkey_part(device_id).to_string()
}

/// The single temporary live-policy projection used by every session edge.
#[cfg(test)]
pub(super) fn current_policy_admits(
    gov: &network_state::NetworkState,
    local_device_id: &str,
    remote_device_id: &str,
) -> bool {
    if gov.kind.is_open_governance() {
        return true;
    }
    gov.roles.contains_key(&pk(local_device_id)) && gov.roles.contains_key(&pk(remote_device_id))
}

/// Canonical Closed-policy admission for registry fences. The bootstrap roots
/// and the shared FactGraph are the only authority inputs; compatibility
/// NetworkState roles/logs are intentionally not consulted.
pub(super) fn canonical_policy_admits_from(
    bootstrap: &crate::semantic::VerifiedBootstrap,
    graph: &crate::semantic::FactGraph,
    local_device_id: &str,
    remote_device_id: &str,
) -> bool {
    if matches!(
        bootstrap.policy(),
        crate::semantic::VerifiedProjectPolicy::Open
    ) {
        return true;
    }
    let Ok(local) = crate::semantic::DeviceId::from_canonical_str(local_device_id) else {
        return false;
    };
    let Ok(remote) = crate::semantic::DeviceId::from_canonical_str(remote_device_id) else {
        return false;
    };
    let roots = bootstrap.authority_roots();
    let projection = graph.projection();
    let role_admits = |device: &crate::semantic::DeviceId| {
        if projection.is_stood_down(device) {
            return false;
        }
        if !roots.iter().any(|root| root == device) {
            let cell = crate::semantic::ExclusiveCell::role(device.clone());
            let Some(id) = projection.value(&cell) else {
                return false;
            };
            let Some(fact) = graph.get(&id) else {
                return false;
            };
            if !matches!(
                &fact.content.body,
                crate::semantic::FactBody::RoleGrant { target, role }
                    if target == device
                        && matches!(
                            role,
                            crate::semantic::Role::Member
                                | crate::semantic::Role::Controller
                                | crate::semantic::Role::Owner
                        )
            ) {
                return false;
            }
        }
        let membership = crate::semantic::ExclusiveCell::membership(device.clone());
        if projection.is_conflicted(&membership) {
            return false;
        }
        projection
            .value(&membership)
            .and_then(|id| graph.get(&id))
            .is_none_or(|fact| {
                !matches!(
                    &fact.content.body,
                    crate::semantic::FactBody::Evict { target } if target == device
                )
            })
    };
    role_admits(&local) && role_admits(&remote)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalRoleProjection {
    Granted(Role),
    Revoked,
    Evicted,
    Invalid,
}

#[derive(Default)]
struct CanonicalProjection {
    roles: BTreeMap<String, Role>,
    evicted: BTreeSet<String>,
}

fn canonical_role_projection(
    graph: &crate::semantic::FactGraph,
    id: &FactId,
) -> CanonicalRoleProjection {
    let Some(fact) = graph.get(id) else {
        return CanonicalRoleProjection::Invalid;
    };
    match &fact.content.body {
        FactBody::RoleGrant { role, .. } => CanonicalRoleProjection::Granted(match role {
            crate::semantic::Role::Member => Role::Member,
            crate::semantic::Role::Controller => Role::Controller,
            crate::semantic::Role::Owner => Role::Owner,
        }),
        FactBody::RoleRevoke { .. } => CanonicalRoleProjection::Revoked,
        FactBody::Evict { .. } => CanonicalRoleProjection::Evicted,
        FactBody::Resolution { selected_head, .. } => {
            canonical_role_projection(graph, selected_head)
        }
        _ => CanonicalRoleProjection::Invalid,
    }
}

fn canonical_projection_snapshot(state: &Arc<EngineState>) -> CanonicalProjection {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let projection = graph.projection();
    let mut result = CanonicalProjection::default();

    for root in state.verified_bootstrap().authority_roots().iter() {
        result.roles.insert(root.to_string(), Role::Owner);
    }

    for (cell, _) in projection.cells() {
        let crate::semantic::ExclusiveCell::Role { subject } = cell else {
            continue;
        };

        let subject = subject.to_string();
        let Some(id) = projection.value(cell) else {
            // A conflict is not a vote for any side.  Remove the cached role
            // so legacy policy cannot accidentally treat a conflicted subject
            // as authoritative.
            result.roles.remove(&subject);
            continue;
        };
        match canonical_role_projection(&graph, &id) {
            CanonicalRoleProjection::Granted(role) => {
                result.roles.insert(subject, role);
            }
            CanonicalRoleProjection::Revoked => {
                result.roles.remove(&subject);
            }
            CanonicalRoleProjection::Evicted => {
                result.roles.remove(&subject);
                result.evicted.insert(subject);
            }
            CanonicalRoleProjection::Invalid => {
                result.roles.remove(&subject);
            }
        }
    }
    result
}

async fn apply_canonical_projection(state: &Arc<EngineState>) -> bool {
    let projection = canonical_projection_snapshot(state);
    let CanonicalProjection { roles, evicted } = projection;
    let roster_changed = {
        let mut roster = state.roster.write();
        let mut changed = false;
        for (pubkey, role) in &roles {
            if !crate::roster::is_authorized(&roster, pubkey) {
                crate::roster::add_peer_in(&mut roster, pubkey, "");
                changed = true;
            }
            if crate::roster::set_role_in(&mut roster, pubkey, *role) {
                changed = true;
            }
        }
        let before = roster.authorized_devices.len();
        roster
            .authorized_devices
            .retain(|entry| !evicted.contains(&entry.device_id));
        changed |= before != roster.authorized_devices.len();
        for entry in &mut roster.authorized_devices {
            if !roles.contains_key(&entry.device_id) && entry.role != Role::Member {
                entry.role = Role::Member;
                changed = true;
            }
        }
        if changed {
            let _ = crate::roster::save(&roster);
        }
        changed
    };
    // The NetworkState compatibility object is deliberately not rewritten:
    // callers that need a snapshot derive it from this graph projection.
    roster_changed
}

/// Iterate active peers — those whose data channel is ACTIVE +
/// authenticated. Used to broadcast governance frames.
fn active_peer_ids(state: &Arc<EngineState>) -> Vec<String> {
    state.peers.collect_map(|peer| {
        let data = peer.state.read();
        if matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) && data.authenticated {
            Some(peer.device_id.clone())
        } else {
            None
        }
    })
}

fn inventory_peer_owners(state: &Arc<EngineState>) -> Vec<PeerOwnerToken> {
    state.peers.owners_snapshot(|peer| {
        let data = peer.state.read();
        data.authenticated && peer.current_worker().is_some()
    })
}

async fn broadcast(state: &Arc<EngineState>, msg: MeshMessage) {
    for peer_id in active_peer_ids(state) {
        let result = super::send_to_peer(state, &peer_id, &msg).await;
        // Best-effort: a failure to send to one peer doesn't block
        // delivery to the others. The next peer's `NetworkState`
        // broadcast on its own ACTIVE transition will catch them up.
        if let Err(e) = result {
            tracing::debug!(peer = %peer_id, err = %e, "governance broadcast send failed");
        }
    }
}

/// Broadcast only while the exact peer installation that justified the
/// broadcast remains current.
///
/// Replacement is checked before every send. A send already started before
/// replacement may finish, but no later send is initiated by the retired
/// owner. This keeps the activation trigger local without changing ordinary
/// governance broadcasts that originate from durable governance mutations.
async fn broadcast_for_owner(
    state: &Arc<EngineState>,
    owner: &PeerOwnerToken,
    msg: MeshMessage,
) -> bool {
    if state.peers.get_if_current(owner).is_none() {
        return false;
    }
    for peer_id in active_peer_ids(state) {
        if state.peers.get_if_current(owner).is_none() {
            return false;
        }
        if let Err(e) = super::send_to_peer(state, &peer_id, &msg).await {
            tracing::debug!(peer = %peer_id, err = %e, "owner-bound governance broadcast send failed");
        }
    }
    state.peers.get_if_current(owner).is_some()
}

fn local_fact_inventory(state: &Arc<EngineState>) -> FactInventory {
    let graph = state.authoritative_fact_graph();
    let ids = graph.read().ids().copied().collect::<Vec<_>>();
    FactInventory::new(state.mesh_context_id(), ids)
}

/// Advertise the exact canonical graph inventory to active peers.  The
/// inventory contains identifiers only; it is a repair hint, never authority.
pub async fn broadcast_fact_inventory(state: &Arc<EngineState>) {
    let inventory = local_fact_inventory(state);
    let owners = inventory_peer_owners(state);
    for owner in owners {
        let result = super::send_to_peer_owner(
            state,
            &owner,
            &MeshMessage::FactInventory(inventory.clone()),
        )
        .await;
        if let Err(error) = result {
            tracing::debug!(peer = %owner.device_id(), %error, "fact inventory broadcast send failed");
        }
    }
}

/// Activation-bound inventory advertisement.  The exact owner fence is held
/// for each send, so a replacement cannot make an old installation advertise
/// on behalf of its successor.
pub(super) async fn broadcast_fact_inventory_for_owner(
    state: &Arc<EngineState>,
    owner: &PeerOwnerToken,
) -> bool {
    if state.peers.get_if_current(owner).is_none() {
        return false;
    }
    let inventory = local_fact_inventory(state);
    broadcast_for_owner(state, owner, MeshMessage::FactInventory(inventory)).await
}

/// Ask the exact logical sender for canonical facts absent from our graph.
pub(super) async fn on_fact_inventory(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    inventory: FactInventory,
) {
    if inventory.context_id() != state.mesh_context_id() {
        return;
    }
    let (missing, remote_missing) = {
        let graph = state.authoritative_fact_graph();
        let graph = graph.read();
        let remote_ids = inventory
            .fact_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let missing = remote_ids
            .iter()
            .copied()
            .filter(|id| graph.get(id).is_none())
            .collect::<Vec<_>>();
        let remote_missing = graph.ids().any(|id| !remote_ids.contains(id));
        (missing, remote_missing)
    };
    if remote_missing && missing.is_empty() {
        // Return our current context-bound inventory on the same logical route
        // when the remote inventory is a strict subset. Incomparable inventories
        // issue requests only, avoiding reciprocal echo storms.
        let reciprocal = MeshMessage::FactInventory(local_fact_inventory(state));
        let result = super::send_logical_reply(state, route, &reciprocal).await;
        if let Err(error) = result {
            tracing::debug!(
                peer = %route.owner().device_id(),
                %error,
                "reciprocal fact inventory send failed"
            );
        }
    }
    if !missing.is_empty() {
        let request = FactRequest::new(state.mesh_context_id(), missing);
        let result =
            super::send_logical_reply(state, route, &MeshMessage::FactRequest(request)).await;
        if let Err(error) = result {
            tracing::debug!(
                peer = %route.owner().device_id(),
                %error,
                "fact inventory request send failed"
            );
        }
    }
}

/// Reply on the captured logical route with only the requested facts known by
/// this exact graph.  Unknown IDs are ignored and the sorted request order is
/// retained by `FactRequest`'s canonical constructor.
pub(super) async fn on_fact_request(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    request: FactRequest,
) {
    if request.context_id() != state.mesh_context_id() {
        return;
    }
    let facts = {
        let graph = state.authoritative_fact_graph();
        let graph = graph.read();
        request
            .fact_ids()
            .iter()
            .filter_map(|id| graph.get(id).cloned())
            .collect::<Vec<_>>()
    };
    let bundle = MeshMessage::FactBundle(FactBundleMessage { facts });
    let result = super::send_logical_reply(state, route, &bundle).await;
    if let Err(error) = result {
        tracing::debug!(
            peer = %route.owner().device_id(),
            %error,
            "fact bundle reply send failed"
        );
    }
}

/// Carry the bootstrap root's initial member grant to the exact authenticated
/// installation that is still waiting for approval.  This is deliberately a
/// governance-only pre-admission seam: a pending peer receives one
/// self-authenticating canonical fact, never application, inventory, request,
/// or realtime traffic.  The owner and worker are captured together, and the
/// worker's structural send claim is held until the exact bytes settle.
async fn send_pending_role_grant(
    state: &Arc<EngineState>,
    target: &str,
    fact: &SignedFact,
) -> Option<PeerOwnerToken> {
    let owner = state.peers.owner(target)?;
    let (owner, worker) = state
        .peers
        .with_current(&owner, |peer| {
            let data = peer.state.read();
            if !data.authenticated || !matches!(data.status, PeerStatus::PendingApproval) {
                return None;
            }
            let worker = peer.current_worker()?;
            Some((owner.for_worker(Arc::clone(&worker)), worker))
        })
        .flatten()?;
    let bytes = match serde_json::to_vec(&MeshMessage::Fact(fact.clone())) {
        Ok(bytes) => bytes,
        Err(error) => {
            diag(
                state,
                crate::events::DiagLevel::Warn,
                format!("unable to encode pending RoleGrant for {target}: {error}"),
            );
            return None;
        }
    };
    let Ok(claim) = crate::application_gateway::structural_json_claim(bytes.len()) else {
        return None;
    };
    let Ok(_lease) = worker.reserve_attempt_work(claim) else {
        return None;
    };
    state.peers.get_if_current(&owner)?;
    match worker.send_owned(bytes::Bytes::from(bytes)).await {
        Ok(_) => Some(owner),
        Err(error) => {
            tracing::debug!(peer = %target, %error, "pending RoleGrant send failed");
            Some(owner)
        }
    }
}

/// Ask the exact current pending installation to run the ordinary approval
/// send/recheck after its canonical RoleGrant projection has committed.
async fn request_pending_approval(state: &Arc<EngineState>, peer_id: &str) {
    let Some(owner) = state.peers.owner(peer_id) else {
        return;
    };
    let pending = state.peers.with_current(&owner, |peer| {
        let data = peer.state.read();
        data.authenticated && matches!(data.status, PeerStatus::PendingApproval)
    });
    if pending == Some(true) {
        super::handshake::reevaluate_after_role_grant(state, &owner).await;
    }
}

fn diag(state: &Arc<EngineState>, level: crate::events::DiagLevel, msg: impl Into<String>) {
    state.log_diag(level, "governance", msg);
}

// ---- snapshot -------------------------------------------------------

/// Read-only compatibility snapshot derived from the bootstrap policy and the
/// canonical FactGraph projection. Legacy transitions and pending proposals
/// are intentionally absent from this view.
pub fn snapshot(state: &Arc<EngineState>) -> network_state::NetworkState {
    let kind = if matches!(
        state.verified_bootstrap().policy(),
        crate::semantic::VerifiedProjectPolicy::Closed(_)
    ) {
        NetworkKind::Closed
    } else if state.config.read().kind == NetworkKind::Silent {
        NetworkKind::Silent
    } else {
        NetworkKind::Open
    };
    network_state::NetworkState::from_canonical_projection(
        &state.network_id,
        kind,
        canonical_projection_snapshot(state).roles,
    )
}

// ---- local proposals ------------------------------------------------

/// Float a new signed transition from this device. Signs with the
/// local identity, persists to pending, broadcasts to peers.
#[cfg(any())]
async fn legacy_propose(
    state: &Arc<EngineState>,
    variant: TransitionVariant,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    // Idempotency short-circuit — placed *before* the custody gate, because
    // re-asserting an already-applied grant authorizes nothing and must never
    // spend an MFA code. A `RoleGrant` whose target already sits at that exact
    // role in the signed state is a no-op: signing it again would append a
    // redundant transition and grow the log on every re-assertion. (The owner
    // re-signs its fleet members on each startup to keep the signed roster
    // authoritative; with closed-network membership now riding the log, that
    // re-assertion has to be free.) We check the *explicit* role map, not
    // `role_of` — an absent target reads as the default `Member` there but is
    // NOT yet signed into the log, so granting it Member is meaningful and must
    // proceed (this is exactly how a not-yet-signed member gets admitted).
    if let TransitionVariant::RoleGrant { target, role } = &variant {
        let gov = state.governance_state.read();
        let signed_member = *role != Role::Member
            || network_state::verify_seeded_logs(
                state.verified_bootstrap(),
                &state.mesh_context_id(),
                &state.network_id,
                &gov.transitions,
                &gov.member_log,
            )
            .map(|verified| {
                network_state::verify_member_log(&verified, &gov.member_log, &state.network_id)
                    .contains(target)
            })
            .unwrap_or(false);
        if gov.roles.get(target).copied() == Some(*role) && signed_member {
            let body = fact_body(&variant)?;
            let parents = causal_parents(state, &body, Vec::new());
            let content = FactContent::new(
                body.domain(),
                state.mesh_context_id(),
                body,
                canonical_device(state.identity.public_id())?,
                parents,
            );
            return Ok(FactId::from_content(&content));
        }
    }
    // Custody lock: authoring a governance transition is a custody-affecting
    // act. If this device enrolled a second factor for this network, a fresh
    // code is required here; otherwise this is a no-op. Composes with — does
    // not replace — the cryptographic owner-quorum checked at ratification.
    crate::custody::require(&state.network_id, mfa_code)?;
    let self_pubkey = state.identity.public_id().to_string();
    let signature =
        network_state::sign_transition(&state.network_id, &variant, state.identity.signing_key());
    let created_at = member_tier_timestamp(state, &variant);
    let fact = signed_fact(state, fact_body(&variant)?, Vec::new())?;
    admit_authored_fact(state, &fact)?;
    broadcast_fact_inventory(state).await;
    let _ = apply_canonical_projection(state).await;
    let fact_id = fact.id;
    let id = fact_id.to_string();
    let proposal = Proposal {
        id: id.clone(),
        created_at,
        proposer: self_pubkey.clone(),
        variant,
        signers: vec![self_pubkey],
        signatures: vec![signature],
        deniers: Vec::new(),
        split_spawned: false,
    };
    // The announcement is derived from the record, before the record is filed
    // away — see [`announcement`] for why it is not built from the same values a
    // second time.
    let msg = MeshMessage::Fact(fact.clone());

    {
        let mut gov = state.governance_state.write();
        gov.pending.push(proposal);
        network_state::save(&gov)?;
    }

    broadcast(state, msg).await;

    // After every governance-mutating step that wrote to pending or
    // transitions, broadcast a fresh state snapshot so peers
    // catch up without waiting for their own ACTIVE transition.
    broadcast_state(state).await;

    // The proposer may have all the signatures they need already
    // (e.g. a single-signer founder self-election on an empty
    // network, or a sole-owner closed→open transition). Try to
    // ratify immediately.
    let _ = try_ratify(state, &id).await;
    // Legacy ratification is retained only as a compatibility projection;
    // canonical graph state is the final live authority.
    let _ = apply_canonical_projection(state).await;

    // The SingleRootSignedMemberLogV1 bootstrap admits its first member with
    // the root-signed canonical RoleGrant itself.  Carry it only after the
    // compatibility projection has committed, while retaining the canonical
    // graph admission ordering above.
    if let FactBody::RoleGrant { target, .. } = &fact.content.body {
        let committed = state
            .governance_state
            .read()
            .member_log
            .iter()
            .any(|entry| {
                matches!(
                    &entry.variant,
                    TransitionVariant::RoleGrant {
                        target: entry_target,
                        role: Role::Member,
                    } if entry_target == target.as_ref()
                )
            });
        if committed {
            if let Some(owner) = send_pending_role_grant(state, target, &fact).await {
                super::handshake::reevaluate_after_role_grant(state, &owner).await;
            }
        }
    }

    Ok(fact_id)
}

/// Author and broadcast one canonical governance fact. Compatibility state is
/// projected only after graph admission; it never creates a proposal or a
/// legacy transition entry.
pub async fn propose(
    state: &Arc<EngineState>,
    variant: TransitionVariant,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    crate::custody::require(&state.network_id, mfa_code)?;
    let fact = signed_fact(state, fact_body(&variant)?, Vec::new())?;
    admit_authored_fact(state, &fact)?;
    let _ = apply_canonical_projection(state).await;
    broadcast_fact_inventory(state).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    broadcast_state(state).await;

    if let FactBody::RoleGrant { target, role } = &fact.content.body {
        if *role == crate::semantic::Role::Member
            && canonical_projection_snapshot(state).roles.get(&pk(target)) == Some(&Role::Member)
        {
            if let Some(owner) = send_pending_role_grant(state, target, &fact).await {
                super::handshake::reevaluate_after_role_grant(state, &owner).await;
            }
        }
    }
    Ok(fact.id)
}

/// The wire announcement for a proposal this device just filed.
///
/// Built from the **record**, not a second time from the values the record was
/// built from, and that distinction is the whole of this function. One signed
/// proposal has one `created_at`: the local pending entry and the frame that
/// announces it used to sample the clock independently, so the proposer filed
/// `member_tier_timestamp` — deliberately strictly past the target's newest
/// member-log entry — while every receiver filed a bare wall clock. `try_ratify`
/// builds `Transition { at: p.created_at, .. }` from whichever record it holds,
/// so one proposal ratified into two different member-log entries.
///
/// That is not cosmetic drift. The member tier orders by `at`, and its total
/// order lets an equal-stamp grant beat a tombstone, so an eviction authored in
/// the same wall-clock second as its target's admit removed the member on the
/// proposer and left it granted on every peer — one node refusing a device
/// another still positively authorises. The two `at` values also gave the two
/// entries different `member_entry_key`s, so the union merge kept both copies of
/// what was logically one transition.
///
/// The signature is the proposer's own, which is the only one a freshly filed
/// proposal carries. A record without it announces an empty signature, which no
/// receiver can verify — a malformed proposal is refused rather than trusted.
/// Sign an existing pending proposal authored elsewhere (or
/// re-sign — a no-op if the local pubkey is already in the signer
/// list). Broadcasts the signed ack. If the signature satisfies the
/// quorum, ratifies the transition in the same step.
#[cfg(any())]
async fn legacy_sign_proposal(
    state: &Arc<EngineState>,
    proposal_id: &str,
    mfa_code: Option<&str>,
) -> Result<()> {
    let self_pubkey = state.identity.public_id().to_string();
    let variant = {
        let gov = state.governance_state.read();
        let proposal = gov
            .pending
            .iter()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        if !proposal.deniers.is_empty() {
            return Err(Error::Other("proposal has been denied".into()));
        }
        if proposal.signers.iter().any(|s| s == &self_pubkey) {
            return Err(Error::Other("already signed".into()));
        }
        crate::custody::require(&state.network_id, mfa_code)?;
        proposal.variant.clone()
    };
    let signature =
        network_state::sign_transition(&state.network_id, &variant, state.identity.signing_key());
    let target = variant_target(&variant)?;

    let proposal = parse_fact_id(proposal_id)
        .ok_or_else(|| Error::Other("proposal id is not a FactId".into()))?;
    let fact = signed_fact(
        state,
        FactBody::Attestation {
            target,
            proposal,
            decision: AttestationDecision::Approve,
            signer: canonical_device(&self_pubkey)?,
            contributions: Vec::new(),
        },
        vec![proposal],
    )?;
    admit_authored_fact(state, &fact)?;
    broadcast_fact_inventory(state).await;
    let _ = apply_canonical_projection(state).await;
    {
        let mut gov = state.governance_state.write();
        let record = gov
            .pending
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        record.signers.push(self_pubkey.clone());
        record.signatures.push(signature);
        network_state::save(&gov)?;
    }
    let msg = MeshMessage::Fact(fact);
    broadcast(state, msg).await;

    let _ = try_ratify(state, proposal_id).await;
    let _ = apply_canonical_projection(state).await;
    Ok(())
}

/// Deny a pending proposal. Signs a deny payload (so a deny can't
/// be forged) and broadcasts. Any single deny invalidates the
/// proposal.
#[cfg(any())]
async fn legacy_deny_proposal(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
    let self_pubkey = state.identity.public_id().to_string();
    let target = {
        let gov = state.governance_state.read();
        let proposal = gov
            .pending
            .iter()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        if proposal.deniers.iter().any(|s| s == &self_pubkey) {
            return Err(Error::Other("already denied".into()));
        }
        variant_target(&proposal.variant)?
    };

    let proposal = parse_fact_id(proposal_id)
        .ok_or_else(|| Error::Other("proposal id is not a FactId".into()))?;
    let fact = signed_fact(
        state,
        FactBody::Attestation {
            target,
            proposal,
            decision: AttestationDecision::Reject,
            signer: canonical_device(&self_pubkey)?,
            contributions: Vec::new(),
        },
        vec![proposal],
    )?;
    admit_authored_fact(state, &fact)?;
    broadcast_fact_inventory(state).await;
    let _ = apply_canonical_projection(state).await;
    {
        let mut gov = state.governance_state.write();
        let proposal = gov
            .pending
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        proposal.deniers.push(self_pubkey.clone());
        network_state::save(&gov)?;
    }
    let msg = MeshMessage::Fact(fact);
    broadcast(state, msg).await;
    // Symmetric with `sign_proposal`: call try_ratify so the
    // denier's own pending list drops the proposal right away
    // (the inbound ack handler does this for receivers, but the
    // denier herself wouldn't otherwise clean up until the next
    // mutation).
    let _ = try_ratify(state, proposal_id).await;
    let _ = apply_canonical_projection(state).await;
    broadcast_state(state).await;
    diag(
        state,
        crate::events::DiagLevel::Info,
        format!("proposal {proposal_id} denied"),
    );
    Ok(())
}

/// Withdraw a proposal authored by the local device. No broadcast —
/// peers see the proposal disappear via the next state snapshot.
#[cfg(any())]
async fn legacy_withdraw_proposal(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
    let self_pubkey = state.identity.public_id().to_string();
    {
        let mut gov = state.governance_state.write();
        let idx = gov
            .pending
            .iter()
            .position(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        if gov.pending[idx].proposer != self_pubkey {
            return Err(Error::Other(
                "only the proposer can withdraw a proposal".into(),
            ));
        }
        gov.pending.remove(idx);
        network_state::save(&gov)?;
    }
    broadcast_state(state).await;
    Ok(())
}

/// Fire the proposer-initiated split fallback. Spawns a derived
/// closed network from the signers the proposal has so far; the
/// local device becomes founder-owner of the new network.
#[cfg(any())]
async fn legacy_spawn_split(state: &Arc<EngineState>, proposal_id: &str) -> Result<String> {
    let _ = (state, proposal_id);
    return Err(Error::Other(
        "split is not an adopted V4 durable fact; create a new mesh explicitly".into(),
    ));
    /* legacy implementation retained below only as migration reference
        let self_pubkey = state.identity.public_id().to_string();
        let (new_network_id, signers, split_signature) = {
            let gov = state.governance_state.read();
            let p = gov
                .pending
                .iter()
                .find(|p| p.id == proposal_id)
                .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
            if p.proposer != self_pubkey {
                return Err(Error::Other("only the proposer can spawn a split".into()));
            }
            if p.split_spawned {
                return Err(Error::Other("split already spawned".into()));
            }
            if !matches!(
                &p.variant,
                TransitionVariant::KindChange {
                    to: NetworkKind::Closed
                }
            ) {
                return Err(Error::Other(
                    "splits only apply to stuck open→closed proposals".into(),
                ));
            }

            // Derived network id is deterministic from the parent + signer
            // set, so the same signers always land in the same network
            // (idempotent retry-safe). The signed payload binds the new
            // network's id + members; the proposer is the lone signer
            // since the split's quorum is single-signer (the would-be
            // founder owner).
            let signers = p.signers.clone();
            let new_network_id = network_state::derive_split_network_id(&state.network_id, &signers);
            let split_variant = TransitionVariant::Split {
                new_network_id: new_network_id.clone(),
                members: signers.clone(),
            };
            let split_signature = network_state::sign_transition(
                &state.network_id,
                &split_variant,
                state.identity.signing_key(),
            );

            (new_network_id, signers, split_signature)
        };

        let parent = parse_fact_id(proposal_id)
            .ok_or_else(|| Error::Other("proposal id is not a FactId".into()))?;
        let fact = signed_fact(
            state,
        /* removed legacy split body {
                new_network_id: new_network_id.clone(),
                members: signers.clone(),
        }, */
            vec![parent],
        )?;
        admit_authored_fact(state, &fact)?;
        broadcast_fact_inventory(state).await;
        let _ = apply_canonical_projection(state).await;
        {
            let mut gov = state.governance_state.write();
            if !gov.pending.iter().any(|p| p.id == proposal_id) {
                return Err(Error::Other(format!("proposal not found: {proposal_id}")));
            }
            let split_variant = TransitionVariant::Split {
                new_network_id: new_network_id.clone(),
                members: signers.clone(),
            };
            let transition = Transition {
                at: now_unix(),
                variant: split_variant,
                signers: vec![self_pubkey],
                signatures: vec![split_signature],
            };
            let after = network_state::apply_transition(gov.clone(), &transition);
            *gov = after;
            if let Some(pending) = gov.pending.iter_mut().find(|p| p.id == proposal_id) {
                pending.split_spawned = true;
            }
            network_state::save(&gov)?;
        }
        let _ = apply_canonical_projection(state).await;
        let msg = MeshMessage::Fact(fact);
        broadcast(state, msg).await;
        broadcast_state(state).await;
        diag(
            state,
            crate::events::DiagLevel::Info,
            format!("spawned split → {new_network_id}"),
        );
        Ok(new_network_id)
    }

    // ---- inbound dispatch -----------------------------------------------

    /// Reduce one canonical V4 fact.  The fact id, complete body, parent list and
    /// embedded author are all verified before any legacy policy projection is
    /// updated; the carrier is never consulted for authority.
    pub(super) async fn on_fact(state: &Arc<EngineState>, fact: SignedFact) {
        if let Err(error) = fact.verify() {
            diag(
                state,
                crate::events::DiagLevel::Warn,
                format!("rejecting invalid semantic fact {error}"),
            );
            return;
        }
        {
            let graph = state.authoritative_fact_graph();
            let mut graph = graph.write();
            if graph.get(&fact.id).is_none() {
                match graph.admit(fact.clone()) {
                    Ok(crate::semantic::Admission::Inserted)
                    | Ok(crate::semantic::Admission::AlreadyPresent) => {}
                    Ok(crate::semantic::Admission::Quarantined { .. }) => return,
                    Err(error) => {
                        diag(
                            state,
                            crate::events::DiagLevel::Warn,
                            format!("rejecting semantic fact admission: {error}"),
                        );
                        return;
                    }
                }
            }
        }

        // Semantic facts are already authenticated and admitted by the canonical
        // graph.  They are projected directly into the compatibility state; their
        // FactId/signature is never placed in a legacy Transition envelope, whose
        // verifier expects a different signed payload.
        let changed = apply_canonical_projection(state).await;
        broadcast_fact_inventory(state).await;
        if changed {
            broadcast_roster_summary(state).await;
            broadcast_state(state).await;
        }
        if let FactBody::RoleGrant { target, .. } = &fact.content.body {
            if pk(target) == pk(state.identity.public_id()) {
                request_pending_approval(state, &fact.content.author).await;
            }
        }
    }

    /// A peer broadcasts their view of the network's governance state.
    /// We diag-log governance drift, and — because the broadcast carries the
    /// sender's roster membership root — drive roster convergence off it too:
    /// if their roster membership differs from ours, pull the delta. This
    /// makes the post-mutation `NetworkState` broadcast double as a roster
    /// summary, so a peer learns of new members the moment any governance
    /// frame lands, not just on its own ACTIVE transition.
    // `pub(super)`: logical-route-bound, so it names a crate-private operation, and the
    // engine's own frame dispatch is its only caller. The identity-keyed
    // governance handlers below stay `pub` — integration tests drive them.
    pub(super) async fn on_state_broadcast(
        state: &Arc<EngineState>,
        route: &LogicalSessionOperation,
        msg: NetworkStateBroadcast,
    ) {
        let peer_id = route.owner().device_id();
        let (local_kind, local_count, local_member_count) = {
            let gov = state.governance_state.read();
            (
                gov.kind,
                gov.transitions.len() as u32,
                gov.member_log.len() as u32,
            )
        };
        let local_fact_heads = local_count.saturating_add(local_member_count);
        if local_kind != msg.kind || local_fact_heads != msg.fact_heads_count {
            diag(
                state,
                crate::events::DiagLevel::Info,
                format!(
                    "governance drift with {}: local {:?}/{} vs theirs {:?}/{}",
                    &peer_id[..peer_id.len().min(12)],
                    local_kind,
                    local_fact_heads,
                    msg.kind,
                    msg.fact_heads_count
                ),
            );
        }
        // Pull the peer's roster — which now carries the signed governance log —
        // when *either* our membership root differs or the peer's log is ahead of
        // ours. The log half is what converges roles (who the owner is) fleet-wide:
        // a role grant (or the founder election) bumps `transitions_count` without
        // necessarily changing membership, so a membership-only check would miss it.
        let membership_differs =
            crate::roster::membership_root(&state.roster.read()) != msg.roster_root;
        let reply = state_broadcast_reply(local_count, local_member_count, &msg, membership_differs);
        if reply.pull_roster {
            request_roster(state, route).await;
        }
        if reply.re_advertise {
            send_state_to_owner(state, route).await;
        }
        let inventory = MeshMessage::FactInventory(local_fact_inventory(state));
        if let Err(error) = super::send_logical_reply(state, route, &inventory).await {
            tracing::debug!(
                peer = %route.owner().device_id(),
                %error,
                "fact inventory route advertisement failed"
            );
        }
    }

    /// Decide both halves of the reply from four numbers.
    ///
    /// Extracted from [`on_state_broadcast`] because the interesting property is
    /// the decision rather than the send, and a decision reachable only through a
    /// transport is one nothing can state exhaustively.
    ///
    /// **Why a re-advertise exists at all.** Every pull condition asks "is the
    /// *sender* ahead of me". That converges a peer who hears from someone further
    /// along, and does nothing at all for a peer who is behind and hears from
    /// someone who is not: the peer that holds the newer log sees a stale snapshot,
    /// has no reason to pull, and — before this — said nothing back. Since
    /// [`broadcast_state`] fires only on a local mutation or an activation, and
    /// nothing re-announces on a timer, one broadcast that arrives while a peer is
    /// not yet Active left that peer stale until the next mutation or a reconnect.
    /// In a two-peer mesh that is a hang; in a fleet it is one owner holding a
    /// member the others never see, arriving through timing rather than a fork.
    ///
    /// **Why this cannot echo.** A re-advertise is triggered only by a *strict*
    /// inequality on a count. For any one count, at most one of two peers can be
    /// strictly greater, so the peer we answer cannot answer us back on that same
    /// count — it is strictly behind, so it pulls instead. `membership_differs` is
    /// symmetric and deliberately does **not** trigger one; two peers whose roots
    /// disagree would otherwise answer each other forever. Genuine cross-divergence
    /// — each side ahead on a different count — costs exactly one frame each way,
    /// and both sides also pull, so the next exchange has equal counts and both
    /// fall silent. Convergence is the fixed point: nothing is strictly ahead, so
    /// nothing is sent.
        */
}

/// Legacy proposal controls are intentionally inert during the canonical V4
/// migration. Callers must submit a canonical fact instead; no proposal or
/// transition log is created here.
pub async fn sign_proposal(
    _state: &Arc<EngineState>,
    _proposal_id: &str,
    _mfa_code: Option<&str>,
) -> Result<()> {
    Err(Error::Other(
        "legacy proposal signing is disabled; submit a canonical fact".into(),
    ))
}

pub async fn deny_proposal(_state: &Arc<EngineState>, _proposal_id: &str) -> Result<()> {
    Err(Error::Other(
        "legacy proposal denial is disabled; submit a canonical fact".into(),
    ))
}

pub async fn withdraw_proposal(_state: &Arc<EngineState>, _proposal_id: &str) -> Result<()> {
    Err(Error::Other(
        "legacy proposal withdrawal is disabled; submit a canonical fact".into(),
    ))
}

pub async fn spawn_split(_state: &Arc<EngineState>, _proposal_id: &str) -> Result<String> {
    Err(Error::Other(
        "split is not an adopted V4 durable fact; create a new mesh explicitly".into(),
    ))
}

/// Compatibility callers may still invoke the old adoption hook, but it has
/// no authority and deliberately performs no mutation. Canonical facts must
/// arrive through semantic ingress and the shared FactGraph.
#[cfg(test)]
pub(super) async fn adopt_transition_log(
    _state: &Arc<EngineState>,
    _peer_id: &str,
    _incoming_gov: &[network_state::Transition],
    _incoming_members: &[network_state::Transition],
) {
}

/// Admit one verified canonical fact and project it into the read-only
/// compatibility view. The carrier and legacy transition logs are never used
/// as authority.
pub(super) async fn on_fact(state: &Arc<EngineState>, fact: SignedFact) {
    if let Err(error) = fact.verify() {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!("rejecting invalid semantic fact {error}"),
        );
        return;
    }
    let graph = state.authoritative_fact_graph();
    let admission = graph.write().admit(fact.clone());
    if let Err(error) = admission {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!("rejecting semantic fact admission: {error}"),
        );
        return;
    }
    let changed = apply_canonical_projection(state).await;
    broadcast_fact_inventory(state).await;
    if changed {
        broadcast_roster_summary(state).await;
        broadcast_state(state).await;
    }
    if let FactBody::RoleGrant { target, .. } = &fact.content.body {
        if pk(target) == pk(state.identity.public_id()) {
            request_pending_approval(state, &fact.content.author).await;
        }
    }
}

/// What one received `NetworkState` snapshot obliges us to send back.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateBroadcastReply {
    /// Ask the sender for their roster and signed logs: they hold something we
    /// do not.
    pull_roster: bool,
    /// Send our own snapshot straight back to the sender: we hold something
    /// they do not, and nothing else is going to tell them.
    re_advertise: bool,
}

#[cfg(test)]
fn state_broadcast_reply(
    local_transitions: u32,
    local_members: u32,
    msg: &NetworkStateBroadcast,
    membership_differs: bool,
) -> StateBroadcastReply {
    let local_heads = local_transitions.saturating_add(local_members);
    StateBroadcastReply {
        pull_roster: membership_differs || msg.fact_heads_count > local_heads,
        re_advertise: local_heads > msg.fact_heads_count,
    }
}

/// Our current governance snapshot, as the wire carries it.
///
/// One builder for all three senders — the fleet broadcast, the
/// activation-bound broadcast, and the targeted re-advertise above — so a
/// change to what a snapshot states cannot reach two of them and miss the
/// third.
///
/// The membership root is the *membership* root and not the full merkle root,
/// so peers reconcile on who is in the network rather than on per-node label
/// and timestamp churn — see [`crate::roster::membership_root`].
fn local_state_snapshot(state: &Arc<EngineState>) -> NetworkStateBroadcast {
    let graph = state.authoritative_fact_graph();
    let fact_heads_count = graph.read().len() as u32;
    let kind = snapshot(state).kind;
    NetworkStateBroadcast {
        kind,
        fact_heads_count,
        roster_root: crate::roster::membership_root(&state.roster.read()),
    }
}

/// Reconcile canonical fact heads after receiving a compatibility snapshot.
/// The snapshot is only a hint; all authority comes from FactInventory and
/// FactRequest over the shared graph.
pub(super) async fn on_state_broadcast(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    msg: NetworkStateBroadcast,
) {
    let local_heads = state.authoritative_fact_graph().read().len() as u32;
    if msg.fact_heads_count != local_heads {
        let inventory = MeshMessage::FactInventory(local_fact_inventory(state));
        if let Err(error) = super::send_logical_reply(state, route, &inventory).await {
            tracing::debug!(
                peer = %route.owner().device_id(),
                %error,
                "canonical inventory reconciliation send failed"
            );
        }
    }
}

/// Unsigned roster roots cannot authorize membership. Keep this compatibility
/// hook side-effect free; canonical inventory reconciliation handles durable
/// convergence.
async fn maybe_request_roster(
    _state: &Arc<EngineState>,
    _route: &LogicalSessionOperation,
    _their_root: &str,
) {
}

// ---- roster gossip --------------------------------------------------
//
// Anti-entropy over the per-network roster. The contract (see
// `docs/NETWORK-TYPES.md`): once a peer is *mutually* confirmed (the
// bilateral approve handshake completes and the link goes ACTIVE) it is
// persisted into the local roster and advertised to the rest of the
// network so every member converges on the same membership.
//
// "Advertise, don't flood": we broadcast a compact membership *summary*
// (a 52-char root, not the entries) to active peers. A peer whose root
// disagrees pulls the full roster with one targeted `RosterRequest`; the
// responder replies peer-to-peer with `RosterEntries`. Each node that
// learns a new member re-summarises to ITS active peers, so an update
// ripples hop-by-hop along whatever shape the network actually has — a
// ring forwards it neighbour-to-neighbour, a star through the hub —
// reaching members we have no direct link to, instead of every node
// blasting its whole roster at every other node.
//
// Unsigned roster entries are carrier material only. They are never merged;
// signed governance/member logs are the sole durable membership authority.

/// Broadcast our roster membership summary to every active peer. Cheap —
/// one small frame per peer carrying a root, not the roster itself.
/// Called when our roster changes (a peer is confirmed / approved) and on
/// each ACTIVE transition so a freshly-connected peer reconciles at once.
pub async fn broadcast_roster_summary(state: &Arc<EngineState>) {
    // Silent networks never gossip membership — every connection is
    // deliberate, so there is nothing to converge. Presence and the per-peer
    // handshake are unaffected; only this anti-entropy advertise is suppressed.
    if !state.gossip_roster_enabled() {
        return;
    }
    let summary = crate::roster::summary(&state.roster.read());
    broadcast(state, MeshMessage::RosterSummary(summary)).await;
}

/// Activation-triggered roster summary. Unlike an ordinary durable
/// governance broadcast, this effect is cancelled when its exact activating
/// peer installation is replaced.
pub(super) async fn broadcast_roster_summary_for_owner(
    state: &Arc<EngineState>,
    owner: &PeerOwnerToken,
) -> bool {
    if state.peers.get_if_current(owner).is_none() || !state.gossip_roster_enabled() {
        return false;
    }
    let summary = crate::roster::summary(&state.roster.read());
    broadcast_for_owner(state, owner, MeshMessage::RosterSummary(summary)).await
}

/// Inbound roster summary. If the sender's membership root differs from
/// ours, ask for their full roster so we can merge what we're missing.
pub(super) async fn on_roster_summary(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    msg: RosterSummaryMessage,
) {
    maybe_request_roster(state, route, &msg.root).await;
}

/// Inbound roster request. Reply peer-to-peer (not broadcast) with our
/// full roster as entries. v1 always sends everything (`include_all`); a
/// subtree-walk can ship later without changing the frame kind.
pub(super) async fn on_roster_request(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    _msg: RosterRequestMessage,
) {
    // A Silent network never emits roster entries — membership is not gossiped
    // in either direction. (It also never sends summaries, so a well-behaved
    // peer won't request; this guards the unsolicited case.)
    if !state.gossip_roster_enabled() {
        return;
    }
    let entries: Vec<RosterEntry> = state
        .roster
        .read()
        .authorized_devices
        .iter()
        .map(RosterEntry::from)
        .collect();
    // Carry the signed governance log with the roster so roles converge with
    // membership: the requester verifies it from genesis and re-derives who is
    // owner/controller, instead of trusting a gossiped role tag. Empty on an
    // open network (no signed log).
    let msg = MeshMessage::RosterEntries(RosterEntriesMessage { entries });
    // Replying through the captured logical route is what keeps our full membership and
    // signed governance log from being handed to whoever holds this device id
    // by the time the reply goes out. A superseded requester gets nothing.
    if let Err(e) = super::send_logical_reply(state, route, &msg).await {
        tracing::debug!(
            peer = %route.owner().device_id(),
            err = %e,
            "roster entries reply send failed"
        );
    }
}

/// Inbound roster entries. The unsigned `entries` field is a carrier bundle,
/// persist if the roster changed, and — if it did — re-summarise to our
/// not an authority-bearing membership update; only the signed logs can change
/// durable state.
pub async fn on_roster_entries(state: &Arc<EngineState>, source: &str, msg: RosterEntriesMessage) {
    // `source` names where this arrived from, for the diagnostics below and for
    // the ones `adopt_transition_log` emits. It is not consulted by any decision
    // in either place: the governance and member logs authenticate themselves
    // through `verify_log` / `verify_member_log`; the unsigned `entries` are
    // ignored regardless of network kind or carrier.
    let peer_id = source;
    // The unsigned `entries` field is a legacy carrier hint, not an
    // authority-bearing membership fact. Every network kind follows the same
    // rule: only the signed logs below can change durable membership.
    if !msg.entries.is_empty() {
        diag(
            state,
            crate::events::DiagLevel::Debug,
            format!(
                "roster: ignored {} unsigned entry(ies) from {} \
                 (membership is derived from signed logs)",
                msg.entries.len(),
                &peer_id[..peer_id.len().min(12)]
            ),
        );
    }
    // Roles AND closed-network membership ride the signed log: verify the
    // peer's log, adopt it when it extends ours, and re-derive the roster from
    // it. On a closed network this is the *only* membership source — every
    // member is a ratified `RoleGrant` authored by an owner/controller.
    // Unsigned roster hints never reduce the semantic graph or governance
    // projection. Canonical signed facts are the only authority source.
}

// ---- eviction enforcement -------------------------------------------
//
// The signed log is a closed network's tombstone: an `Evict` in the
// member tier is the durable, verifiable "this device is OUT." What was
// missing was ENFORCEMENT at the boundary — an evicted device that never
// heard the news (offline during the evict) redialed forever, and the
// handshake treated it as a fresh face: pending-approval nudges at best,
// and on an auto-approve network (every fleet mesh) it was re-approved,
// re-rostered on mutual ACTIVE, and re-gossiped — resurrection on a loop.
// The three pieces below close that loop: the verdict helpers, the
// deny-with-proof at the handshake, and the self-evicted quiescence.

/// Whether `device_id`'s pubkey is explicitly evicted by this network's
/// signed state. Only meaningful on closed governance (open networks
/// have no signed membership); false there. The verdict is the same
/// [`network_state::member_log_removed`] the roster mirror prunes by,
/// with a guard: a pubkey the governance log currently seats as
/// owner/controller is never "evicted" (a stale member-tier entry can't
/// outrank the governance tier).
pub(super) fn log_evicted(state: &Arc<EngineState>, device_id: &str) -> bool {
    if matches!(
        state.verified_bootstrap().policy(),
        crate::semantic::VerifiedProjectPolicy::Open
    ) {
        return false;
    }
    canonical_projection_snapshot(state)
        .evicted
        .contains(&pk(device_id))
}

/// Recompute and cache whether the signed state has evicted THIS device
/// (see [`EngineState::self_evicted`]). Called at driver startup and
/// after every log adoption/ratification, so the verdict tracks the
/// signed state in both directions: an eviction stands the engine down
/// (announce/dial gates read the flag), and a later re-admit — the
/// owner re-claiming the device signs a fresh member grant — clears it
/// and the network comes back to life without a restart.
///
/// On the false→true edge this also clears every standing dial
/// (reconnect intents, sticky dials) and emits the `governance` /
/// `self_evicted` diag event — the signal an embedding app (AllMyStuff)
/// uses to tear down its fleet state cleanly.
pub(crate) fn refresh_self_evicted(state: &Arc<EngineState>) {
    use std::sync::atomic::Ordering;
    let verdict = log_evicted(state, state.identity.public_id());
    let was = state.self_evicted.swap(verdict, Ordering::SeqCst);
    if verdict && !was {
        state.reconnect_intents.lock().clear();
        state.sticky_peers.lock().clear();
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "governance",
            "this device was EVICTED from the network by its signed governance — standing down \
             (no more announces or dials here; a re-admit revives it)",
            serde_json::json!({
                "hint": "self_evicted",
                "network": state.network_id.clone(),
            }),
        );
    } else if !verdict && was {
        state.log_diag(
            crate::events::DiagLevel::Info,
            "governance",
            "re-admitted by the signed governance — this network is live again",
        );
    }
}

/// The handshake gate: if the authenticated `device_id` is evicted by
/// our signed state and deny it.
/// and drop the session. Returns true when the peer was denied — the
/// caller must stop the admission flow (no pending-approval, no
/// auto-approve; those were exactly the resurrection engine). The proof
/// costs nothing to trust: the denied device verifies it independently
/// through strict-extension adoption, so a spoofed deny changes nothing.
pub(super) async fn deny_if_evicted(
    state: &Arc<EngineState>,
    owner: &super::peer_registry::PeerOwnerToken,
) -> bool {
    let device_id = owner.device_id();
    if !log_evicted(state, device_id) {
        return false;
    }
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "governance",
        format!(
            "denied {} — evicted by the signed state (proof attached so it can stand down)",
            &device_id[..device_id.len().min(12)]
        ),
        serde_json::json!({ "peer": device_id, "reason": "evicted" }),
    );
    let deny = MeshMessage::Deny(crate::protocol::DenyMessage {
        reason: Some(crate::protocol::DENY_REASON_EVICTED.to_string()),
    });
    // One attempt, and the attempt's return is the boundary. The proof is
    // best-effort diagnostic material rather than authority — the peer is
    // already denied by the current policy projection — so nothing here waits
    // for it to be received, acknowledged, or retried, and no elapsed duration
    // participates in the drop.
    if let Err(e) = super::send_to_peer_owner(state, owner, &deny).await {
        tracing::debug!(peer = %device_id, err = %e, "eviction deny send failed");
    }
    // Owner-bound, so a peer that was already replaced under the same Device ID
    // keeps its successor: `drop_peer_if_current` drops nothing when this token
    // is no longer the current one.
    super::drop_peer_if_current(state, owner, DropReason::Denied).await;
    true
}

/// Feed a deny's attached logs through the standard strict-extension
/// adoption. Nothing about the *sender* is trusted: a forged or foreign
/// log fails verification inside [`adopt_transition_log`] and changes
/// nothing; a genuine one converges our state, and the adoption tail's
/// [`refresh_self_evicted`] flips this engine to stood-down if the
/// verified verdict really does evict us.
/// Re-derive the full role projection from both logs: owners and managers from
/// the verified **governance** log, plus the union-merged **member** set as
/// `Member`. With a member tier, the governance log alone no longer carries
/// members, so this is the single source of truth for `gov.roles`. A governance
/// log that fails to verify (never expected for our own ratified state) falls
/// back to no governance roles rather than panicking.
#[cfg(any())]
fn legacy_project_roles(
    bootstrap: &crate::semantic::VerifiedBootstrap,
    context: &crate::semantic::MeshContextId,
    network_id: &str,
    transitions: &[Transition],
    member_log: &[Transition],
) -> std::collections::BTreeMap<String, Role> {
    let gov =
        network_state::verify_seeded_logs(bootstrap, context, network_id, transitions, member_log)
            .unwrap_or_else(|_| {
                network_state::verify_seeded_logs(bootstrap, context, network_id, &[], &[])
                    .unwrap_or_else(|_| network_state::NetworkState::empty_for(network_id))
            });
    let mut roles = gov.roles.clone();
    for m in network_state::verify_member_log(&gov, member_log, network_id) {
        roles.entry(m).or_insert(Role::Member);
    }
    roles
}

/// Adopt a peer's two signed logs, converging both tiers of the cert chain.
///
/// The **governance** log (kind changes, owner/manager grants and removals,
/// splits) is verified from genesis ([`crate::network_state::verify_log`]) and
/// adopted only when it **extends** ours — shares our prefix and is strictly
/// longer — so a peer can add a grant or the founder election we hadn't seen
/// but can never rewrite our genesis (and the owner it elected) out from under
/// us. A divergent log is rejected whole, leaving our state untouched.
///
/// The **member** log (per-member admits/removals) is **union-merged**
/// ([`crate::network_state::merge_member_logs`]) — commutative, so two
/// managers' concurrent offline admissions both survive instead of forking the
/// way a strict-prefix log would. Either tier may change independently; if
/// either does we reproject the full role map from both logs, mirror it into
/// the roster, and re-gossip so it ripples on. We keep our in-flight pending
/// proposals throughout.
#[cfg(test)]
#[cfg(any())]
async fn legacy_adopt_transition_log(
    state: &Arc<EngineState>,
    peer_id: &str,
    incoming_gov: &[Transition],
    incoming_members: &[Transition],
) {
    // Governance log: decide adoption (verified, fork-guarded) without holding
    // the write lock across verify_log.
    let rebuilt: Option<network_state::NetworkState> = {
        let extends = {
            let gov = state.governance_state.read();
            let longer = incoming_gov.len() > gov.transitions.len();
            let shares_prefix = incoming_gov
                .iter()
                .zip(gov.transitions.iter())
                .all(|(a, b)| a.variant == b.variant && same_signer_set(a, b));
            if longer && !shares_prefix {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!(
                        "rejecting forked governance log from {}",
                        &peer_id[..peer_id.len().min(12)]
                    ),
                );
            }
            longer && shares_prefix
        };
        if extends {
            match network_state::verify_seeded_logs(
                state.verified_bootstrap(),
                &state.mesh_context_id(),
                &state.network_id,
                incoming_gov,
                incoming_members,
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    diag(
                        state,
                        crate::events::DiagLevel::Warn,
                        format!(
                            "rejecting invalid governance log from {}: {e}",
                            &peer_id[..peer_id.len().min(12)]
                        ),
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    // Apply both tiers under the write lock; reproject + mirror if either moved.
    let (changed, roles, removed, adopted_topology) = state.peers.with_governance_commit(|gov| {
        let mut changed = false;
        let mut adopted_topology = None;

        if let Some(rebuilt) = rebuilt {
            // Re-check length in case it raced another adopter.
            if rebuilt.transitions.len() > gov.transitions.len() {
                gov.kind = rebuilt.kind;
                gov.transitions = rebuilt.transitions;
                gov.splits = rebuilt.splits;
                // A prefix-extending log can only carry topology forward
                // (our Some came from our own prefix), so None never
                // clobbers Some here; surface a real change so the
                // runtime selector follows the adopted governance.
                if rebuilt.topology != gov.topology {
                    adopted_topology = rebuilt.topology.clone();
                }
                gov.topology = rebuilt.topology;
                changed = true;
            }
        }

        if !incoming_members.is_empty() {
            let merged = network_state::merge_member_logs(&gov.member_log, incoming_members);
            // Union only ever grows; a longer result means new entries.
            if merged.len() > gov.member_log.len() {
                gov.member_log = merged;
                changed = true;
            }
        }

        if !changed {
            (false, gov.roles.clone(), Default::default(), None)
        } else {
            let projected = project_roles(
                state.verified_bootstrap(),
                &state.mesh_context_id(),
                &state.network_id,
                &gov.transitions,
                &gov.member_log,
            );
            // Devices the signed log explicitly evicted/revoked — the only ones
            // the roster mirror deletes.
            let verified = network_state::verify_seeded_logs(
                state.verified_bootstrap(),
                &state.mesh_context_id(),
                &state.network_id,
                &gov.transitions,
                &gov.member_log,
            )
            .unwrap_or_else(|_| {
                network_state::verify_seeded_logs(
                    state.verified_bootstrap(),
                    &state.mesh_context_id(),
                    &state.network_id,
                    &[],
                    &[],
                )
                .unwrap_or_else(|_| network_state::NetworkState::empty_for(&state.network_id))
            });
            let removed =
                network_state::member_log_removed(&verified, &gov.member_log, &state.network_id);
            gov.roles = projected.clone();
            if let Err(e) = network_state::save(gov) {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!("persist after adopting logs failed: {e}"),
                );
            }
            (true, projected, removed, adopted_topology)
        }
    });

    if !changed {
        return;
    }

    if let Some(mode) = adopted_topology {
        // Governance carried a topology this node hadn't applied yet —
        // follow it live, exactly like a local ratification does.
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = crate::topology::from_mode(&mode);
        super::ladder::reevaluate_topology(state).await;
        diag(
            state,
            crate::events::DiagLevel::Info,
            format!("governed topology adopted: {mode:?}"),
        );
    }

    // Mirror the converged roles into the roster: add role-bearers, update tags,
    // and delete only the devices the signed log explicitly evicted/revoked
    // (`removed`). This is how an eviction learned via gossip de-authorises the
    // target on this node, matching the local-ratify path — without over-pruning
    // devices that are simply not (yet) in the signed projection.
    {
        let mut roster = state.roster.write();
        let self_pk = state.identity.public_id().to_string();
        if mirror_roles_to_roster(&roles, &mut roster, &removed, &self_pk) {
            if let Err(e) = crate::roster::save(&roster) {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!("persist roster after role mirror failed: {e}"),
                );
            }
        }
    }
    diag(
        state,
        crate::events::DiagLevel::Info,
        format!(
            "adopted converged logs from {}",
            &peer_id[..peer_id.len().min(12)]
        ),
    );
    // The adopted logs may have evicted (or re-admitted) THIS device —
    // settle the cached verdict before telling anyone anything.
    refresh_self_evicted(state);
    // Tell our own peers — both the new membership and the new governance
    // counts — so it ripples on.
    broadcast_roster_summary(state).await;
    broadcast_state(state).await;
}

// ---- ratification ---------------------------------------------------

/// Reorder a transition's `(signer, signature)` pairs into a canonical,
/// peer-independent order: the proposer first, then every other signer sorted
/// by pubkey, each signature carried with its signer. Signatures are matched to
/// signers positionally by [`network_state::verify_transition_signatures`], so
/// the two vectors are permuted together.
///
/// Ratification runs the assembled transition through this so that two peers
/// which gathered the same co-signatures in different ack-arrival orders record
/// the *byte-identical* entry. That is what the shared-prefix fork guard in
/// [`adopt_transition_log`] — and any future hash over the log — depend on.
/// ed25519 signatures are deterministic, so once the signer order agrees the
/// whole entry agrees. Keeping the proposer first preserves the
/// `signers.first() == founder/proposer` convention `apply_transition` relies
/// on (genesis and splits are single-signer, so this is a no-op for them).
/// The pubkey a member-tier transition acts on, if it is one.
#[cfg(any())]
fn legacy_member_entry_target(t: &network_state::Transition) -> Option<&str> {
    match &t.variant {
        TransitionVariant::RoleGrant { target, .. }
        | TransitionVariant::RoleRevoke { target }
        | TransitionVariant::Evict { target } => Some(target.as_str()),
        _ => None,
    }
}

/// Timestamp to stamp on a newly-authored transition. Member-tier entries
/// Legacy transition envelopes retain `at` for traceability and stable local
/// persistence, but [`network_state::verify_member_log`] deliberately does not
/// treat it as authority. We still stamp one past the newest locally known
/// member-log entry for the target so independently persisted envelopes remain
/// distinguishable; re-admission after a tombstone requires canonical causal
/// resolution, never a larger timestamp. Governance-tier transitions likewise
/// retain the wall clock only as non-authoritative metadata.
#[cfg(any())]
fn legacy_member_tier_timestamp(state: &Arc<EngineState>, variant: &TransitionVariant) -> u64 {
    let now = now_unix();
    let gov = state.governance_state.read();
    let target = match variant {
        TransitionVariant::RoleGrant {
            target,
            role: Role::Member,
        } => target.as_str(),
        // A revoke rides the member log (and needs the monotonic stamp) only when
        // it targets a plain member; a revoke of an owner/manager stays governance
        // tier and just demotes, so it takes the wall clock below.
        TransitionVariant::RoleRevoke { target } if gov.role_of(target) == Role::Member => {
            target.as_str()
        }
        // An evict is tombstoned in the member log at *either* tier (see
        // `try_ratify`) — to suppress the target's member-tier admit — so it must
        // ALWAYS be stamped strictly past the target's newest member-log entry.
        // Otherwise a same-second admit wins the last-writer-wins tie and the
        // evicted device survives: a promoted owner/manager keeps the plain-member
        // admit it was given before promotion, and re-appears fleet-wide.
        TransitionVariant::Evict { target } => target.as_str(),
        _ => return now,
    };
    let newest = gov
        .member_log
        .iter()
        .filter(|t| member_entry_target(t) == Some(target))
        .map(|t| t.at)
        .max()
        .unwrap_or(0);
    now.max(newest.saturating_add(1))
}

/// If `proposal_id`'s pending entry has gathered enough signatures
/// to satisfy the quorum table for its variant — and hasn't been
/// denied — fold it into the signed transition log, apply, persist,
/// and broadcast a fresh state snapshot.
#[cfg(any())]
async fn legacy_try_ratify(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
    let transition = state
        .peers
        .with_governance_commit(|gov| -> Result<Option<Transition>> {
            let Some(idx) = gov.pending.iter().position(|p| p.id == proposal_id) else {
                return Ok(None);
            };
            if !gov.pending[idx].deniers.is_empty() {
                // Denied — drop from pending and bail.
                gov.pending.remove(idx);
                network_state::save(gov)?;
                return Ok(None);
            }
            let p = &gov.pending[idx];

            // Fold the (signer, signature) pairs into a canonical order —
            // proposer first, then the rest sorted by signer pubkey — so that two
            // peers who collected the same co-signatures in different ack-arrival
            // orders record the *byte-identical* transition. Without this, the
            // shared-prefix fork guard in `adopt_transition_log` would see two
            // orderings of the same multi-signer transition as divergent logs and
            // refuse to converge. ed25519 signatures are deterministic, so once the
            // signer order agrees the whole entry agrees. Genesis and splits are
            // single-signer, so `first()` still resolves to the founder/proposer
            // (canonicalisation is a no-op there).
            let (signers, signatures) =
                canonicalize_signers(&p.proposer, &p.signers, &p.signatures);
            let candidate = Transition {
                at: p.created_at,
                variant: p.variant.clone(),
                signers,
                signatures,
            };
            if network_state::verify_transition_signatures(&state.network_id, &candidate).is_err() {
                // Should never happen — we verified each at intake.
                return Ok(None);
            }

            // Quorum check. Authority is read entirely off the signed state
            // (`gov.roles`), reconstructed from the log — no external roster is
            // consulted, so this matches what a converging peer's `verify_log`
            // will re-derive.
            if network_state::verify_quorum(gov, &candidate).is_err() {
                return Ok(None);
            }

            let transition = candidate;
            // Route by tier: a member admit/removal rides the union-merged member
            // log (so two managers' concurrent offline admissions don't fork);
            // everything else (kind change, owner/manager grant or removal, split)
            // extends the strict governance log. A removal is member-tier iff its
            // target is currently a plain member.
            let member_tier = match &transition.variant {
                TransitionVariant::RoleGrant {
                    role: Role::Member, ..
                } => true,
                TransitionVariant::RoleRevoke { target } | TransitionVariant::Evict { target } => {
                    gov.role_of(target) == Role::Member
                }
                _ => false,
            };
            if member_tier {
                gov.member_log.push(transition.clone());
                gov.roles = project_roles(
                    state.verified_bootstrap(),
                    &state.mesh_context_id(),
                    &state.network_id,
                    &gov.transitions,
                    &gov.member_log,
                );
            } else {
                // Apply to the governance log. `apply_transition` advances
                // `gov.roles` **incrementally, from this transition alone** —
                // the genesis arm inserts the founder and nothing else — so the
                // reprojection below is what folds the other tier back in. It
                // is not an optimisation and not defensive: without it the
                // founder's own close leaves every signed member absent from
                // `roles`, and `with_governance_commit` then synchronously
                // revokes the sessions of exactly those members. A node that
                // adopts a close through `adopt_transition_log` reprojects from
                // both tiers and keeps them; the node that *authors* one used to
                // drop them, which is the node guaranteed to hit it.
                let after = network_state::apply_transition(gov.clone(), &transition);
                *gov = after;
                // Evicting a device promoted past plain member (an owner or manager)
                // still leaves its *original* member-tier admit in the member log.
                // On its own the governance-log evict removes the role but not that
                // admit, so any peer that re-derives membership from the signed logs
                // — the gossip-adoption path a co-owner runs after being offline for
                // the kick — folds the stale admit back in and resurrects the evicted
                // device as a plain member: it lingers in the roster, still
                // authorised, and nobody but the evicting owner sees it gone. Record
                // the evict in the union-merged member log too, so it tombstones that
                // admit; the removal then converges network-wide and survives
                // concurrent authors, exactly like a plain-member evict.
                if matches!(&transition.variant, TransitionVariant::Evict { .. }) {
                    gov.member_log.push(transition.clone());
                }
                // Both tiers, once, for every governance transition. The evict
                // above used to carry its own copy of this line, which made the
                // reprojection look like part of tombstoning rather than what it
                // is — the projection this branch owes on *any* mutation. Evict
                // semantics are unchanged: the tombstone is still pushed first,
                // so `verify_member_log` sees it and the target's latest
                // member-tier verdict is still removal.
                gov.roles = project_roles(
                    state.verified_bootstrap(),
                    &state.mesh_context_id(),
                    &state.network_id,
                    &gov.transitions,
                    &gov.member_log,
                );
            }
            gov.pending.retain(|p| p.id != proposal_id);
            network_state::save(gov)?;
            Ok(Some(transition))
        })?;

    if let Some(transition) = transition {
        // Mirror role grants into the on-disk roster's `role`
        // projection so peers' rows render with the new authority
        // without re-reading the state log.
        if let TransitionVariant::RoleGrant { target, role } = &transition.variant {
            let mut roster = state.roster.write();
            if !crate::roster::is_authorized(&roster, target) {
                // Granting a role to a non-member is allowed — we
                // add them to the roster too so the local peer
                // list reflects reality.
                crate::roster::add_peer_in(&mut roster, target, "");
            }
            crate::roster::set_role_in(&mut roster, target, *role);
            crate::roster::save(&roster)?;
        }
        if let TransitionVariant::RoleRevoke { target } = &transition.variant {
            // Withdrawal back to a plain member: unlike an evict the device stays
            // in the roster, but its cached authority tag has to drop to `member`
            // so this node's peer rows — and everything that reads the roster role,
            // including the fleet UI's grant/withdraw controls — reflect the
            // demotion at once. The gossip-adoption path already reprojects the
            // whole role map onto the roster; the local ratify path open-codes
            // per-variant mirrors and previously skipped revoke entirely, so on the
            // very device that authored the withdrawal the role never "took".
            let mut roster = state.roster.write();
            if crate::roster::set_role_in(&mut roster, target, Role::Member) {
                crate::roster::save(&roster)?;
            }
        }
        if let TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        } = &transition.variant
        {
            // Founder self-election promoted the local identity to
            // Owner; mirror onto the local roster entry.
            let self_pk = state.identity.public_id().to_string();
            let mut roster = state.roster.write();
            if !crate::roster::is_authorized(&roster, &self_pk) {
                let label = state.identity.label();
                crate::roster::add_peer_in(&mut roster, &self_pk, &label);
            }
            crate::roster::set_role_in(&mut roster, &self_pk, Role::Owner);
            crate::roster::save(&roster)?;
        }
        if let TransitionVariant::Evict { target } = &transition.variant {
            // The evict's whole purpose: drop the target from the roster
            // projection so it loses authorisation here. Because every
            // peer that ratifies this transition runs the same mirror,
            // the removal propagates across the closed network (unlike a
            // bare roster remove, which is local + additive-gossip only).
            let removed = {
                let mut roster = state.roster.write();
                let was = crate::roster::is_authorized(&roster, target);
                if was {
                    crate::roster::remove_peer_in(&mut roster, target);
                    crate::roster::save(&roster)?;
                }
                was
            };
            if removed {
                // Tear down any live session to the evicted device so it
                // can't keep riding an already-open data channel.
                let _ = state.cmd_tx.send(NetworkCmd::DropPeer {
                    device_id: target.clone(),
                    reason: DropReason::Denied,
                });
            }
        }
        if let TransitionVariant::TopologyChange { to } = &transition.variant {
            // The governed shape goes live the moment it ratifies —
            // the same effect as `NetworkCmd::SetTopology`, run inline
            // since ratification already happens on the driver.
            *state.topology.write() = to.clone();
            *state.topology_impl.write() = crate::topology::from_mode(to);
            super::ladder::reevaluate_topology(state).await;
        }

        diag(
            state,
            crate::events::DiagLevel::Info,
            format!("ratified transition: {:?}", transition.variant),
        );
        // A ratified Evict may target THIS device (the online-eviction
        // case: we hold the network's log and just applied our own
        // removal), and a ratified member grant may be our re-admit —
        // settle the cached verdict either way.
        refresh_self_evicted(state);
        // Membership/roles may have changed — summarise so peers reconcile (a
        // member admit shows up as a roster-root + member-log-count bump).
        broadcast_roster_summary(state).await;
        broadcast_state(state).await;
    }

    Ok(())
}

// ---- state broadcast ------------------------------------------------

/// Emit a `NetworkState` snapshot to every active peer. Called
/// after every mutation to keep peers in sync without waiting on
/// the next ACTIVE transition.
pub async fn broadcast_state(state: &Arc<EngineState>) {
    broadcast(
        state,
        MeshMessage::NetworkState(local_state_snapshot(state)),
    )
    .await;
}

/// Activation-triggered state snapshot. Each outbound send retains the exact
/// activating-owner fence, while ordinary governance mutations continue to use
/// [`broadcast_state`].
pub(super) async fn broadcast_state_for_owner(
    state: &Arc<EngineState>,
    owner: &PeerOwnerToken,
) -> bool {
    if state.peers.get_if_current(owner).is_none() {
        return false;
    }
    broadcast_for_owner(
        state,
        owner,
        MeshMessage::NetworkState(local_state_snapshot(state)),
    )
    .await
}

/// Controls for [`current_policy_admits`], which is declared near the top of
/// this file with the rest of the policy projection.
///
/// The module sits here rather than beside what it exercises because a test
/// module is the end of a file by convention, and items following one read as
/// though they were meant to be inside it.
#[cfg(test)]
mod current_policy_controls {
    use super::*;

    #[test]
    fn closed_requires_positive_local_and_remote_roles() {
        let mut gov = network_state::NetworkState::empty_for("closed-policy-control");
        gov.kind = NetworkKind::Closed;
        gov.roles.insert("local".into(), Role::Owner);
        assert!(!current_policy_admits(&gov, "local", "unknown"));
        gov.roles.insert("remote".into(), Role::Member);
        assert!(current_policy_admits(&gov, "local", "remote"));
        gov.roles.remove("local");
        assert!(!current_policy_admits(&gov, "local", "remote"));
    }

    #[test]
    fn open_and_silent_are_only_the_policy_half() {
        for kind in [NetworkKind::Open, NetworkKind::Silent] {
            let mut gov = network_state::NetworkState::empty_for("open-policy-control");
            gov.kind = kind;
            assert!(current_policy_admits(&gov, "local", "remote"));
        }
        // Mutual approval remains a separate conjunct in PeerRegistry's
        // promotion lender; this predicate deliberately does not manufacture
        // that legacy admission fact.
    }
}

/// Controls for the projection [`try_ratify`] owes on a governance transition.
#[cfg(test)]
mod governance_projection_controls {
    use super::*;

    /// A root-signed canonical member grant survives the compatibility mirror.
    ///
    /// This is deliberately production-shaped: an explicit Closed bootstrap
    /// supplies the verified root owner, and the real local `propose` path
    /// creates, graph-admits, ratifies, and projects the member grant. The
    /// legacy transition/pending record is inspected only as compatibility
    /// evidence; it cannot erase the canonical role or roster projection.
    #[tokio::test]
    async fn a_closed_bootstrap_canonical_member_grant_survives_compatibility_projection() {
        let state = crate::engine::build_test_closed_state("canonical-member", [7; 32]);
        let root = state
            .verified_bootstrap()
            .authority_roots()
            .iter()
            .next()
            .cloned()
            .expect("closed bootstrap supplies one verified root");
        let member = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        {
            let gov = state.governance_state.read();
            assert_eq!(gov.kind, NetworkKind::Closed);
            assert_eq!(gov.roles.get(&root.to_string()).copied(), Some(Role::Owner));
        }

        let proposal_id = propose(
            &state,
            TransitionVariant::RoleGrant {
                target: member.clone(),
                role: Role::Member,
            },
            None,
        )
        .await
        .expect("verified bootstrap root can author a member grant");

        {
            let graph = state.authoritative_fact_graph();
            assert!(graph.read().get(&proposal_id).is_some());
            let projected = snapshot(&state);
            assert_eq!(
                projected.roles.get(&root.to_string()).copied(),
                Some(Role::Owner)
            );
            assert_eq!(projected.roles.get(&member).copied(), Some(Role::Member));
        }
        {
            let roster = state.roster.read();
            assert!(
                roster
                    .authorized_devices
                    .iter()
                    .any(|entry| entry.device_id == member && entry.role == Role::Member),
                "canonical member grant must project into the compatibility roster"
            );
        }
        let graph = state.authoritative_fact_graph();
        let graph = graph.read();
        assert!(
            canonical_policy_admits_from(
                state.verified_bootstrap(),
                &graph,
                &root.to_string(),
                &member,
            ),
            "closed policy must admit the root-to-member session"
        );
        assert!(
            canonical_policy_admits_from(
                state.verified_bootstrap(),
                &graph,
                &root.to_string(),
                &root.to_string(),
            ),
            "the verified root owner must retain self-admission"
        );
    }
}

/// Controls for [`state_broadcast_reply`], the anti-entropy decision.
#[cfg(test)]
mod state_broadcast_reply_controls {
    use super::*;

    /// One peer's snapshot as it arrives on the wire. `kind` and the root are
    /// held constant in every control below that is about the counts, so a
    /// verdict is attributable to the numbers under test and nothing else.
    fn snapshot(transitions: u32, members: u32, root: &str) -> NetworkStateBroadcast {
        NetworkStateBroadcast {
            kind: NetworkKind::Open,
            fact_heads_count: transitions.saturating_add(members),
            roster_root: root.to_string(),
        }
    }

    /// A peer that is **behind** us has to be told, because nothing else will.
    ///
    /// The load-bearing control for the whole repair. Every pull condition asks
    /// whether the *sender* is ahead, so the peer holding the newer log used to
    /// see a stale snapshot and say nothing: the staleness was visible to
    /// exactly the one party that had the answer. This fails the moment
    /// `re_advertise` stops firing on a strictly-ahead local count, in either
    /// tier independently — the member tier is the one `cross_approve`'s
    /// open-network grant rides, and the governance tier is the one a founder
    /// election rides.
    #[test]
    fn a_local_count_ahead_of_the_sender_re_advertises() {
        let behind = snapshot(0, 0, "identical-root");

        let ahead_on_members = state_broadcast_reply(0, 1, &behind, false);
        assert!(
            ahead_on_members.re_advertise,
            "a member log the sender has not got must be advertised back to it"
        );
        assert!(
            !ahead_on_members.pull_roster,
            "and we ask a peer that is strictly behind us for nothing"
        );

        let ahead_on_transitions = state_broadcast_reply(1, 0, &behind, false);
        assert!(
            ahead_on_transitions.re_advertise,
            "the governance tier converges the same way — a founder election \
             bumps only this count"
        );
        assert!(!ahead_on_transitions.pull_roster);
    }

    /// The direction that already worked still works, and does not answer.
    ///
    /// Without this half the repair could satisfy the control above by
    /// re-advertising unconditionally, which would turn every received snapshot
    /// into a reply and the pair into a pure echo.
    #[test]
    fn a_sender_ahead_of_us_still_pulls_and_stays_quiet() {
        for ahead in [
            snapshot(0, 1, "identical-root"),
            snapshot(1, 0, "identical-root"),
        ] {
            let reply = state_broadcast_reply(0, 0, &ahead, false);
            assert!(
                reply.pull_roster,
                "a sender holding more than we do is still pulled from"
            );
            assert!(
                !reply.re_advertise,
                "and we do not answer a peer that already has everything we have"
            );
        }
    }

    /// A differing membership root pulls and must **not** re-advertise.
    ///
    /// The echo guard, stated on the one input that is symmetric: two peers
    /// whose roots disagree both see `membership_differs`, so a re-advertise
    /// triggered by it would have each answering the other's answer with no
    /// count ever moving to end it. The roster pull is what resolves a root
    /// disagreement; the snapshot reply is only ever about counts.
    #[test]
    fn a_differing_membership_root_pulls_without_re_advertising() {
        let reply = state_broadcast_reply(2, 2, &snapshot(2, 2, "their-root"), true);
        assert!(
            reply.pull_roster,
            "a root disagreement is resolved by pulling"
        );
        assert!(
            !reply.re_advertise,
            "a symmetric condition must never trigger a reply, or two peers \
             answer each other forever"
        );
    }

    /// Exhaustive: no pair of peers can re-advertise at each other forever.
    ///
    /// The termination argument as a control rather than as a comment. Over
    /// every pair of count vectors in a small grid it checks two things: two
    /// converged peers fall completely silent, which is the fixed point; and
    /// the only way both peers reply at once is a genuine cross-divergence —
    /// each strictly ahead in a *different* tier — in which case both also
    /// pull, so the exchange that follows has equal counts and stops. Any
    /// implementation that answered on a non-strict comparison, or on the
    /// symmetric root, fails here rather than in a mesh three months later.
    #[test]
    fn no_pair_of_peers_can_re_advertise_at_each_other_forever() {
        for a_transitions in 0..4u32 {
            for a_members in 0..4u32 {
                for b_transitions in 0..4u32 {
                    for b_members in 0..4u32 {
                        let a_sees_b = state_broadcast_reply(
                            a_transitions,
                            a_members,
                            &snapshot(b_transitions, b_members, "identical-root"),
                            false,
                        );
                        let b_sees_a = state_broadcast_reply(
                            b_transitions,
                            b_members,
                            &snapshot(a_transitions, a_members, "identical-root"),
                            false,
                        );

                        if a_transitions == b_transitions && a_members == b_members {
                            assert_eq!(
                                (a_sees_b, b_sees_a),
                                (
                                    StateBroadcastReply {
                                        pull_roster: false,
                                        re_advertise: false
                                    },
                                    StateBroadcastReply {
                                        pull_roster: false,
                                        re_advertise: false
                                    }
                                ),
                                "two peers that agree must send nothing at all: \
                                 convergence is the fixed point"
                            );
                            continue;
                        }

                        if a_sees_b.re_advertise && b_sees_a.re_advertise {
                            assert!(
                                (a_transitions > b_transitions && b_members > a_members)
                                    || (a_members > b_members && b_transitions > a_transitions),
                                "both sides may only reply when each is ahead in a \
                                 different tier; anything else is an echo"
                            );
                            assert!(
                                a_sees_b.pull_roster && b_sees_a.pull_roster,
                                "and a real cross-divergence pulls both ways, so the \
                                 next exchange has equal counts and falls silent"
                            );
                        }
                    }
                }
            }
        }
    }
}
