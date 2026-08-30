//! Engine half of closed-network governance.
//!
//! Canonical governance ingress and projection.
//!
//! Signed V4 facts are admitted into the one bootstrap-bound `FactGraph` and
//! broadcast with their exact content address. Compatibility carriers never
//! provide authority; all governance decisions come from the semantic graph.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::events::DropReason;
use crate::network_state::{NetworkKind, Role, TransitionVariant};
use crate::protocol::{
    FactBundleMessage, FactInventory, FactRequest, MeshMessage, NetworkStateBroadcast,
    ProofAckMessage, ProofDeliveryMessage, RosterEntriesMessage, RosterEntry, RosterRequestMessage,
    RosterSummaryMessage,
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

fn signed_fact(
    state: &Arc<EngineState>,
    body: FactBody,
    extra_parents: Vec<FactId>,
) -> Result<SignedFact> {
    let author = canonical_device(state.identity.public_id())?;
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let witness = graph.authoring_witness(&body, &author);
    // Keep the authoring path explicit about the typed AuthorityLineage.  The
    // witness currently derives these same parents, but carrying the heads
    // here makes it impossible for a future ordinary-cell-only witness to
    // omit a cross-cell authority fork or selected branch.
    let mut authority_parents = extra_parents;
    for subject in body.authority_use_subjects(&author) {
        authority_parents.extend(graph.authority_lineage(&subject).heads().iter().copied());
    }
    let content = FactContent::from_authoring_witness(&graph, body, &witness, authority_parents);
    SignedFact::sign(content, state.identity.signing_key())
        .map_err(|error| Error::Other(format!("semantic fact rejected: {error}")))
}

fn admit_authored_fact(state: &Arc<EngineState>, fact: &SignedFact) -> Result<()> {
    let (admission, _) = state.admit_fact_durably(fact.clone())?;
    if matches!(admission, crate::semantic::Admission::Quarantined { .. }) {
        return Err(Error::Other(
            "authored semantic fact is missing a causal parent".into(),
        ));
    }
    Ok(())
}

/// Author one explicit Open participation lifecycle fact for this device.
///
/// Join and rejoin are durable `joined: true` facts; leave is a durable
/// `joined: false` fact. The graph supplies the current participation/authority
/// heads, so refresh and carrier observation can never manufacture a fresh
/// presence fact with an empty causal witness.
fn author_open_self_participation(state: &Arc<EngineState>, joined: bool) -> Result<SignedFact> {
    if !matches!(
        state.verified_bootstrap().policy(),
        crate::semantic::VerifiedProjectPolicy::Open
    ) {
        return Err(Error::Other(
            "Open participation is unavailable on a Closed network".into(),
        ));
    }
    let device_id = canonical_device(state.identity.public_id())?;
    signed_fact(
        state,
        FactBody::OpenParticipation { device_id, joined },
        Vec::new(),
    )
}

async fn commit_open_self_participation(state: &Arc<EngineState>, joined: bool) -> Result<FactId> {
    let fact = author_open_self_participation(state, joined)?;
    admit_authored_fact(state, &fact)?;
    let _ = apply_canonical_projection(state).await;
    broadcast_fact_inventory(state).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    broadcast_state(state).await;
    Ok(fact.id)
}

/// Explicit local Open-network lifecycle join.
pub(crate) async fn join_open_participation(state: &Arc<EngineState>) -> Result<FactId> {
    commit_open_self_participation(state, true).await
}

/// Explicit local Open-network lifecycle leave. Refresh, carrier loss,
/// process death, and shutdown deliberately never call this function.
pub(crate) async fn leave_open_participation(state: &Arc<EngineState>) -> Result<FactId> {
    commit_open_self_participation(state, false).await
}

/// Explicit local Open-network lifecycle rejoin, causally following the last
/// participation head rather than manufacturing an independent presence fact.
pub(crate) async fn rejoin_open_participation(state: &Arc<EngineState>) -> Result<FactId> {
    commit_open_self_participation(state, true).await
}

/// Return the complete proof material for the currently effective positive
/// Open-participation value. A projection value may be a `Resolution`, not the
/// terminal `OpenParticipation` fact itself, so forwarding only that value
/// leaves a fresh peer unable to validate the decision.
fn current_open_participation_bundle(state: &Arc<EngineState>) -> Option<Vec<SignedFact>> {
    let device_id = canonical_device(state.identity.public_id()).ok()?;
    let graph = state.authoritative_fact_graph();
    let bundle = graph.read().open_participation_bundle(&device_id);
    bundle
}

/// Return the complete causal proof for the current closed-network eviction of
/// `target`.  The inventory/request exchange can discover these identifiers,
/// but an evicted reconnect is denied before it can become an ordinary active
/// peer, so that first delivery must carry the proof itself.  Starting from
/// both exclusive cells is intentional: an eviction advances role and
/// membership together, while a later causal restoration can advance only one
/// of them.
fn current_eviction_proof_bundle(
    state: &Arc<EngineState>,
    target: &str,
) -> Option<Vec<SignedFact>> {
    let target = canonical_device(target).ok()?;
    let graph = state.authoritative_fact_graph();
    let bundle = graph.read().eviction_proof_bundle(&target);
    bundle
}

/// Compatibility hook retained for the handshake module. Participation is an
/// explicit local lifecycle operation now; handshake promotion may only forward
/// an already-admitted positive fact and must never author a join.
pub(super) async fn announce_open_participation(state: &Arc<EngineState>, owner: &PeerOwnerToken) {
    let Some(bundle) = current_open_participation_bundle(state) else {
        return;
    };
    let _ = super::send_pending_open_participation(state, owner, &bundle).await;
}

/// Strip the display suffix (`-XXXXX`) from a Device ID. The
/// governance store keys everything on the bare pubkey.
fn pk(device_id: &str) -> String {
    crate::signing::pubkey_part(device_id).to_string()
}

/// Canonical policy admission for registry and handshake fences. The bootstrap
/// binding and the shared FactGraph are the only authority inputs;
/// compatibility NetworkState roles are intentionally not consulted.
/// The decision itself is always delegated to the graph's sealed semantic
/// evaluator so every consumer uses one projection and one conflict rule.
pub(super) fn canonical_policy_admits_from(
    bootstrap: &crate::semantic::VerifiedBootstrap,
    graph: &crate::semantic::FactGraph,
    local_device_id: &str,
    remote_device_id: &str,
) -> bool {
    let Ok(local) = crate::semantic::DeviceId::from_canonical_str(local_device_id) else {
        return false;
    };
    let Ok(remote) = crate::semantic::DeviceId::from_canonical_str(remote_device_id) else {
        return false;
    };
    graph.admits_policy_session(bootstrap, &local, &remote)
}

#[derive(Default)]
struct CanonicalProjection {
    roles: BTreeMap<String, Role>,
    evicted: BTreeSet<String>,
    stood_down: BTreeSet<String>,
    open_participation: BTreeMap<String, bool>,
}

/// Convert the sealed semantic projection into the compatibility roster/snapshot
/// shape.  The graph, evaluator, and typed projection decide every value;
/// this adapter only performs compatibility-key conversion and must not grow
/// independent governance rules.
fn canonical_projection_snapshot(state: &Arc<EngineState>) -> CanonicalProjection {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let projection = graph.projection();
    let evaluator = graph.evaluator();
    let mut result = CanonicalProjection::default();

    let mut subjects = BTreeSet::new();
    for root in state.verified_bootstrap().authority_roots().iter() {
        subjects.insert(root.clone());
    }
    for (cell, _) in projection.cells() {
        match cell {
            crate::semantic::ExclusiveCell::Role { subject }
            | crate::semantic::ExclusiveCell::Membership { subject }
            | crate::semantic::ExclusiveCell::OpenParticipation { subject } => {
                subjects.insert(subject.clone());
            }
            crate::semantic::ExclusiveCell::Decision { .. } => {}
        }
    }
    subjects.extend(projection.stand_down_targets().cloned());

    for subject in subjects {
        let subject_string = subject.to_string();
        // Role(C) remains a normal exclusive-cell projection.  The typed
        // AuthorityLineage is an independent currentness fence for the
        // authority that may author that projection; it is not a replacement
        // for Role-cell Resolution semantics.
        let role = evaluator.effective_authorized_role(&subject);
        let membership = evaluator.effective_membership(&subject);
        let stood_down = evaluator.is_stood_down(&subject);
        let open_participation = evaluator.effective_open_participation(&subject);

        if membership == Some(false) {
            result.evicted.insert(subject_string.clone());
        }
        if stood_down {
            result.stood_down.insert(subject_string.clone());
        }
        if let Some(joined) = open_participation {
            result
                .open_participation
                .insert(subject_string.clone(), joined);
        }
        if let Some(role) = role {
            if membership != Some(false) && !stood_down {
                result.roles.insert(
                    subject_string,
                    match role {
                        crate::semantic::Role::Member => Role::Member,
                        crate::semantic::Role::Controller => Role::Controller,
                        crate::semantic::Role::Owner => Role::Owner,
                    },
                );
            }
        }
    }
    result
}

async fn apply_canonical_projection(state: &Arc<EngineState>) -> bool {
    let projection = canonical_projection_snapshot(state);
    let CanonicalProjection {
        roles,
        evicted,
        stood_down,
        ..
    } = projection;
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
        roster.authorized_devices.retain(|entry| {
            roles.contains_key(&entry.device_id)
                && !evicted.contains(&entry.device_id)
                && !stood_down.contains(&entry.device_id)
        });
        changed |= before != roster.authorized_devices.len();
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

/// Verify that any eviction material in a reduced bundle agrees with the
/// canonical projection before it can be acknowledged.  Ordinary governance
/// and participation bundles have no target-level acknowledgement condition;
/// eviction closures do.  In particular, a signed proof is not acknowledged
/// merely because its bytes entered the graph: the exact target must be stood
/// down by the resulting authoritative projection.  The plain `Evict` closure
/// used during a denied handshake is checked against the corresponding
/// membership tombstone instead.
pub(super) fn fact_bundle_projection_is_verified(
    state: &Arc<EngineState>,
    facts: &[SignedFact],
) -> bool {
    state
        .authoritative_fact_graph()
        .read()
        .bundle_projection_is_verified(facts)
}

/// Verify the target-bound projection condition for one typed proof delivery.
/// The wire identity is checked by `ProofDeliveryMessage::validate`; this
/// predicate adds the receiver's exact mesh-context fence and requires the
/// delivery target itself to be represented by the resulting canonical
/// stand-down/eviction projection. A valid bundle for some other target can
/// therefore never settle this delivery.
pub(super) fn proof_delivery_projection_is_verified(
    state: &Arc<EngineState>,
    delivery: &ProofDeliveryMessage,
) -> bool {
    if delivery.context_id != state.mesh_context_id() {
        return false;
    }
    let graph = state.authoritative_fact_graph();
    let verified = graph
        .read()
        .proof_bundle_is_verified(&delivery.target, &delivery.facts);
    verified
}

/// A FactBundle acknowledgement is the receiver's exact current inventory on
/// the same logical route that requested the bundle.  It is deliberately an
/// inventory rather than a new authority fact: the sender learns which signed
/// facts actually entered our graph and can request any remaining causal
/// dependencies, while the route only selects where the coordination reply is
/// sent.  This also works for a disconnected/offline proof source when the
/// next exact session is established; no heartbeat or carrier observation is
/// treated as acknowledgement.
pub(super) async fn acknowledge_fact_bundle(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
) {
    let inventory = MeshMessage::FactInventory(local_fact_inventory(state));
    if let Err(error) = super::send_logical_reply(state, route, &inventory).await {
        tracing::debug!(
            peer = %route.owner().device_id(),
            %error,
            "fact bundle acknowledgement send failed"
        );
    }
}

/// Emit the only verified receipt for a typed proof delivery. The exact
/// context, target, and content-derived delivery identity are copied from the
/// validated wire envelope; no generic inventory can settle this proof.
pub(super) async fn acknowledge_proof_delivery(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    delivery: &ProofDeliveryMessage,
) {
    let ack = MeshMessage::ProofAck(ProofAckMessage::for_delivery(delivery));
    if let Err(error) = super::send_logical_reply(state, route, &ack).await {
        tracing::debug!(
            peer = %route.owner().device_id(),
            %error,
            "proof delivery acknowledgement send failed"
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
async fn request_pending_approval(
    state: &Arc<EngineState>,
    peer_id: &str,
    _echo_open_participation: bool,
) {
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

// ---- local proposals ------------------------------------------------

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

/// Author and broadcast the owner-signed membership restoration fact used
/// after a Closed eviction. Membership admission and the role grant remain
/// separate canonical cells; callers must issue the causal RoleGrant(Member)
/// afterward when session authority is also being restored.
pub async fn propose_membership_admit(
    state: &Arc<EngineState>,
    target: &str,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    crate::custody::require(&state.network_id, mfa_code)?;
    let fact = signed_fact(
        state,
        FactBody::MembershipAdmit {
            target: canonical_device(target)?,
        },
        Vec::new(),
    )?;
    admit_authored_fact(state, &fact)?;
    let _ = apply_canonical_projection(state).await;
    broadcast_fact_inventory(state).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    broadcast_state(state).await;
    Ok(fact.id)
}

/// Legacy proposal controls are inert during the canonical V4 migration.
/// Callers must submit a canonical fact instead; no proposal or transition log
/// is created here.
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

/// Admit one verified canonical fact and project it into the read-only
/// compatibility view. The carrier and compatibility logs are never used as
/// authority.
pub(super) async fn on_fact(state: &Arc<EngineState>, fact: SignedFact) {
    if let Err(error) = fact.verify() {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!("rejecting invalid semantic fact {error}"),
        );
        return;
    }
    let admission = state.admit_fact_durably(fact.clone());
    let (admission, _) = match admission {
        Ok(admission) => admission,
        Err(error) => {
            diag(
                state,
                crate::events::DiagLevel::Warn,
                format!("rejecting semantic fact admission: {error}"),
            );
            return;
        }
    };
    if matches!(admission, crate::semantic::Admission::Quarantined { .. }) {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            "deferring semantic fact with missing causal parent",
        );
        return;
    }
    let changed = apply_canonical_projection(state).await;
    // Fact admission is the explicit lifecycle boundary for terminal recovery.
    // Refresh the local stand-down cache, then reconcile only the subject whose
    // canonical cell may have changed. Recovery never waits for a ticker to
    // discover that signed policy has become negative.
    refresh_self_evicted(state);
    match &fact.content.body {
        FactBody::RoleGrant { target, .. }
        | FactBody::RoleRevoke { target }
        | FactBody::Evict { target }
        | FactBody::MembershipAdmit { target }
        | FactBody::EvictionProof { target, .. }
        | FactBody::Attestation { target, .. } => {
            super::reconcile_terminal_recovery_policy(state, target);
        }
        FactBody::OpenParticipation { device_id, .. }
        | FactBody::SelfStandDown { device_id, .. } => {
            super::reconcile_terminal_recovery_policy(state, device_id);
        }
        FactBody::Resolution { cell, .. } => match cell {
            crate::semantic::ExclusiveCell::Role { subject }
            | crate::semantic::ExclusiveCell::Membership { subject }
            | crate::semantic::ExclusiveCell::OpenParticipation { subject } => {
                super::reconcile_terminal_recovery_policy(state, subject);
            }
            crate::semantic::ExclusiveCell::Decision { .. } => {}
        },
        FactBody::AuthorityLineageResolution { subject, .. } => {
            super::reconcile_terminal_recovery_policy(state, subject);
        }
    }
    broadcast_fact_inventory(state).await;
    if changed {
        broadcast_roster_summary(state).await;
        broadcast_state(state).await;
    }
    match &fact.content.body {
        FactBody::RoleGrant { target, .. } if pk(target) == pk(state.identity.public_id()) => {
            request_pending_approval(state, &fact.content.author, false).await;
        }
        FactBody::OpenParticipation {
            device_id,
            joined: true,
        } => {
            request_pending_approval(state, device_id, true).await;
        }
        _ => {}
    }
}

/// What one received `NetworkState` snapshot obliges us to send back.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateBroadcastReply {
    /// Ask the sender for semantic facts: they hold something we do not.
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

/// Inbound roster entries. The unsigned entries are carrier material,
/// never an authority-bearing membership update. Canonical signed facts arrive
/// through semantic inventory/fact exchange and alone change durable state.
pub async fn on_roster_entries(state: &Arc<EngineState>, source: &str, msg: RosterEntriesMessage) {
    if !msg.entries.is_empty() {
        diag(
            state,
            crate::events::DiagLevel::Debug,
            format!(
                "roster: ignored {} unsigned entry(ies) from {} (membership is derived from signed facts)",
                msg.entries.len(),
                &source[..source.len().min(12)]
            ),
        );
    }
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
/// signed state. Only meaningful on closed governance (open networks have no
/// signed membership); false there. The verdict is derived from the sealed
/// semantic membership projection, so compatibility roster data cannot outrank
/// the canonical graph.
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
        // Ratification and adopted-log refreshes can reach this edge without
        // passing through the mod.rs subject reconciler.  Detach the current
        // exact carrier guards before clearing recovery custody so a stale
        // source cannot retain or settle an emission after self-eviction.
        state.detach_signaling_guards();
        state.cancel_all_recovery_demands();
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
/// auto-approve; those were exactly the resurrection engine). The signed
/// eviction closure is sent over the durable semantic lane before the denial,
/// so the denied device can verify it independently through causal admission;
/// a spoofed transport deny still changes nothing.
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
    // Deliver the signed eviction closure before ending this installation.
    // Pending peers use the narrow semantic lane; an already-active test/lab
    // installation uses the ordinary application lane. Both are owner-bound,
    // provider-funded writes, and either refusal leaves the proof available for
    // the next inventory/request exchange rather than changing the decision.
    if let Some(bundle) = current_eviction_proof_bundle(state, device_id) {
        let message = MeshMessage::FactBundle(crate::protocol::FactBundleMessage {
            facts: bundle.clone(),
        });
        let proof_result = match super::send_pending_open_participation(state, owner, &bundle).await
        {
            Ok(()) => Ok(()),
            Err(_) => super::send_to_peer_owner(state, owner, &message).await,
        };
        if let Err(error) = proof_result {
            tracing::debug!(
                peer = %device_id,
                %error,
                "eviction proof bundle delivery failed"
            );
        }
    }
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

/// Controls for semantic proof forwarding.
#[cfg(test)]
mod governance_projection_controls {
    use super::*;

    /// The pending-peer path carries a real causal proof, not whichever
    /// terminal body happens to be visible at the sender.  A fork is refused
    /// until the local author resolves it; once resolved, a fresh graph can
    /// admit the complete bundle and project the same positive value.
    #[tokio::test]
    async fn open_participation_forwards_conflict_resolution_to_a_fresh_graph() {
        let state = crate::engine::build_test_state("open-proof-forwarding");
        crate::engine::join_open_participation(&state)
            .await
            .expect("explicit local join admits");
        let local = DeviceId::from_canonical_str(state.identity.public_id())
            .expect("fixture identity is canonical");
        let cell = crate::semantic::ExclusiveCell::open_participation(local.clone());
        let initial = {
            let graph = state.authoritative_fact_graph();
            let graph = graph.read();
            let id = graph
                .projection()
                .value(&cell)
                .expect("join projects a value");
            graph.get(&id).cloned().expect("join remains stored")
        };

        let branch = |joined: bool| {
            let content = FactContent::open_participation(
                state.mesh_context_id(),
                local.clone(),
                joined,
                vec![initial.id],
            );
            SignedFact::sign(content, state.identity.signing_key())
                .expect("self-authored branch signs")
        };
        let left = branch(false);
        let right = branch(true);
        {
            let graph = state.authoritative_fact_graph();
            let mut graph = graph.write();
            graph.admit(left.clone()).expect("negative branch admits");
            graph.admit(right.clone()).expect("positive branch admits");
        }
        assert!(
            current_open_participation_bundle(&state).is_none(),
            "a joined true/false conflict has no forwardable value"
        );

        let mut cited = vec![left.id, right.id];
        cited.sort();
        let resolution = {
            let graph = state.authoritative_fact_graph();
            let graph = graph.read();
            let body = FactBody::Resolution {
                cell: cell.clone(),
                cited_heads: cited.clone(),
                selected_head: right.id,
            };
            let witness = graph.authoring_witness(&body, &local);
            let content =
                FactContent::from_authoring_witness(&graph, body, &witness, std::iter::empty());
            SignedFact::sign(content, state.identity.signing_key())
                .expect("self-authored resolution signs")
        };
        state
            .authoritative_fact_graph()
            .write()
            .admit(resolution.clone())
            .expect("self resolution admits");

        let bundle = current_open_participation_bundle(&state)
            .expect("resolved positive value has a forwardable proof");
        let bundle_ids: BTreeSet<_> = bundle.iter().map(|fact| fact.id).collect();
        assert!(bundle_ids.contains(&resolution.id));
        assert!(bundle_ids.contains(&left.id));
        assert!(bundle_ids.contains(&right.id));
        assert!(bundle_ids.contains(&initial.id));
        assert!(bundle
            .iter()
            .all(|fact| { fact.content.mesh_context == state.mesh_context_id() }));

        let mut fresh = crate::semantic::FactGraph::from_bootstrap(state.verified_bootstrap());
        for fact in bundle {
            fresh
                .admit(fact)
                .expect("fresh graph accepts proof material");
            let _ = fresh.retry_quarantined();
        }
        assert_eq!(
            fresh.evaluator().effective_open_participation(&local),
            Some(true),
            "the proof bundle alone reconstructs the resolved joined value"
        );
    }

    #[tokio::test]
    async fn eviction_proof_bundle_contains_the_exact_causal_closure() {
        let state = crate::engine::build_test_closed_state("eviction-proof-bundle", [10; 32]);
        let target = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        let evict_id = propose(
            &state,
            TransitionVariant::Evict {
                target: target.clone(),
            },
            None,
        )
        .await
        .expect("the verified root can author an eviction");

        let bundle = current_eviction_proof_bundle(&state, &target)
            .expect("a current eviction has a deliverable proof closure");
        let bundle_ids: BTreeSet<_> = bundle.iter().map(|fact| fact.id).collect();
        assert!(bundle_ids.contains(&evict_id));
        assert!(
            bundle.iter().all(|fact| {
                crate::semantic::causal::dependencies(fact)
                    .into_iter()
                    .all(|dependency| bundle_ids.contains(&dependency))
            }),
            "an offline proof bundle must carry every causal dependency"
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
