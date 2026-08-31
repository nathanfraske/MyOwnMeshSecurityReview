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
use crate::protocol::{
    FactBundleMessage, FactInventory, FactRequest, MeshMessage, ProofAckMessage,
    ProofDeliveryMessage,
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
    let _ = apply_canonical_projection(state);
    broadcast_fact_inventory(state).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
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
/// binding and the shared FactGraph are the only authority inputs.
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
    roles: BTreeMap<String, crate::semantic::Role>,
    evicted: BTreeSet<String>,
    stood_down: BTreeSet<String>,
    open_participation: BTreeMap<String, bool>,
}

/// Convert the sealed semantic projection into the read-only roster shape. The
/// graph, evaluator, and typed projection decide every value; this projection
/// performs only key conversion and has no independent governance rules.
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
                        crate::semantic::Role::Member => crate::semantic::Role::Member,
                        crate::semantic::Role::Controller => crate::semantic::Role::Controller,
                        crate::semantic::Role::Owner => crate::semantic::Role::Owner,
                    },
                );
            }
        }
    }
    result
}

pub(super) fn apply_canonical_projection(state: &Arc<EngineState>) -> bool {
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
        // delivery to the others. The next fact inventory pass will repair
        // any advertisement lost while this channel was unavailable.
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

struct FactInventoryCursor {
    graph: Arc<parking_lot::RwLock<crate::semantic::FactGraph>>,
    context_id: crate::semantic::MeshContextId,
    cursor: Option<FactId>,
    finished: bool,
    invalid: bool,
}

impl FactInventoryCursor {
    fn next_page(&mut self) -> Option<FactInventory> {
        if self.finished || self.invalid {
            return None;
        }
        let mut fact_ids = Vec::new();
        let graph = self.graph.read();
        for fact_id in graph.ids_after(self.cursor) {
            let mut candidate_ids = fact_ids.clone();
            candidate_ids.push(*fact_id);
            let candidate = FactInventory::new(self.context_id, candidate_ids);
            let encoded_len = match serde_json::to_vec(&MeshMessage::FactInventory(candidate)) {
                Ok(encoded) => encoded.len(),
                Err(_) => {
                    self.invalid = true;
                    return None;
                }
            };
            if encoded_len > crate::protocol::RECEIVE_FRAME_BYTES {
                if fact_ids.is_empty() {
                    self.invalid = true;
                    return None;
                }
                break;
            }
            fact_ids.push(*fact_id);
        }
        drop(graph);
        if fact_ids.is_empty() {
            self.finished = true;
            return None;
        }
        self.cursor = fact_ids.last().copied();
        Some(FactInventory::new(self.context_id, fact_ids))
    }

    fn is_valid(&self) -> bool {
        !self.invalid
    }
}

fn local_fact_inventory_cursor(state: &Arc<EngineState>) -> FactInventoryCursor {
    FactInventoryCursor {
        graph: state.authoritative_fact_graph(),
        context_id: state.mesh_context_id(),
        cursor: None,
        finished: false,
        invalid: false,
    }
}

/// Advertise the exact canonical graph inventory to active peers.  The
/// inventory contains identifiers only; it is a repair hint, never authority.
pub async fn broadcast_fact_inventory(state: &Arc<EngineState>) {
    let owners = inventory_peer_owners(state);
    for owner in owners {
        let mut inventory = local_fact_inventory_cursor(state);
        while let Some(page) = inventory.next_page() {
            let result =
                super::send_to_peer_owner(state, &owner, &MeshMessage::FactInventory(page)).await;
            if let Err(error) = result {
                tracing::debug!(peer = %owner.device_id(), %error, "fact inventory broadcast send failed");
            }
        }
        if !inventory.is_valid() {
            tracing::debug!(peer = %owner.device_id(), "fact inventory cannot fit the exact receive-safe frame boundary");
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
    let mut inventory = local_fact_inventory_cursor(state);
    while let Some(page) = inventory.next_page() {
        if !broadcast_for_owner(state, owner, MeshMessage::FactInventory(page)).await {
            return false;
        }
    }
    if !inventory.is_valid() {
        tracing::debug!(peer = %owner.device_id(), "owner-bound fact inventory exceeds the exact receive-safe frame boundary");
        return false;
    }
    true
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
    // A page is only a one-way repair hint. Do not answer it with a partial
    // reciprocal inventory: that would echo every page back and keep two
    // incomparable inventories alive indefinitely. The periodic/event-driven
    // full inventory pass repairs lost pages and converges once missing ids
    // have been admitted.
    let missing = {
        let graph = state.authoritative_fact_graph();
        let graph = graph.read();
        let missing = inventory
            .fact_ids()
            .iter()
            .copied()
            .filter(|id| graph.get(id).is_none())
            .collect::<Vec<_>>();
        missing
    };
    if !missing.is_empty() {
        let request = FactRequest::new(state.mesh_context_id(), missing);
        let mut pages = request.pages();
        while let Some(fact_ids) = pages.next() {
            let page = FactRequest::new(request.context_id(), fact_ids);
            let result =
                super::send_logical_reply(state, route, &MeshMessage::FactRequest(page)).await;
            if let Err(error) = result {
                tracing::debug!(
                    peer = %route.owner().device_id(),
                    %error,
                    "fact inventory request send failed"
                );
                break;
            }
        }
        if !pages.is_valid() {
            tracing::debug!(peer = %route.owner().device_id(), "fact inventory request exceeds the exact receive-safe frame boundary");
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
    let mut page_facts = Vec::new();
    for id in request.fact_ids() {
        let Some(fact) = state.authoritative_fact_graph().read().get(id).cloned() else {
            continue;
        };
        page_facts.push(fact);
        let Some(encoded_len) = FactBundleMessage::encoded_len_for_facts(&page_facts) else {
            tracing::debug!(peer = %route.owner().device_id(), "fact bundle page could not be sized");
            return;
        };
        if encoded_len > crate::protocol::RECEIVE_FRAME_BYTES {
            let last = page_facts.pop().expect("the just-added fact is present");
            if page_facts.is_empty() {
                match send_single_fact_page(state, route, last).await {
                    Ok(true) => continue,
                    Ok(false) => {
                        tracing::debug!(peer = %route.owner().device_id(), "fact bundle and single fact exceed the exact receive-safe frame boundary");
                        // This exact fact cannot cross the receive boundary.
                        // It is not a transport failure: continue the request
                        // so later individually transmittable facts are not
                        // starved behind it.
                        continue;
                    }
                    Err(error) => {
                        tracing::debug!(peer = %route.owner().device_id(), %error, "single fact reply send failed");
                        return;
                    }
                }
            }
            if send_fact_bundle_page(state, route, std::mem::take(&mut page_facts))
                .await
                .is_err()
            {
                tracing::debug!(
                    peer = %route.owner().device_id(),
                    "fact bundle reply send failed"
                );
                return;
            }
            page_facts.push(last);
            if FactBundleMessage::encoded_len_for_facts(&page_facts)
                .is_none_or(|length| length > crate::protocol::RECEIVE_FRAME_BYTES)
            {
                let last = page_facts.pop().expect("the just-added fact is present");
                match send_single_fact_page(state, route, last).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::debug!(peer = %route.owner().device_id(), "fact bundle and single fact exceed the exact receive-safe frame boundary");
                        // Skip only this untransmittable fact. A later
                        // request item still deserves its own exact attempt.
                    }
                    Err(error) => {
                        tracing::debug!(peer = %route.owner().device_id(), %error, "single fact reply send failed");
                        return;
                    }
                }
            }
        }
    }
    if !page_facts.is_empty()
        && send_fact_bundle_page(state, route, page_facts)
            .await
            .is_err()
    {
        tracing::debug!(peer = %route.owner().device_id(), "fact bundle reply send failed");
    }
}

async fn send_fact_bundle_page(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    facts: Vec<crate::semantic::SignedFact>,
) -> Result<()> {
    super::send_logical_reply(
        state,
        route,
        &MeshMessage::FactBundle(FactBundleMessage { facts }),
    )
    .await
}

/// Send one canonical fact when its one-item bundle envelope would be too
/// large. The standalone `fact` frame has a different envelope and may still
/// fit the exact receive boundary; refusing only after checking that frame
/// preserves later requested IDs instead of abandoning the whole request.
async fn send_single_fact_page(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    fact: crate::semantic::SignedFact,
) -> Result<bool> {
    let message = MeshMessage::Fact(fact);
    let encoded_len = serde_json::to_vec(&message)
        .map(|encoded| encoded.len())
        .map_err(Error::Serde)?;
    if encoded_len > crate::protocol::RECEIVE_FRAME_BYTES {
        return Ok(false);
    }
    super::send_logical_reply(state, route, &message).await?;
    Ok(true)
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
    let mut inventory = local_fact_inventory_cursor(state);
    while let Some(page) = inventory.next_page() {
        if let Err(error) =
            super::send_logical_reply(state, route, &MeshMessage::FactInventory(page)).await
        {
            tracing::debug!(
                peer = %route.owner().device_id(),
                %error,
                "fact bundle acknowledgement send failed"
            );
            break;
        }
    }
    if !inventory.is_valid() {
        tracing::debug!(peer = %route.owner().device_id(), "fact bundle acknowledgement exceeds the exact receive-safe frame boundary");
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

/// Admit, project, and publish one already-typed canonical governance fact.
/// The read-only roster projection is refreshed only after durable graph
/// admission.
async fn commit_proposal(
    state: &Arc<EngineState>,
    body: FactBody,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    crate::custody::require(&state.network_id, mfa_code)?;
    let fact = signed_fact(state, body, Vec::new())?;
    admit_authored_fact(state, &fact)?;
    let _ = apply_canonical_projection(state);
    broadcast_fact_inventory(state).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    if let FactBody::RoleGrant { target, role } = &fact.content.body {
        if *role == crate::semantic::Role::Member
            && canonical_projection_snapshot(state).roles.get(&pk(target))
                == Some(&crate::semantic::Role::Member)
        {
            if let Some(owner) = send_pending_role_grant(state, target, &fact).await {
                super::handshake::reevaluate_after_role_grant(state, &owner).await;
            }
        }
    }
    Ok(fact.id)
}

/// Author and publish an exact canonical role grant.
pub async fn propose_role_grant(
    state: &Arc<EngineState>,
    target: &str,
    role: crate::semantic::Role,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    commit_proposal(
        state,
        FactBody::RoleGrant {
            target: canonical_device(target)?,
            role,
        },
        mfa_code,
    )
    .await
}

/// Author and publish an exact canonical role revoke.
pub async fn propose_role_revoke(
    state: &Arc<EngineState>,
    target: &str,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    commit_proposal(
        state,
        FactBody::RoleRevoke {
            target: canonical_device(target)?,
        },
        mfa_code,
    )
    .await
}

/// Author and publish an exact canonical eviction.
pub async fn propose_evict(
    state: &Arc<EngineState>,
    target: &str,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    commit_proposal(
        state,
        FactBody::Evict {
            target: canonical_device(target)?,
        },
        mfa_code,
    )
    .await
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
    let _ = apply_canonical_projection(state);
    broadcast_fact_inventory(state).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    Ok(fact.id)
}

/// Admit one verified canonical fact and project it into the read-only roster
/// view. The carrier and projection are never used as authority.
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
    apply_canonical_projection(state);
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

// ---- retired roster wire hooks -------------------------------------
//
// The roster remains a local semantic projection. Legacy lifecycle call
// sites are retained as no-op hooks; canonical signed facts are the only
// authority and no unsigned roster wire frame is emitted or consumed.
//
// No roster summary is broadcast; this retired hook area is intentionally empty.
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
/// semantic membership projection, so roster data cannot outrank the canonical
/// graph.
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
        let evict_id = propose_evict(&state, &target, None)
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

    #[test]
    fn fact_inventory_cursor_streams_receive_safe_pages_and_reaches_quiescence() {
        let state = crate::engine::build_test_state("fact-inventory-cursor-controls");
        let context_id = state.mesh_context_id();
        let author = DeviceId::from_canonical_str(state.identity.public_id())
            .expect("fixture identity is canonical");
        let mut graph = crate::semantic::FactGraph::from_bootstrap(state.verified_bootstrap());

        // Use valid signed facts in a real graph, while varying only the
        // causal parent so the producer sees a large deterministic key set.
        // The cursor itself retains no graph-wide collection.
        for index in 0..2_048u64 {
            let mut parent = [0u8; 32];
            parent[..8].copy_from_slice(&index.to_be_bytes());
            let content = FactContent::open_participation(
                context_id,
                author.clone(),
                index % 2 == 0,
                vec![FactId::from_bytes(parent)],
            );
            let fact = SignedFact::sign(content, state.identity.signing_key())
                .expect("fixture fact signs");
            graph.facts.insert(fact.id, fact);
        }
        let expected_ids = graph.len();
        let graph = Arc::new(parking_lot::RwLock::new(graph));
        let mut cursor = FactInventoryCursor {
            graph,
            context_id,
            cursor: None,
            finished: false,
            invalid: false,
        };
        let mut page_count = 0;
        let mut observed = BTreeSet::new();

        while let Some(page) = cursor.next_page() {
            page_count += 1;
            let encoded = serde_json::to_vec(&MeshMessage::FactInventory(page.clone()))
                .expect("inventory page serializes");
            assert!(encoded.len() <= crate::protocol::RECEIVE_FRAME_BYTES);
            assert!(page.fact_ids().windows(2).all(|pair| pair[0] < pair[1]));
            observed.extend(page.fact_ids().iter().copied());
        }

        assert!(cursor.is_valid());
        assert!(page_count >= 2, "control must exercise multiple pages");
        assert_eq!(observed.len(), expected_ids);
        assert!(
            cursor.next_page().is_none(),
            "a drained cursor is quiescent"
        );
    }
}
