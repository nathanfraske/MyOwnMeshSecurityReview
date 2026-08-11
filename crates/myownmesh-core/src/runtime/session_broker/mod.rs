//! Session Broker: the one atomic promotion into `SessionCapability`.
//!
//! Arc 02 defined the output types and left the transition unimplemented. This
//! module implements it. Promotion consumes, in one call and with no partial
//! commit:
//!
//! - one `AuthenticatedChannelCapability` for the exact current connector;
//! - the current policy answer, produced by the narrow temporary adapter in
//!   [`policy`] over the engine's existing admission state;
//! - one explicit local process principal;
//! - one real post-authentication resource reservation.
//!
//! Two invalidations are structural rather than checked by a timer or a
//! generation counter. Connector replacement invalidates because the capability
//! privately retains the exact `ConnectorIncarnation` it was promoted from, and
//! every use compares that `Arc` by pointer identity against the installed one.
//! Process restart invalidates because nothing here is serializable, durable, or
//! reconstructible from a label — the whole chain is memory-only.
//!
//! There is deliberately no identity, attestation, or migration framework here,
//! no timer, generation, or route authority, and no compatibility mode. A
//! session is promoted or it is not.

pub(crate) mod policy;

use std::sync::Arc;

use crate::application_gateway::LocalPrincipalCapability;
use crate::connector::ConnectorIncarnation;
use crate::endpoint_auth::AuthenticatedChannelCapability;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease, ResourceUnavailable};
use crate::runtime::attempt::MeshConnectorResourceScope;
use crate::runtime::RuntimeIncarnation;

pub(crate) use policy::CurrentPolicyAdmission;

/// The post-authentication reservation one promoted session holds.
///
/// Mechanically derived from the state a promotion actually creates, so these
/// numbers cannot drift from the objects they pay for. A promotion constructs
/// exactly one of each of these and holds both for the session's whole life:
///
/// - the session record — [`SessionCapability`], which owns by value the
///   authenticated channel it was promoted from, the shared local principal
///   handle, the connector identity, and the permit carrying this very
///   reservation; and
/// - the session-owned realtime flow set —
///   [`SessionRealtimeFlows`](crate::transport::webrtc::SessionRealtimeFlows),
///   built by the exact connector this session was promoted from and dropped
///   with the session that owns it.
///
/// Both terms are `size_of`, read from the types themselves. There is no
/// estimate, no per-peer multiplier, and no number written out that a later
/// field addition could silently invalidate.
///
/// Two exclusions are **by design**. The `RealtimeFlowRegistry` the flow set
/// holds is the connector's own and preexisting — promotion clones the handle,
/// it does not allocate the registry — so charging it here would bill a session
/// for something that outlives it. And every per-flow, queue and payload lease
/// is charged where it is taken, against limits the connector's realtime policy
/// chooses; a session that opens no flow must not pre-pay for flows.
///
/// The third term is the heap `SessionRealtimeFlows::new` allocates for the set
/// promotion builds: the flow-set token, the arrival stream, the lifecycle
/// stream, and the inbound bindings, each with its `Arc` counter words. Those
/// three of four types are private to the connector, so the size is asked of the
/// connector rather than restated here — restating it is precisely the
/// hand-written cost this claim exists to remove, and a field added to
/// `SessionStream` would silently stop being paid for.
///
/// It is worth knowing that the third term is exhaustive *by maintenance*, not
/// by construction: a fifth root added to `new` and not added there is a mistake
/// no compiler catches. The mitigation is that the function lives beside `new`.
///
/// Deliberately not derived from anything measured before authentication — a
/// pre-authentication lease cannot be reused as proof that this capacity exists.
fn session_claim() -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let bytes = std::mem::size_of::<SessionCapability>()
        .checked_add(std::mem::size_of::<
            crate::transport::webrtc::SessionRealtimeFlows,
        >())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([(ResourceClass::AccountedMemoryBytes, bytes)])?
        .checked_add(crate::transport::webrtc::SessionRealtimeFlows::promotion_root_claim()?)
}

/// Proof that post-authentication session capacity was reserved.
///
/// There is no conversion from `PreAuthAttemptPermit` into this type, and none
/// from `AuthenticatedChannelCapability` either: an authenticated channel is not
/// an authorized session. It privately owns the provider lease, so dropping the
/// permit releases exactly the reservation it took and nothing else.
pub(crate) struct SessionPermit {
    runtime: RuntimeIncarnation,
    /// Held for its `Drop`. The reservation exists for as long as the permit
    /// does, which is for as long as the session it was promoted into.
    _lease: ResourceLease,
}

impl SessionPermit {
    fn reserve(
        scope: &MeshConnectorResourceScope,
        runtime: RuntimeIncarnation,
    ) -> Result<Self, ResourceUnavailable> {
        let lease = scope.reserve_session(session_claim().expect(
            "the session claim is `size_of` arithmetic over fixed types and cannot overflow",
        ))?;
        Ok(Self {
            runtime,
            _lease: lease,
        })
    }

    /// The runtime this reservation was taken under.
    ///
    /// The session reads its runtime from here rather than from the channel:
    /// the permit is the post-authentication authority, and `promote` has
    /// already proved the two agree.
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }
}

/// Memory-only authority for application use of one promoted peer session.
///
/// The only way to obtain one is [`SessionBroker::promote`], from a verified
/// authenticated channel. Not `Clone`, not serializable, no id field, no
/// constructor taking a label — so a peer string, socket, or stored client
/// record cannot produce one, and possession cannot be transferred or replayed.
pub(crate) struct SessionCapability {
    /// The channel this session was promoted from. Held by value: the session
    /// *is* the authenticated channel's application-facing continuation, and
    /// dropping the session returns the connected claim to the connector.
    authenticated_channel: AuthenticatedChannelCapability,
    /// The one local process principal, shared rather than re-minted.
    ///
    /// `Arc` because there is exactly one authenticated local principal per
    /// process and every session speaks for that same one. Sharing it is not
    /// cloning authority — a second `LocalPrincipalCapability` value would be a
    /// second principal, which is precisely the generic identity framework the
    /// directive excludes.
    local_principal: Arc<LocalPrincipalCapability>,
    permit: SessionPermit,
    /// The exact connector this session was promoted from, retained privately
    /// so currentness is decided by pointer identity rather than by a device id
    /// a replacement may since have taken over.
    connector: Arc<ConnectorIncarnation>,
}

impl SessionCapability {
    fn runtime(&self) -> &RuntimeIncarnation {
        self.permit.runtime()
    }

    /// Whether this session was promoted from that exact connector incarnation.
    ///
    /// This is the replacement-invalidation predicate, and it is **identity
    /// only**. A session promoted from a superseded connector answers `false`
    /// against the replacement's incarnation, with no timer, generation counter,
    /// or revocation list.
    ///
    /// Liveness is deliberately not answered here, for the same reason
    /// [`ConnectorIncarnation`] does not answer it: the transport's own
    /// incarnation is the single authoritative source for whether a connector is
    /// still live, and a second flag on this side could disagree with it. A
    /// consumer that needs "the same connector **and** still live" — every
    /// send-time gate does — pairs this with the transport's own liveness:
    ///
    /// ```text
    /// session.belongs_to(incarnation.generic()) && incarnation.is_active()
    /// ```
    ///
    /// A session is never re-bound to a replacement connector. Replacement
    /// invalidates it and the application promotes a new one; an authority that
    /// followed its peer across channels would be the cross-channel relay the
    /// non-session-unique binding cannot rule out on its own.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<ConnectorIncarnation>) -> bool {
        Arc::ptr_eq(&self.connector, incarnation)
    }

    /// Whether this session authenticates that exact mesh and remote Device.
    ///
    /// Read from the channel's own private record, never from a caller-supplied
    /// label, so a session for one context cannot be presented for another.
    /// The §7.3 recheck every application operation owes, in one call.
    ///
    /// Promotion proved these once. This proves them *again at use*, which is
    /// the point: a cached session outlives the instant it was minted, and the
    /// facts it rests on can move underneath it. Each conjunct is read from the
    /// session's own private record or from an identity comparison, never from a
    /// caller-supplied label.
    ///
    /// - the exact connector, so replacement invalidates;
    /// - the exact mesh context and remote Device, so a session cannot be
    ///   presented for a peer or a network it was not authenticated for;
    /// - the local principal and the reservation, still bound to the runtime the
    ///   broker is currently promoting under.
    pub(crate) fn is_current_for(
        &self,
        connector: &Arc<ConnectorIncarnation>,
        mesh_context: &str,
        remote_device_id: &str,
        runtime: &RuntimeIncarnation,
    ) -> bool {
        self.belongs_to(connector)
            && self.remote_device_id() == remote_device_id
            && self.authenticated_for(mesh_context, remote_device_id)
            && self.runtime().is_same(runtime)
            && self.local_principal().runtime().is_same(runtime)
    }

    pub(crate) fn authenticated_for(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.authenticated_channel
            .authenticated_for(mesh_context, remote_device_id)
    }

    /// The exact remote Device this session was authenticated against.
    ///
    /// For attribution only. It is derived from the authenticated record, so it
    /// cannot be used to *reach* a peer — reaching one requires presenting this
    /// capability to the registry fence, which revalidates it.
    pub(crate) fn remote_device_id(&self) -> &str {
        self.authenticated_channel.record().remote_device_id()
    }

    pub(crate) fn local_principal(&self) -> &LocalPrincipalCapability {
        &self.local_principal
    }
}

/// Why one promotion did not happen.
///
/// Every variant is a statement about *this* promotion attempt. None of them
/// retires the channel or the connector: refusing to promote leaves the caller's
/// own fail-closed handling to decide what happens to the connection, exactly as
/// the endpoint-authentication setup vocabulary does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionPromotionError {
    /// The channel's connector is no longer the installed one, so there is no
    /// live channel left to promote.
    ChannelNotCurrent,
    /// Current policy does not admit this peer.
    PolicyRefused,
    /// The local principal belongs to a different runtime than the channel.
    ///
    /// Not an authorization decision: it means two values that must describe one
    /// process do not, which makes the promotion meaningless rather than merely
    /// refused.
    RuntimeMismatch,
    /// Post-authentication session capacity was not available.
    ResourcesUnavailable,
}

/// The one owner of the promotion transition.
///
/// Holds the process-wide inputs a promotion needs beside the per-channel ones:
/// the explicit local principal for this process, and the resource scope its
/// post-authentication reservations draw from.
pub(crate) struct SessionBroker {
    runtime: RuntimeIncarnation,
    principal: Arc<LocalPrincipalCapability>,
    resources: MeshConnectorResourceScope,
}

impl SessionBroker {
    /// Install the broker for one live Mesh runtime.
    ///
    /// The principal is minted once, here, from the explicit local process
    /// binding — not inferred per request from a client label, and not
    /// negotiated with a peer.
    pub(crate) fn new(runtime: RuntimeIncarnation, resources: MeshConnectorResourceScope) -> Self {
        let principal = Arc::new(LocalPrincipalCapability::for_local_process(runtime.clone()));
        Self {
            runtime,
            principal,
            resources,
        }
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    /// Promote the authenticated channel held in `slot` into a live session, or
    /// refuse without disturbing it.
    ///
    /// The channel is **borrowed** for every fallible step and moved out of the
    /// slot only once the post-authentication reservation has been taken. That
    /// ordering is the contract, not an implementation detail: a
    /// [`ResourcesUnavailable`](SessionPromotionError::ResourcesUnavailable)
    /// refusal leaves the exact authenticated channel installed, so the next
    /// attempt retries the same proven channel rather than having to
    /// re-authenticate one that a transient capacity shortfall destroyed — a
    /// shortfall the peer had no part in and cannot be asked to prove its way
    /// out of again.
    ///
    /// The three *terminal* refusals still consume it, deliberately and
    /// visibly: a channel whose connector is superseded, whose peer policy
    /// refuses, or whose runtime disagrees is not one this entry may keep, and
    /// retrying it could only ever produce the same answer.
    ///
    /// Lending the slot rather than the value is what makes both halves
    /// structural. A caller cannot commit a channel other than the one that was
    /// validated, because it never holds one: the move happens in here, after
    /// the last fallible step, and nothing between the two can substitute a
    /// different value.
    pub(crate) fn promote(
        &self,
        slot: &mut Option<AuthenticatedChannelCapability>,
        connector: &Arc<ConnectorIncarnation>,
        policy: CurrentPolicyAdmission,
    ) -> Result<SessionCapability, SessionPromotionError> {
        // Every free conjunct, decided against a borrow so that nothing is
        // consumed while an answer is still in doubt. The borrow ends with this
        // block — the value it yields carries no reference — which is what lets
        // the terminal arm below take the slot at all.
        let terminal = match slot.as_ref() {
            // No channel to promote. Spelled as `ChannelNotCurrent` because that
            // is what an absent channel means here: the entry holds no live
            // authenticated channel for this connector.
            None => Some(SessionPromotionError::ChannelNotCurrent),
            Some(authenticated_channel) => {
                if !authenticated_channel.belongs_to(connector) {
                    // The channel must have been promoted from the exact
                    // connector the caller is promoting for. Trusting the
                    // caller's connector alone would accept a capability from a
                    // superseded channel whenever the current one was supplied
                    // alongside it.
                    Some(SessionPromotionError::ChannelNotCurrent)
                } else if !policy.admits(authenticated_channel) {
                    // Policy is read from the adapter's proof value rather than
                    // re-derived here, so the broker cannot disagree with the
                    // fence that produced it.
                    Some(SessionPromotionError::PolicyRefused)
                } else if !authenticated_channel.runtime().is_same(&self.runtime)
                    || !self.principal.runtime().is_same(&self.runtime)
                {
                    // One process, one runtime. A principal from a replaced
                    // runtime object cannot be combined with a channel from this
                    // one.
                    Some(SessionPromotionError::RuntimeMismatch)
                } else {
                    None
                }
            }
        };
        if let Some(error) = terminal {
            drop(slot.take());
            return Err(error);
        }

        // The last fallible step, and the only one that can refuse a channel
        // which is in every other respect promotable. Until it succeeds the slot
        // still holds its channel, so `?` here retries cleanly.
        let permit = SessionPermit::reserve(&self.resources, self.runtime.clone())
            .map_err(|_| SessionPromotionError::ResourcesUnavailable)?;

        // Infallible from here: the move out of the slot *is* the commit.
        let authenticated_channel = slot
            .take()
            .expect("the slot held a channel through every check above and nothing released it");

        Ok(SessionCapability {
            authenticated_channel,
            local_principal: Arc::clone(&self.principal),
            permit,
            connector: Arc::clone(connector),
        })
    }
}

#[cfg(test)]
pub(crate) fn session_for_test(runtime: RuntimeIncarnation) -> SessionCapability {
    let authenticated_channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
    let connector = Arc::clone(authenticated_channel.record().connector());
    let local_principal = Arc::new(LocalPrincipalCapability::for_test(runtime.clone()));
    let permit = SessionPermit::reserve(&test_resource_scope(), runtime)
        .expect("fixture provider admits one session reservation");

    SessionCapability {
        authenticated_channel,
        local_principal,
        permit,
        connector,
    }
}

/// What the finite provider records for one scope, over and above whatever the
/// scope is granted.
///
/// Taken from the provider rather than restated, so a fixture cannot come to
/// disagree with the accounting it is paying for. Kept as a named local because
/// this is the scope half of the provider's bookkeeping; the reservation half
/// is [`session_reservation_charge_for_test`], and a grant that is short should
/// read as a missing term rather than as an unexplained number.
#[cfg(test)]
fn provider_bookkeeping_unit() -> ResourceClaim {
    crate::resource::FiniteResourceProvider::scope_record_charge_for_test()
}

/// What one promoted session actually costs the provider: [`session_claim`]
/// plus the record it keeps for the reservation carrying it.
///
/// Mechanically derived, and `pub(crate)` so every fixture that has to leave
/// room for a session charges the same thing. A fixture that hand-adds the
/// session claim alone is short by exactly the record the provider keeps, and is
/// short *silently* until the grant happens to bind — which is the defect this
/// exists to make unrepeatable.
#[cfg(any(test, feature = "transport-lab"))]
pub(crate) fn session_reservation_charge_for_test() -> ResourceClaim {
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(
        session_claim().expect("the session claim is `size_of` arithmetic and cannot overflow"),
    )
    .expect("one session claim plus the provider's reservation record is representable")
}

/// The exact reservation one promoted session takes out of a fixture's grant.
///
/// Public so an **external** integration-test fixture can leave room for the
/// sessions it promotes, and unavailable without `transport-lab` so it stays out
/// of the default public API — the same shape as
/// [`transport_lab_connector_fixture_grant`](crate::transport_lab_connector_fixture_grant).
/// An integration test is a separate crate: it sees only `pub` items and links
/// the library built *without* `cfg(test)`, so neither the `pub(crate)` helper
/// above nor the provider's own charge is reachable from one. This is.
///
/// It is the **reservation** charge, not the bare claim. The provider charges
/// the claim together with the record it keeps for the lease carrying it, so a
/// fixture that budgets the claim alone is short by exactly one record per
/// session — and short *silently*, binding or refusing on whatever slack some
/// unrelated term happened to leave. Deriving it here is what stops a fixture
/// from restating a number the broker owns.
#[cfg(feature = "transport-lab")]
pub fn transport_lab_session_reservation_claim() -> ResourceClaim {
    session_reservation_charge_for_test()
}

/// What the fixture's own scaffolding costs, before a single session.
///
/// Two things are charged that are not session capacity: the two provider
/// scopes — the process scope `ResourceProviderPort::new` creates and the Mesh
/// scope `issue_mesh_scope` creates — and the reservation the connector cleanup
/// executor holds for as long as it lives, which carries the provider's record
/// on top of the infrastructure claim itself.
///
/// A grant that names only the session claim's own dimension is refused at
/// provider construction, in the `OpaqueDependencyResidual` dimension, before
/// any control can express what it meant to test — which is why every control
/// here adds this scaffolding rather than granting session capacity alone.
///
/// Every term is derived rather than written out. The executor's claim is the
/// connector's to choose and the records are the provider's; restating either
/// would mean a change on that side turned into a fixture that quietly stopped
/// admitting the thing under test rather than one that fails loudly.
#[cfg(test)]
fn fixture_scaffolding_claim() -> ResourceClaim {
    let scopes = provider_bookkeeping_unit()
        .checked_scale(2)
        .expect("two scope records are representable");
    crate::resource::FiniteResourceProvider::reservation_charge_for_test(
        crate::runtime::attempt::cleanup_executor_infrastructure_claim()
            .expect("the cleanup executor infrastructure claim is representable"),
    )
    .expect("the cleanup executor reservation charge is representable")
    .checked_add(scopes)
    .expect("the fixture scaffolding claim is representable")
}

/// The scaffolding above plus room for exactly `sessions` promotions.
#[cfg(test)]
fn fixture_grant(sessions: u64) -> ResourceClaim {
    let sessions = session_reservation_charge_for_test()
        .checked_scale(sessions)
        .expect("the fixture session capacity is representable");
    fixture_scaffolding_claim()
        .checked_add(sessions)
        .expect("the fixture grant is representable")
}

#[cfg(test)]
fn test_resource_scope() -> MeshConnectorResourceScope {
    scope_for_grant(fixture_grant(64))
}

/// Stand one isolated provider up over `grant` and issue its Mesh scope.
///
/// The whole chain, so a control that wants a different capacity says so with a
/// grant and nothing else moves between it and the baseline.
#[cfg(test)]
fn scope_for_grant(grant: ResourceClaim) -> MeshConnectorResourceScope {
    use crate::resource::{FiniteResourceProvider, ProcessResourceRoot, ResourceProviderPort};

    let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("fixture provider accounts for its own process scope");
    ProcessResourceRoot::isolated()
        .install_resource_provider(provider)
        .expect("fresh isolated root has no installed provider")
        .issue_mesh_scope()
        .expect("installed provider issues one mesh scope")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker_for_test(runtime: RuntimeIncarnation) -> SessionBroker {
        SessionBroker::new(runtime, test_resource_scope())
    }

    #[test]
    fn v4_arc05_promotion_binds_channel_principal_permit_and_connector() {
        // Positive control: a promotion that satisfies every conjunct produces a
        // capability bound to the exact channel, connector, and runtime it was
        // promoted from.
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());
        let channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let connector = Arc::clone(channel.record().connector());

        let mut slot = Some(channel);
        let session = broker
            .promote(
                &mut slot,
                &connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("every promotion conjunct holds");

        assert!(
            slot.is_none(),
            "a committed promotion moves the channel out of the slot"
        );
        assert!(session.belongs_to(&connector));
        assert!(session.runtime().is_same(&runtime));
        assert!(session.local_principal().runtime().is_same(&runtime));
        assert!(session.authenticated_for("fixture-mesh", "fixture-device-remote"));
    }

    #[test]
    fn v4_arc05_promotion_refuses_a_channel_from_another_connector() {
        // Negative control for the replacement conjunct: the capability and the
        // connector are each individually genuine, and the promotion still
        // refuses, because they are not the same channel.
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());
        let channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let replacement = crate::endpoint_auth::authenticated_for_test(runtime);
        let other_connector = Arc::clone(replacement.record().connector());

        let mut slot = Some(channel);
        assert_eq!(
            broker
                .promote(
                    &mut slot,
                    &other_connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .err(),
            Some(SessionPromotionError::ChannelNotCurrent)
        );
        assert!(
            slot.is_none(),
            "a terminal refusal consumes the channel: it can never promote here"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_when_current_policy_does_not_admit() {
        // Negative control for the policy conjunct, with every other conjunct
        // held true — so the refusal is attributable to policy alone.
        let runtime = crate::runtime::runtime_for_test();
        let broker = broker_for_test(runtime.clone());
        let channel = crate::endpoint_auth::authenticated_for_test(runtime);
        let connector = Arc::clone(channel.record().connector());

        let mut slot = Some(channel);
        assert_eq!(
            broker
                .promote(
                    &mut slot,
                    &connector,
                    CurrentPolicyAdmission::refused_for_test()
                )
                .err(),
            Some(SessionPromotionError::PolicyRefused)
        );
        assert!(
            slot.is_none(),
            "a policy refusal is terminal, so the channel does not survive it"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_a_channel_from_another_runtime() {
        // Negative control for the runtime conjunct: a channel authenticated
        // under a replaced runtime object cannot be promoted by this broker.
        let broker = broker_for_test(crate::runtime::runtime_for_test());
        let foreign = crate::runtime::runtime_for_test();
        let channel = crate::endpoint_auth::authenticated_for_test(foreign);
        let connector = Arc::clone(channel.record().connector());

        let mut slot = Some(channel);
        assert_eq!(
            broker
                .promote(
                    &mut slot,
                    &connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .err(),
            Some(SessionPromotionError::RuntimeMismatch)
        );
        assert!(
            slot.is_none(),
            "a runtime disagreement is terminal, so the channel does not survive it"
        );
    }

    /// Positive install premise for every control in this module.
    ///
    /// The fixture grant covers its own scaffolding — both provider scopes and
    /// the connector cleanup executor — so a provider stands up, issues a Mesh
    /// scope, and admits a promotion. Without this the whole module fails at
    /// `ResourceProviderPort::new` in the `OpaqueDependencyResidual` dimension,
    /// and every control reads as a broken conjunct rather than as a grant that
    /// never described the fixture it was paying for.
    ///
    /// The second half is what keeps that scaffolding honest. Every dimension
    /// the scaffolding names is already spoken for — the executor's own
    /// reservation covers its infrastructure claim, including the accounted
    /// memory a session claim is denominated in, and the bookkeeping is spent on
    /// the two scopes and that reservation. If a session could still be promoted
    /// out of the scaffolding alone, then `fixture_grant(1)` would really admit
    /// two, and the exhaustion control below would be measuring slack rather
    /// than its own stated capacity.
    #[test]
    fn v4_arc05_the_fixture_grant_pays_for_its_own_scaffolding_and_no_session() {
        let runtime = crate::runtime::runtime_for_test();

        let broker = SessionBroker::new(runtime.clone(), scope_for_grant(fixture_grant(1)));
        let channel = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let connector = Arc::clone(channel.record().connector());
        assert!(
            broker
                .promote(
                    &mut Some(channel),
                    &connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .is_ok(),
            "the scaffolding plus one session admits exactly that one session"
        );

        let bare = SessionBroker::new(
            runtime.clone(),
            scope_for_grant(fixture_scaffolding_claim()),
        );
        let channel = crate::endpoint_auth::authenticated_for_test(runtime);
        let connector = Arc::clone(channel.record().connector());
        let mut slot = Some(channel);
        assert_eq!(
            bare.promote(
                &mut slot,
                &connector,
                CurrentPolicyAdmission::admitted_for_test()
            )
            .err(),
            Some(SessionPromotionError::ResourcesUnavailable),
            "and the scaffolding on its own admits no session, so the capacity \
             in a fixture grant is the only thing that ever admits one"
        );
        assert!(
            slot.is_some(),
            "a capacity refusal is not terminal: the exact channel stays installed"
        );
    }

    #[test]
    fn v4_arc05_promotion_refuses_when_session_capacity_is_exhausted() {
        // Negative control for the resource conjunct. The grant is the fixture
        // scaffolding plus exactly one session, so the second promotion refuses
        // on capacity with every other conjunct still true — and the refusal is
        // a typed cause, not a silent unpromoted channel.
        //
        // The scaffolding is added rather than the session claim being used as
        // the whole grant: a grant naming only the session's own dimension
        // cannot construct a provider at all, so this control would have
        // panicked before reaching its own subject. The one session remains the
        // only session capacity, which is what keeps it discriminating.
        //
        // The grant is exact in every dimension a promotion touches, so the
        // second one exceeds it in both the session dimension and the
        // bookkeeping its reservation is charged. That is the fixture paying
        // for exactly one session rather than a dimension left slack, and both
        // are released together by the drop below.
        let runtime = crate::runtime::runtime_for_test();
        let broker = SessionBroker::new(runtime.clone(), scope_for_grant(fixture_grant(1)));

        let first = crate::endpoint_auth::authenticated_for_test(runtime.clone());
        let first_connector = Arc::clone(first.record().connector());
        let held = broker
            .promote(
                &mut Some(first),
                &first_connector,
                CurrentPolicyAdmission::admitted_for_test(),
            )
            .expect("the first session fits the whole grant");

        let second = crate::endpoint_auth::authenticated_for_test(runtime);
        let second_connector = Arc::clone(second.record().connector());
        let mut retryable = Some(second);
        assert_eq!(
            broker
                .promote(
                    &mut retryable,
                    &second_connector,
                    CurrentPolicyAdmission::admitted_for_test()
                )
                .err(),
            Some(SessionPromotionError::ResourcesUnavailable)
        );
        assert!(
            retryable.is_some(),
            "capacity is the one refusal that leaves the channel installed — the \
             peer proved this channel and a shortfall it had no part in must not \
             cost it that proof"
        );

        // Non-vacuity, and the retry contract in one step: the capacity is
        // genuinely released with the session, and what promotes afterwards is
        // the *exact* channel the shortfall refused — not a freshly minted one.
        // A broker that destroyed the channel on `ResourcesUnavailable` could
        // not reach this line at all, and one that never admits twice would fail
        // it.
        drop(held);
        assert!(broker
            .promote(
                &mut retryable,
                &second_connector,
                CurrentPolicyAdmission::admitted_for_test()
            )
            .is_ok());
        assert!(
            retryable.is_none(),
            "and the successful retry is the commit that finally moves it"
        );
    }

    #[test]
    fn v4_arc05_a_promoted_session_names_one_exact_remote_device() {
        let runtime = crate::runtime::runtime_for_test();
        let session = session_for_test(runtime);

        assert_eq!(session.remote_device_id(), "fixture-device-remote");
        assert!(!session.authenticated_for("fixture-mesh", "other-device"));
    }
}
