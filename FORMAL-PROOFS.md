# MyOwnMesh formal model and proof obligations

Status: formal architecture model and proof obligations for the hybrid networking architecture in [`ARCHITECTURE.md`](ARCHITECTURE.md).

This document separates mathematical claims from the minimal architecture and concrete implementation constraints. These are proof sketches and obligations, not a claim of completed machine verification.

## 1. Model and notation

Let:

```text
M      exact MeshContext
D      finite accepted durable fact set for one projection scope
B      Genesis or one verified durable semantic basis
P      Project(M, scope, B, D), the derived durable state
L      live runtime state
I      one explicit typed input
G      the finite resource grant currently assigned to one provider domain
Q      one finite resource claim vector
R      the multiset of live lease claims and failed-cleanup-retained claims
       in that provider domain
E      one bounded effect set
```

The durable semantic function is:

```text
Project(M, scope, B, D) -> P
```

The live transition function is:

```text
Step(P, L, I) -> PlannedLiveState x Q* x E*
```

The connector runtime has local opaque capabilities:

```text
ConnectorCandidateCapability
ConnectedChannelCapability
AuthenticatedChannelCapability
SessionCapability
```

A capability is unforgeable within the selected runtime model, bound to one runtime incarnation, and not reconstructible from a durable fact or serialized identifier alone.

For one live connection attempt `a`, let `C(a)` be its finite live set of connector candidates. Every `c` in `C(a)` has exactly one attempt owner and one finite live claim. A WebRTC candidate `c_w` owns one peer connection and one ICE agent. Its internal ICE candidate and pair sets are finite live connector state, not members of `C(a)` and not authority capabilities. The model fixes no universal maximum for `|C(a)|`, Mesh runtimes, peers, sessions, or flows.

```text
DataChannelOpen(c_w)
and Owns(a, c_w)
and Active(a)
    -> ConnectedChannelCapability(c_w)
```

If `a` is retired before this transition, no delayed callback for any member of `C(a)` may produce a connected-channel capability or mutate the replacement attempt.

### 1.1 Durable facts

For durable fact `f` in domain `d`:

```text
FactID(f) = H(domain_separator_d || CanonicalEncode(f.content))
```

A valid signed durable fact satisfies:

```text
CommonValid(M, f) :=
    Canonical(f.content)
    and RecomputeFactID(f) = f.fact_id
    and DeviceID(f.author_public_key) = f.author_device_id
    and Verify(f.author_public_key, f.fact_id, f.signature)
    and f.mesh_context_digest = Digest(M)
    and DomainShapeValid_d(f)
    and WithinDurableProtocolMaxima_d(f)
```

### 1.2 Causal relation

Let `x ≺ y` mean that `y` directly or transitively names `x` as a required durable predecessor.

Causal concurrency is:

```text
x || y  iff  not (x ≺ y) and not (y ≺ x)
```

The adopted durable domain separately defines:

```text
ConflictKey_d(f)
Relation_d(x, y) in { Independent, Joinable, Exclusive }
```

Two causally concurrent facts are exclusive siblings only when the domain maps both to the same exclusive semantic cell.

### 1.3 Live transport state

A transport hint is any bounded typed input that may inform pathfinding:

```text
TransportHint =
    AddressHint
    | CandidateHint
    | IncomingSocketHint
    | RelayHint
    | ConnectIntent
    | ConnectorSpecificHint
```

A hint is not authority. It may enter `Step` and cause only a member of the pre-authentication effect set:

```text
PreAuthEffect =
    CreateBoundedCandidate
    | OpenBoundedTransport
    | SendBoundedProbe
    | CreateBoundedRelayAllocation
    | PerformBoundedHandshake
    | RecordBoundedTransportObservation
    | CancelOrReleaseCandidate
```

A promoted session effect is separate:

```text
PromoteSession(
    authenticated_channel,
    exact_mesh_context,
    exact_endpoint_ids,
    authenticated_local_principal,
    reserved_resources,
    opaque_session_capability
)
```

### 1.4 Session promotion predicate

For connected channel `c`, local device `A`, remote device `C`, and local principal `u`:

```text
MayPromote(c, M, A, C, u) :=
    ChannelCurrentlyWorks(c)
    and FreshMutualDeviceAuthentication(c, A, C)
    and ChannelBindsExactMesh(c, M)
    and DurablePolicyAllows(P, M, A, C)
    and LocalPrincipalAllows(u, M, A, C)
    and PostAuthResourcesReserved(c, A, C, u)
    and FreshSessionCapabilityReserved(c, A, C, u)
```

`DurablePolicyAllows` means Open self-participation under the Open profile or the selected Closed authorization proof under the Closed profile.

## 2. Assumptions

The cryptographic claims depend on:

1. Canonical encodings are unique for every accepted durable fact and endpoint-authentication transcript.
2. The selected hash has the adopted collision, preimage, and second-preimage security.
3. Device signatures are strictly verified and existentially unforgeable under the adopted assumptions.
4. The endpoint-authentication protocol proves fresh possession of both Device keys and binds them to the exact working channel and mesh context.
5. Session and packet protection provides confidentiality, integrity, role separation, and replay rejection under the adopted assumptions.
6. Opaque local capabilities cannot be forged or reconstructed from serialized public values.
7. Only the reducer, connector runtime, endpoint authenticator, and session broker transitions described by the implementation contract mutate their respective owned state.
8. Every protected allocation is dominated by a successful resource reservation.
9. Honest endpoint private keys and the runtime paths that use them are not compromised.

The availability claims explicitly exclude complete control of every usable signaling or data path by an adversary.

## 3. Durable fact integrity and transport substitution

### Theorem 3.1. Exact durable content integrity

Assume the canonical encoding, hash, and signature premises. A carrier cannot change any accepted durable fact field without either changing the computed Fact ID or forging the author signature for the changed Fact ID.

#### Proof sketch

Every state-deriving field is inside the canonical content. Any field change changes the canonical byte string. Under the hash assumptions, the changed content does not retain the original Fact ID except with negligible probability. The original signature verifies only over the original Fact ID. Therefore the changed fact fails recomputation or signature verification.

### Theorem 3.2. Carrier non-authorship

A carrier account, socket identity, service identity, address, path, or delivery provenance cannot satisfy durable fact authorship unless it also supplies the exact valid Device signature required by `CommonValid`.

#### Proof

Carrier metadata is not an input to `CommonValid`'s authorship predicate. The author is derived from the signed public key and exact Device ID. Therefore carrier identity is irrelevant to authorship.

### Theorem 3.3. Durable semantic transport substitution

Let deliveries `T1` and `T2` produce the same accepted durable fact set `D`, the same exact context `M`, scope, and semantically equivalent verified basis `B`. Then:

```text
Project(M, scope, B, D) under T1
    =
Project(M, scope, B, D) under T2
```

#### Proof

`Project` is a pure function of the listed semantic inputs. Transport identity, delivery order, socket state, and delivery timing are not inputs. Equal explicit inputs produce equal output.

### Corollary 3.4. Transport independence does not imply operational equivalence

The theorem above does not imply that `T1` and `T2` have equal latency, loss, directionality, reachability, bandwidth, metadata exposure, or ability to form a live endpoint channel.

## 4. Durable causality and conflict

### Lemma 4.1. Durable causality is a partial order

If the required predecessor graph is acyclic and predecessor references are exact Fact IDs, then `≺` is irreflexive and transitive. Its reflexive closure is a partial order.

#### Proof

Acyclicity gives irreflexivity. Transitive closure gives transitivity. Exact Fact IDs make ancestry independent of delivery order.

### Theorem 4.2. Common ancestry is insufficient for conflict

Two durable facts that reference a common context or support fact are not exclusive siblings unless the adopted domain maps them to the same exclusive `ConflictKey`.

#### Proof

Causal support and semantic conflict are separate domain functions. A shared support reference does not imply equal conflict keys. Therefore conflict cannot be inferred from common ancestry alone.

### Theorem 4.3. Join-order independence

If the adopted join operator `⊔` is associative, commutative, and idempotent, projection of a finite set of joinable facts is independent of delivery order and duplication.

#### Proof

Associativity removes grouping dependence, commutativity removes order dependence, and idempotence removes duplicate dependence.

### Theorem 4.4. Exclusive sibling confinement

If `x` and `y` are valid, causally incomparable, and occupy the same exclusive semantic cell, then neither may independently supply the singular projected proposition after both are accepted.

#### Proof sketch

The domain projection rule maps an exclusive incomparable head set of cardinality greater than one to `Ambiguous` or another fail-closed result. No arrival, hash, carrier, or identity-count rule is part of the projection. Therefore neither sibling alone supplies the singular proposition.

## 5. Open and Closed authority

### Theorem 5.1. Open permissionlessness

Under the Open rule, any Device key may create its own valid Open participation fact without a third-party authorization input.

#### Proof

The Open participation predicate requires only `CommonValid`, exact Open context, self-authorship, and the Open domain shape. No existing participant, service, application, quorum, or pair grant is an input.

### Theorem 5.2. Open authority confinement

An attacker controlling arbitrarily many Open Device keys cannot author a durable fact as an uncompromised Device ID or resolve another Device ID's exclusive stream solely through identity count.

#### Proof

Each durable fact requires the exact author's signature. Identity count is not an authority or conflict-resolution input. More keys create more self-authored identities but do not yield another key's signature.

### Theorem 5.3. Closed authority confinement

A Device signature that lacks the exact accepted Closed authorization proof cannot create a Closed authority-bearing projection.

#### Proof

The Closed projection predicate is `CommonValid` plus the selected Closed authorization verifier over the accepted Closed governance state. Failure of the additional predicate prevents the authority-bearing projection.

### Corollary 5.4. Closed does not imply a central authority

A Closed governance commitment can encode any reviewed decentralized proof rule. The theorem requires exact proof verification, not a central server or leader.

## 6. Speculative transport work

### Definition 6.1. Pre-authentication work envelope

Let `G_pre` be the finite pre-authentication resource grant currently assigned by the process provider. Let `R_pre` be its live lease multiset. Every speculative transport effect must acquire a finite claim `q` such that `sum(R_pre) + q <= G_pre` before protected allocation or retention.

### Theorem 6.2. Speculative-work confinement

Assume the reducer and connector effect unions are closed and every pre-authentication effect is resource-guarded. Any untrusted hint can cause only effects whose current live resource claims were granted. It cannot directly create durable authority, an authenticated session capability, or application delivery.

#### Proof

By construction, the only transitions reachable from an untrusted hint before `MayPromote` are members of `PreAuthEffect`. None contains a durable authority mutation, `PromoteSession`, or application-delivery effect. Closed effect unions exclude any alternate path. Resource reservation bounds each reachable effect.

### Corollary 6.3. Bounded early transport allocation is not a security failure

Creating a candidate, socket, relay allocation, transport object, or finite media quarantine before endpoint authentication is conforming when every protected object retains its exact lease and cannot reach application delivery or authority.

### Theorem 6.4. Identity rotation does not bypass the global pre-authentication bound

If every claim consumes the process grant before per-identity accounting, an attacker cannot exceed the live process grant merely by using fresh valid or invalid Device identities.

#### Proof

Every allocation consumes the process component independent of identity. For every admitted claim `q`, admission requires `sum(R_pre) + q <= G_pre`. Identity changes do not alter either side of that inequality.

## 7. Channel promotion

### Theorem 7.1. Working transport is insufficient for session authority

A connected socket, successful ICE check, TURN allocation, relay allocation, or transport handshake alone cannot produce an `AuthenticatedPeerSession`.

#### Proof

Each omits one or more required conjuncts of `MayPromote`, including fresh mutual Device authentication, exact mesh binding, durable Open or Closed policy, local-principal admission, post-authentication reservation, or fresh session capability.

### Theorem 7.2. Channel-promotion soundness

If a conforming runtime exposes `AuthenticatedPeerSession(A, C, M)`, then at the exposure transition:

1. A and C were freshly authenticated over the exact working channel;
2. the channel was bound to `M`;
3. the applicable Open or Closed policy allowed the peer under the local accepted durable state;
4. the local principal was authorized;
5. required post-authentication resources were reserved;
6. the exposed handle was a fresh live capability.

#### Proof

`PromoteSession` is the only effect capable of exposing the handle. Its guard is exactly `MayPromote`. Therefore every conjunct held at commit and is rechecked before effect execution.

### Theorem 7.3. Durable evidence cannot reconstruct a live session

Reopening a durable store or replaying old durable facts or ephemeral transport-control messages cannot reconstruct a prior `SessionCapability`.

#### Proof

The capability is created only by the live promotion transition and bound to one runtime incarnation, authenticated channel, principal, and resource reservation. None is derivable from durable facts or old control bytes. Store opening initializes live capabilities empty.

### Theorem 7.4. Replayed control cannot promote a different channel

Assume fresh endpoint challenges and channel binding. Replaying a control transcript from channel `c1` cannot satisfy `FreshMutualDeviceAuthentication(c2)` for a different channel `c2` except by breaking the endpoint-authentication premise.

#### Proof sketch

The endpoint-authentication transcript commits to channel-specific material and fresh endpoint contributions. A transcript for `c1` fails exact binding or freshness verification on `c2`.

## 8. No durable route identity is required

### Theorem 8.1. Route-identifier independence

The session-promotion safety predicate requires a working channel and exact endpoint authentication, but does not require a durable route identifier, global route record, monotonic path generation, or route consensus.

#### Proof

Inspect `MayPromote`. Its inputs are the live channel, exact endpoint proof, mesh context, durable policy, local principal, resources, and live capability. A route identifier is absent. Therefore a route identifier is not necessary for the stated safety property.

### Corollary 8.2. Local connector handles are sufficient for correlation

A connector may correlate asynchronous callbacks and cleanup using unforgeable local candidate and channel capabilities. Those values need no cross-runtime semantic meaning.

### Theorem 8.3. Old callback confinement

If every connector callback carries the exact live local capability for the candidate or channel it mutates, destroying that capability prevents a delayed callback from mutating a replacement candidate or channel.

#### Proof

The replacement has a different unforgeable capability. Exact capability mismatch rejects the delayed callback before mutation.

## 9. Handoff and recovery

Let `V_x` be endpoint `x`'s set of live authenticated channel capabilities for one peer session. Let `Select_x(V_x, observations)` be a local path-selection function.

### Theorem 9.1. Authenticated channel addition is safety preserving

Suppose `V'_x = V_x ∪ {d}` and `d` entered the set only after satisfying the same endpoint-authentication and mesh-binding requirements as the existing channels. Then every channel in `V'_x` is an authenticated A-C channel.

#### Proof

Channels already in `V_x` satisfy the invariant by induction. The sole insertion transition verifies the invariant for `d`. Therefore all members of the union satisfy it.

### Theorem 9.2. Channel removal cannot introduce forgery

If `V'_x = V_x \ {b}`, any packet or operation accepted using `V'_x` was also eligible under a member of `V_x`. Removing a channel cannot add an unauthenticated channel.

### Theorem 9.3. No global switch is required

Safety requires only that each used channel be individually authenticated. It does not require A and C to select one globally current carrier at the same instant.

#### Proof

Application packet acceptance is keyed to the authenticated channel and endpoint-session binding, not to a global carrier variable. Temporary use of two valid channels does not weaken endpoint identity.

### Theorem 9.4. Relay-to-relay signaling is unnecessary for endpoint handoff

A replacement relay D can be authenticated and used through endpoint communication A-D, C-D, and A-C without any B-D state transfer.

#### Proof

D's candidate channel and allocation are independently established. A and C perform fresh endpoint authentication or current-session key confirmation through D. No security predicate requires B's approval, key, or state.

### Theorem 9.5. Forced failure can influence selection but not authorization

An attacker capable of dropping channel B may cause local policy to choose another already authenticated channel D. The attacker cannot add D to the authenticated set or promote an unauthenticated D channel solely by dropping B.

#### Proof

Failure changes live observations and selection input. It does not satisfy the insertion or promotion predicate for D.

## 10. Relay safety

### Definition 10.1. Exact relay allocation

A relay allocation is live bounded state naming one exact endpoint pair and one exact relay instance. It accepts only endpoint-authentication packets or endpoint ciphertext for that pair.

### Theorem 10.2. Relay non-substitution

Assume A-C endpoint authentication and packet protection. A malicious TURN, generic relay, or Closed member relay cannot cause C to accept an application packet as authored by A without breaking endpoint authentication or packet integrity.

#### Proof sketch

The relay lacks A-C endpoint keys. C accepts application data only after verification under keys derived by A and C over an authenticated channel. Relay modification or substitution fails verification.

### Theorem 10.3. Exact-destination confinement

If the relay effect accepts no caller-supplied arbitrary destination and is created only for one exact endpoint pair, a conforming relay operation cannot become a general network gateway or application fanout service.

### Corollary 10.4. Visible member relay identity

A Closed member relay may be authenticated as Device B. Anonymous attestation is unnecessary. Visibility does not weaken the A-C endpoint theorem because B is not an endpoint of the inner A-C session.

### Residual relay powers

The relay may deny, delay, reorder, duplicate, meter, and correlate traffic and may observe packet metadata. These are availability and privacy residuals, not endpoint-authentication failures.

## 11. Signaling and payload noninterference

Let the accepted message alphabets be disjoint:

```text
Σ_durable
Σ_ephemeral_transport_control
Σ_endpoint_authentication
Σ_application_payload
```

### Theorem 11.1. Signaling cannot directly deliver application payload

If signaling parsers and reducers have no effect variant containing application bytes and an application consumer, then a signaling input cannot directly produce application delivery.

#### Proof

No transition in the signaling effect union reaches the application-delivery effect. Closed exhaustiveness of the union excludes another case.

### Theorem 11.2. Application APIs cannot use signaling as a generic message bus

If ordinary application APIs expose no raw durable-fact or ephemeral-signal constructor and the accepted signaling schemas contain no generic application byte field, an ordinary application cannot place its payload into a supported signaling operation.

### Theorem 11.3. Physical multiplexing does not merge semantics

Sharing a process, socket, host, or lower transport does not invalidate noninterference when immutable message classification, parser dispatch, keys, capabilities, queues, and effects remain disjoint.

#### Proof sketch

Security follows from accepted types and reachable effects, not physical placement. The proof requires implementation refinement showing no cross-dispatch path.

### Theorem 11.4. Connector-native real-time flow confinement

Assume a connector-native real-time flow can be created or used by an application only through a live `SessionCapability`, and assume codec, track purpose, and lane labels are not inputs to durable authority, endpoint authentication, or channel promotion. Then creating, receiving, or changing such a flow cannot alter mesh participation, Closed authorization, peer identity, or session admission.

#### Proof

The real-time flow transition consumes an already promoted session capability and produces only data-plane state and bounded payload effects. No transition from the flow state reaches durable semantic projection or session promotion. Codec and application labels are absent from the authority predicates. Pre-promotion native track objects have no application-delivery effect. Therefore real-time flow state can affect availability, latency, resource use, and application delivery only after promotion, but it cannot create or modify authority.

## 12. Reachability evidence

### Theorem 12.1. Positive observation meaning

A valid fresh endpoint-authenticated packet observation proves only that the exact authenticated peer produced traffic verifiable under the current channel keys at the local observation point. It does not prove future reachability.

A valid signed presence response proves only that the exact Device key answered the exact challenge. It does not prove a usable application channel.

### Theorem 12.2. Local freshness integrity

If observation age is computed from local monotonic time recorded at successful local verification, a remote timestamp or carrier timestamp cannot make an old observation appear locally newer.

### Corollary 12.3. Absence is not revocation

Failure to obtain a new observation supplies no signed Open withdrawal or Closed removal and therefore cannot synthesize either durable semantic change.

## 13. Durable retention and storage opening

### Definition 13.1. Sufficient durable semantic basis

A durable basis is sufficient when it preserves the current durable projection, unresolved exclusive conflicts, adopted continuation validation, and durable pending effects without requiring removed history during ordinary operation.

### Theorem 13.2. Compaction equivalence

For every future durable continuation admitted by the domain's fixed continuation contract, evaluation from the verified compacted basis yields the same validation dispositions and durable projection as evaluation from the removed full history.

This is a proof obligation of the compaction profile, not a property of a hash root alone.

### Theorem 13.3. Store-opening non-revival

Opening a valid durable basis can reproduce its durable projection but cannot reproduce prior live transport or session state when live capabilities, keys, replay windows, connector objects, sockets, and reservations are excluded from durable restoration.

### Theorem 13.4. Whole-witness rollback limit

If every witness of a later durable fact is lost and only an older internally valid basis remains, no algorithm using only that basis can distinguish the world in which the later fact existed from the world in which it never existed.

#### Proof

The local input is identical in both worlds. A deterministic or probabilistic algorithm cannot derive information absent from its input with guaranteed correctness.

## 14. Effects and resources

### Theorem 14.1. No unreserved protected work

If every parser, candidate, socket, relay, handshake, media quarantine, session, queue entry, task, native object, and effect allocation is dominated by a successful finite lease, then the sum of live claims cannot exceed the provider grant.

#### Proof

The provider grants claim `q` only when component-wise checked addition proves `sum(R) + q <= G`. Owner Drop after proven cleanup removes exactly the claim held by that lease. Failed-cleanup retention replaces the live lease claim with the same exact retained claim, so it does not reduce `sum(R)`. Failed subtraction or addition cannot create capacity and instead poisons the affected accounting domain. Induction over grant, release, and failed-cleanup-retention transitions preserves `sum(R) <= G`.

This theorem covers only quantities actually charged to `R`. It does not prove that allocator slack, native WebRTC allocations, OS handles, runtime internals, driver state, or external provider allocations are represented. Those require a conservative claim, an isolation boundary, or an explicit residual report.

### Theorem 14.2. Pre-authentication and post-authentication separation

Allowing bounded pre-authentication allocations does not imply that post-authentication session or application resources may be allocated before `MayPromote`. Separate reservation classes enforce the boundary.

### Theorem 14.3. Semantic cardinality need not be fixed

Assume each live product object owns a finite nonzero composite claim and the provider enforces `sum(R) <= G`. Then no fixed Mesh, peer, attempt, session, or flow count is required to preserve resource safety.

#### Proof

Admission depends on the next claim and remaining resources, not on the product-object count. One large object may consume more of `G` than many small objects. Any number of objects may coexist while their summed claims fit. The next object fails with typed pressure when its claim does not fit.

### Theorem 14.4. Child scopes cannot multiply capacity

If every child scope reserves from the same process provider and scope creation grants no resources, adding Mesh scopes cannot increase `G` or permit `sum(R) > G`.

### Theorem 14.5. Work-conserving borrowing preserves safety

Allowing one child to consume capacity unused by another preserves `sum(R) <= G` because both claims are charged to the same finite process grant. No basal weight, quota, reserved share, or partition is needed for this inequality. This theorem proves resource safety only. It does not prove eventual admission.

### Theorem 14.5a. Demand arbitration preserves safety

Assume a provider may retain unsatisfied requests as pending demands and may select among them by any selection policy. Holding, ordering, selecting, or moving a pending demand does not change `R`. A successful grant adds its exact claim only after proving the resulting sum does not exceed `G`. Therefore arbitration changes service order without creating capacity or weakening `sum(R) <= G`.

The theorem is independent of the selection policy. It fixes no authority ordering, rotation rule, queue discipline, or per-scope pending-demand cardinality, and no other proof in this document depends on such a rule. A concrete provider must declare its own selection policy and show only that the policy does not mutate `R`.

### Theorem 14.5b. Indefinite leases, unrestricted borrowing, and guaranteed later admission are incompatible

Assume a valid lease may remain live indefinitely, the provider may not revoke
it, and one scope may borrow every currently unused unit. The provider cannot
also guarantee that a later request from another scope will be admitted.

#### Proof

Let scope A borrow the remaining grant and retain every lease. Let scope B then
request a nonzero claim in any exhausted dimension. Admitting B would violate
`sum(R) <= G`. Releasing A would revoke a valid lease. Waiting for A provides no
bounded admission guarantee because A may remain valid indefinitely. At least
one premise must change. A deployment that requires guaranteed cross-scope
admission must reserve capacity, isolate scopes, or use an owner contract that
explicitly makes borrowed work reclaimable.

This impossibility result is a prerequisite for any cooperative provider policy. A provider policy may weaken the nonrevocation premise only for leases whose owner contract explicitly declares them reclaimable. It does not claim that every live lease is reclaimable.

### Theorem 14.5c. Retirement requests cannot forge release

Suppose a pending demand does not fit. The provider may notify the exact owners of reclaimable leases whose claims contribute to the deficit. Notification changes no member of `R`. Capacity becomes reusable only after an owner finishes cleanup and drops the exact lease. If cleanup cannot be proven, transferring the exact claim into failed-cleanup retention keeps that claim charged. Therefore a retirement request cannot make `sum(R)` understate known live or unreleased resources.

A deterministic selection policy yields a defined service order, not eventual admission. A nonreclaimable lease may retain capacity indefinitely. A reclaimable owner may ignore a retirement request. Failed cleanup may retain the exact charge indefinitely. No timer resolves any of these cases, so the model makes no stronger liveness claim.

### Note 14.5d. Provider policy is not mesh semantics

Theorems 14.1 through 14.5c constrain any conforming resource provider: conservation of `sum(R) <= G`, explicit owner-held cleanup, honest retention of unreleasable charges, typed pressure rather than authorization, and fallible admission. They deliberately fix no scheduling algorithm.

A concrete provider may additionally adopt an exact pending-demand cardinality, an authority ordering over demand classes, and a rotation rule among equal-class scopes. Such a rule is one provider policy. It is not a universal mesh semantic, is not a proof obligation of this model, and no result above becomes unsound if a different conforming provider selects demands differently.

### Note 14.5e. Finite-trace partition invariance beneath a fixed FairnessRoot is a separate provider obligation

Provider conformance also requires that repartitioning one fixed fairness root's identical demand trace across attribution child scopes beneath it cannot give that root earlier eligibility, additional selections or turns, or a larger admitted quantity, and cannot delay a competing fixed root. The requirement is one-way and imposes no equality of outcome. The terms are the closed architectural definitions:

- a `FairnessRoot` is the unit of scheduling attribution a provider serves. It is selected locally by the trusted provider or ingress owner that installs the grant, and is process-local and opaque. It is not mintable by the claimant it attributes: no unverified claimant, peer, or wire assertion may directly name, select, split, rotate, or multiply one. The trusted local owner may use facts it has itself verified or authenticated, including an authenticated local principal or an isolated ingress domain, as mapping input; mere submission over the wire is never sufficient. It is neither a semantic or durable identity nor an authentication or authorization root or capability. It may be a local scheduling identity within its own process, but it is not a Device ID, Mesh ID, durable semantic identity, endpoint identity, or wire value.
- an `AttributionChildScope` refines accounting beneath exactly one `FairnessRoot` and creates no additional share, turn, or service weight.

**The obligation, as finite-trace partition invariance.** Let `A` and `B` be two fairness roots. Fix a finite ordered demand trace for each, in which every demand carries its exact claim, its authority class, and its reclaimability under its owner contract, and in which every arrival and release event and their ordering are fixed. Fix the initial provider state and the grant.

Let `T` be `A`'s trace attributed to `A` alone, and let `T'` be that same trace repartitioned across any number of attribution child scopes beneath `A`. `T'` differs from `T` only in attribution: the demands, their claims, their authority, their reclaimability, and their arrival and release events are identical.

The obligation is one-way. For every such `T'`, with everything above held fixed:

```text
eligibility(A, T')   never earlier than  eligibility(A, T)
selections(A, T')    never more than     selections(A, T)
admitted(A, T', d)   never more than     admitted(A, T, d)
                         for every resource dimension d

eligibility(B, T')   never later than    eligibility(B, T)
select_pos(b, T')    never later than    select_pos(b, T)
                         for every demand b of B selected under T
```

Here `select_pos(b, T)` is the position of demand `b`'s selection event within the finite ordered sequence of selection events under `T`, and is `+infinity` when `b` is not selected under `T` at all. The last two lines are one obligation, not two: they jointly express *do not delay the competing root*. `B` may not be made eligible later, and no selection of a `B` demand may be pushed to a later position in the selection order. Eligibility alone would not capture delay, because a demand can remain eligible at the same moment and still be selected later.

The `+infinity` convention is what makes this a single observable. If a demand of `B` is selected under `T` but not under `T'`, its position has moved from a finite value to `+infinity`, so it has been delayed without bound and the comparison forbids it. That case is excluded by the delay bound itself, not by any separate rule about how many demands of `B` are selected.

The obligation remains one-way and imposes no equality. Additional selections of `B` under `T'` are permitted, since a demand not selected under `T` is outside the comparison entirely. `B`'s admitted quantity is unconstrained in either direction. What is excluded is exactly this: a demand of `B` being served later than it was under `T`, or not at all.

These comparisons are the entire obligation, and each bounds one direction only. Nothing here requires equality of service outcomes. `A` faring worse under `T'` is permitted, `B` faring better under `T'` is permitted, and `B`'s admitted quantity is unconstrained in either direction. `B`'s selection count is not constrained upward either; it is bounded only in the sense that the delay comparison forbids a baseline selection from vanishing. The obligation bounds only amplification of `A` and delay of `B`.

Repartitioning may therefore change how charges are labelled, measured, and reported. What it may not do is obtain earlier eligibility, additional selections, or a larger admitted quantity for `A`, or push `B` later.

This is a fairness obligation on a provider, not a corollary of any theorem above. This document does not prove it and supplies no scheduler, root taxonomy, weighting, or turn mapping that would.

**Nonclaims.** The obligation is an invariance over attribution, not an identity property over the world.

- it does not bind apparent ingress sources into one real-world claimant;
- it is not a proof of Sybil resistance, and no Sybil-resistance claim may be derived from it;
- it does not determine how many fairness roots an actor should receive.

If a provider maps two apparent sources to two fairness roots, the obligation says nothing about whether those sources are one actor. It constrains only what re-attribution beneath an already-selected root can achieve. Selecting roots is a local trust decision outside this model: a trusted local provider or ingress owner may derive roots from facts it has itself verified or authenticated, including an authenticated local principal or an isolated ingress domain, while no unverified claimant, peer, or wire assertion may directly name, select, split, rotate, or multiply a root. Mere submission over the wire is never sufficient; a locally verified or authenticated input is permitted.

The obligation is also not a progress property. It says nothing about progress, throughput, latency, or backpressure, and nothing about behavior under hostile ingress. Those are separate concerns of ingress admission and backpressure design. Satisfying the obligation neither implies nor requires progress under hostile ingress, and no liveness claim follows from it.

The conservation and impossibility results are independent of it in both directions. Theorems 14.1 through 14.5c neither prove the obligation nor depend on it: `sum(R) <= G` holds regardless of which demand is served next, because selection and rotation do not change `R`. Conversely, discharging the obligation cannot strengthen any liveness claim disclaimed in 14.5b and 14.5c. No safety result in this document may be cited as evidence that the obligation holds.

### Theorem 14.5f. External capacity loss does not reduce a committed grant, and conservation is never suspended

Distinguish three quantities in each resource dimension:

```text
H    external observed or desired host capacity
Gc   committed grant, against which every live claim was admitted
S    charged sum: live claims plus failed-cleanup-retained claims
```

Contraction of `Gc` is permitted only to a value greater than or equal to `S`. A provider may never set `Gc` below `S`, and a fall in `H` is an observation, not a reduction of `Gc`.

**Claim.** `S <= Gc` is invariant across every transition, including arbitrary external capacity loss. There is no reachable state in which conservation is suspended, momentarily false, or restored later.

#### Proof

Initially `S <= Gc`, since every admitted claim was checked against `Gc`. Consider each transition.

Admission grants `q` only when `S + q <= Gc`, so it preserves the invariant. Owner release after proven cleanup reduces `S` by exactly the released claim and leaves `Gc` unchanged, so it preserves the invariant. Failed-cleanup retention replaces a live claim with the identical retained claim, leaving `S` unchanged. Grant expansion raises `Gc` and preserves the invariant trivially. Grant contraction is permitted only to some `Gc'` with `S <= Gc'`, so it preserves the invariant by construction. An external observation `H < S` changes no member of `R` and does not change `Gc`, so `S` and `Gc` are both unchanged and the invariant is preserved; it constrains only which future admissions are allowed, and it may prompt retirement requests, which by Theorem 14.5c change no member of `R`.

Every transition preserves `S <= Gc`, so by induction it holds in every reachable state.

**Why the excluded state is excluded.** Setting `Gc` below `S` would require either releasing claims the provider does not own, which contradicts P2 and Theorem 14.5c, or leaving a charge unattributed, which contradicts P1 and Theorem 14.1. The rule that contraction may not pass `S` is exactly what forbids both.

The excluded state is *internal* overcommitment, `S > Gc`, which is unreachable. It must not be confused with *external* overcommitment, `H < S`, which is a different condition entirely: it is reachable at any time because `H` is outside the provider's control, it is a required typed provider state rather than a defect in the model, and it is modelled immediately below. Excluding `S > Gc` does not exclude, weaken, or dispense with the typed overcommitted state relative to `H`.

**Behavior when `H` falls below `S`.** The provider reports a typed degraded or overcommitted state relative to `H`, and `S <= Gc` remains invariant throughout. `Gc` remains at or above `S` and may contract only as owner-driven release lowers `S`, and only as far as the current `S`, so contraction trails release and never causes it. Reporting the condition is required. The report names `H`; it never presents a reduced `Gc`, never describes `S` as exceeding `Gc`, and never claims capacity was taken back. New conflicting admission is refused with typed pressure or unavailability. The provider may request retirement only from exact owners whose contracts declare their leases reclaimable, and it releases nothing itself. Every unreleased charge stays charged and exactly attributed. `H` is never equated with `Gc`.

**Safety, not liveness.** Nothing here bounds how long `Gc` remains above `H`. `Gc` can follow `S` downward only as owners release, and no timer, notification, or external pressure compels an owner to release. If owners never release, `Gc` never reaches `H`. This is consistent with Theorems 14.5b and 14.5c and adds no progress claim. A deployment that must be able to honor a fall in `H` immediately reserves or isolates in advance under Theorem 14.6; it cannot obtain that guarantee afterwards by revoking. Every result of external capacity loss is a typed resource event and never an authorization result.

### Theorem 14.6. Optional ceiling confinement

An optional local ceiling wrapper may refuse a claim that the provider could grant. It cannot approve a claim the provider refused, so it can reduce availability but cannot increase capacity or create mesh authority.

The same bound holds for an optional local isolation policy that confines a scope to a subset of the grant. Both remain explicitly optional deployment policy. No theorem in this section requires either one, and installing either cannot make an unsound provider sound.

### Theorem 14.7. Time independence

If lease transitions are caused only by explicit owner actions or provider reclamation allowed by the claim contract, elapsed time alone cannot change `R`. A slow operation therefore retains its finite claim without acquiring more authority or capacity.

### Theorem 14.8. Stale-effect suppression

If each pending effect carries exact live capabilities and rechecks them before execution, destroying or replacing those capabilities suppresses delayed effects for old candidates, channels, principals, or sessions.

### Theorem 14.9. Crash replay semantic idempotence

If external effect intents have deterministic identities, commit durably before execution, and adapters deduplicate or map duplicates to the same resource, a crash may repeat physical execution but cannot create a second semantic effect.

## 15. Complete eclipse and freshness

### Theorem 15.1. Complete-eclipse indistinguishability

A node receiving no independent evidence cannot distinguish:

```text
World 1: no newer durable fact or usable path exists
World 2: a newer fact or path exists but every available carrier withholds it
```

when both worlds yield the same local input trace.

### Corollary 15.2. No basal global-currentness predicate

The basal architecture cannot honestly claim that a local durable view is globally newest or complete without an additional domain-specific freshness or finality premise.

### Theorem 15.3. Eclipse-safe authenticity

Withholding durable facts or transport hints may preserve a stale local view or deny a connection. It cannot create a valid Device signature, Closed authorization proof, endpoint-authentication transcript, session capability, or application packet authentication.

## 16. Optional causal contract domains

### Theorem 16.1. Application consensus confinement

An application domain may add total ordering, blocks, quorum certificates, replicated execution, proof of work, proof of stake, or another consensus rule. Its results affect only contract instances and bridge rules that explicitly reference that domain.

### Theorem 16.2. Networking independence from optional consensus

Ordinary candidate discovery, channel promotion, reachability observation, relay allocation, and packet carriage need not wait for an unrelated application consensus domain unless the exact mesh policy deliberately makes that domain a promotion predicate.

## 17. End-to-end session theorem

### Theorem 17.1. Hybrid session soundness

Under the stated assumptions, if a conforming application receives and successfully uses `AuthenticatedPeerSession(A, C, M)`, then:

1. the relevant durable Open or Closed policy under the local accepted view allowed A and C;
2. a connector produced a live channel that actually passed the required handshake traffic;
3. A and C were freshly mutually authenticated over that exact channel or authenticated live-channel set;
4. the exact mesh context was bound to the authentication;
5. an authenticated local principal was allowed to use the session;
6. post-authentication resources and a fresh opaque session capability were reserved;
7. application payload did not traverse the signaling effect path;
8. any relay carrier lacked A-C endpoint authority and plaintext under the cryptographic premises.

#### Proof sketch

The durable policy result follows from `Project` and the Open or Closed verifier. The working channel follows from the connector transition. The endpoint, context, principal, resource, and capability properties are conjuncts of `MayPromote`. Application delivery is reachable only through the promoted capability. Signaling noninterference and relay non-substitution provide the final two properties.

## 18. Required mechanized or executable evidence

A concrete implementation must provide:

1. canonical durable-fact and endpoint-transcript test vectors;
2. a complete input and effect inventory;
3. differential tests between batch `Project` and incremental durable materialization;
4. model or property tests for durable conflict classification;
5. bounded speculative-work tests under malformed and identity-rotating input;
6. promotion tests that independently remove every predicate;
7. replay tests across channels, restart, and delayed callbacks;
8. direct, TURN, generic relay, and Closed member-relay equivalence tests;
9. handoff tests with two concurrently authenticated channels and no relay-to-relay protocol;
10. signaling and payload parser/effect reachability analysis;
11. crash tests for reservations and effect intents;
12. compaction equivalence tests for each adopted durable domain;
13. eclipse controls that preserve the impossibility boundary;
14. elastic-provider controls for grant, pressure, exact release, child-scope borrowing, pending demand under the provider's own declared selection policy, retirement requests to reclaimable owners, ignored retirement, failed-cleanup retention, slow work, and storage-backed work;
15. resource characterization and opaque-residual reports on every supported target.
