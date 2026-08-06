# MyOwnMesh implementation constraints and invariants

Status: normative implementation contract for [`ARCHITECTURE.md`](ARCHITECTURE.md).

This document states what a conforming implementation must and must not do. It deliberately keeps transport, signaling, connector, and session machinery inside MyOwnMesh while preventing transport placement from becoming semantic authority.
The staged transition of the existing Rust repository is defined in [`TRANSITION-PLAYBOOK.md`](TRANSITION-PLAYBOOK.md).

## 1. Required component boundary

A conforming implementation must expose equivalent responsibilities to:

```text
myownmesh-semantic-core
    canonical durable facts
    Open and Closed durable projection
    durable conflict and compaction rules

myownmesh-durable-store
    fact storage, verification material, semantic bases

myownmesh-signaling-runtime
    durable fact exchange
    ephemeral transport-control exchange
    carrier provenance and availability state

myownmesh-connector-runtime
    discovery, candidate gathering, racing, checks
    relay allocation, transport handshakes
    live measurement, migration, recovery

myownmesh-session-runtime
    endpoint authentication
    channel promotion
    session capability and application packet boundary

connector-profile-*
    direct LAN, ICE, TURN, generic relay,
    Closed member relay, non-IP profiles

myownmesh-application-api
    roster, reachability, session lifecycle,
    authenticated payload operations
```

These may share a process or source repository. The dependency and capability boundaries remain normative.

### 1.1 Prohibited dependency and authority edges

The following are prohibited:

```text
semantic-core -> concrete socket or carrier API
carrier identity -> durable fact authorship
signaling parser -> application delivery effect
application payload API -> durable fact or transport-signal constructor
connector callback -> direct session exposure
working channel -> implicit Device identity
relay allocation -> implicit endpoint authentication
route or candidate identifier -> application authority
durable store opening -> live session reconstruction
```

### 1.2 Test-only semantic-core build

A build with all networking disabled is useful for validating durable semantics, canonical encoding, projection, and compaction. It is not full MyOwnMesh conformance. A usable conforming product also implements signaling, at least one connector profile, endpoint authentication, and the application session boundary.

## 2. Required type separation

### 2.1 Durable semantic objects

The core durable envelope is typed and canonical:

```text
DurableFactContent {
    fact_version,
    mesh_context_digest,
    author_device_id,
    author_public_key,
    recipient_scope,
    domain_kind,
    predecessor_fact_ids,
    body
}

SignedDurableFact {
    content,
    signature
}
```

The core durable union must be closed for the selected mesh profile. Unknown domains, variants, fields, or encodings have no durable state transition.

Durable facts may include:

```text
OpenParticipation
ClosedGovernance
DurableCapabilityGrant
DurableCapabilityRevocation
reviewed OptionalApplicationContractFact
```

### 2.2 Ephemeral signaling objects

Ephemeral transport control is a separate closed union, for example:

```text
EphemeralTransportSignal =
    ConnectIntent
    | ConnectAnswer
    | CandidateHint
    | CandidateUpdate
    | RelayRequest
    | RelayResponse
    | CancelAttempt
    | RecoveryHint
```

The exact union is connector-profile-specific. It must be typed, bounded, and unavailable as a generic application byte carrier.

Ephemeral signals are not automatically:

- durable facts;
- content-addressed history;
- inputs to `Project`;
- roster or governance authority;
- application messages.

A profile may authenticate an ephemeral signal. Authentication strengthens attribution and resource policy for that signal. It does not convert it into durable authority unless a separately defined durable fact transition exists.

### 2.3 Live capabilities

At minimum, the runtime must use non-serializable or otherwise unforgeable local capabilities equivalent to:

```text
ConnectorCandidateCapability
ConnectedChannelCapability
AuthenticatedChannelCapability
SessionCapability
LocalPrincipalCapability
ResourceReservationCapability
```

Public diagnostic IDs may index these objects, but the public ID alone cannot authorize mutation or use.

### 2.4 Live observations

Transport and reachability observations are local trace state:

```text
TransportObservation {
    candidate_or_channel_capability,
    expected_remote_device_if_known,
    connector_profile,
    state,
    local_observed_at_monotonic,
    measured_values_if_available
}
```

They are not durable participation or authorization facts.

## 3. Durable semantic validation

Every durable fact follows this order:

1. Reserve connection and frame resources before reading protected bytes.
2. Reserve parser bytes and work before decoding.
3. Reject noncanonical and unknown encodings.
4. Reserve hash work, then recompute the Fact ID.
5. Reserve identity and signature work, then derive the Device ID and verify the signature strictly.
6. Verify exact mesh context, scope, domain kind, shape, predecessor set, and protocol maxima.
7. Reserve dependency work before retaining missing-parent state or requesting evidence.
8. Verify the Open or Closed domain rule.
9. Classify as existing or new without visible mutation.
10. For new content, compute the hypothetical durable projection.
11. Reserve storage, materialization, durable-effect, and compaction claims.
12. Atomically commit the fact, proof, durable derived state, reservations, and pending durable effects.

A stricter local budget may refuse otherwise protocol-valid content. The result is local overload, incomplete view, or unavailability. It is not failed authorship or authorization.

## 4. `Project` and durable materialization

`Project` is reserved for deterministic durable semantic derivation:

```text
Project(context, scope, basis, facts) -> DerivedDurableState
```

The following names or implications are prohibited in the basal implementation:

```text
RouteProjection
ProjectedCurrentPath
ProjectedNextHop
GlobalRouteHead
ProjectedOnlineState
```

A cached incremental materialization must equal batch `Project` for equivalent explicit inputs under every covered topological delivery order and duplicate pattern.

Transport observations, candidate state, connector state, current channel state, packet replay state, and application queues are excluded from durable convergence claims.

## 5. Signaling runtime

### 5.1 Required signaling lanes

The signaling runtime must distinguish:

```text
Durable semantic exchange
Ephemeral transport-control exchange
```

Both may use the same carrier connection, but message classification occurs before domain-specific parsing and effect dispatch.

### 5.2 Signaling carriers

A signaling carrier may be:

- Nostr;
- mDNS or DNS-SD;
- WebSocket or another online service;
- direct peer signaling;
- file or shared storage;
- serial, radio, removable media, or another suitable medium.

The implementation must declare which signaling operations each carrier can satisfy. It must not claim that a one-way or delayed medium supplies the liveness of an interactive signaling channel.

### 5.3 Carrier provenance

Accepted durable facts deduplicate by Fact ID. Separately bounded local receipts record which carriers and connection instances delivered them.

Carrier provenance may guide availability policy and diagnostics. It cannot vote on fact validity, fork resolution, Open participation, Closed root selection, or endpoint identity.

### 5.4 Signaling prohibitions

The signaling runtime must not:

- expose a generic application-payload field;
- deliver signaling content as application data;
- synthesize Open withdrawal or Closed removal from disconnect;
- turn service identity into Device identity;
- create an authenticated session directly;
- allocate or retain protected resources without live provider leases.

## 6. Connector runtime

### 6.1 Connector interface

A connector profile must expose equivalent operations to:

```text
start_attempt(local_intent, bounded_hints)
    -> ConnectorCandidateCapability*

poll_or_receive_connector_candidate(connector_candidate_capability, typed_input)
    -> ConnectorCandidateUpdate

try_connector_candidate(connector_candidate_capability)
    -> ConnectedChannelCapability
       | ConnectorCandidateFailure

observe_channel(channel_capability)
    -> TransportObservation

close_candidate_or_channel(capability)
    -> Released
```

The exact API may be asynchronous or event driven.

One connection attempt may own multiple connector candidates. One WebRTC connector candidate owns one `RTCPeerConnection` and one ICE agent. The ICE agent may own multiple internal ICE candidates and pairs. An internal ICE candidate is typed control input, not a `ConnectorCandidateCapability`.

### 6.2 Speculative work is allowed

An untrusted or partially authenticated hint may create bounded candidate work before durable policy and endpoint authentication complete.

The connector may allocate, under pre-authentication reservations:

- candidate objects;
- sockets and transport objects;
- DNS, STUN, ICE, or connector-specific queries;
- bounded TURN or relay allocation state;
- transport handshake state;
- bounded pre-authentication packet or media quarantine;
- timers, tasks, and observations.

This behavior is conforming and required for usability when it remains inside the pre-authentication envelope.

### 6.3 Pre-authentication prohibitions

Before channel promotion, the connector and transport stack must not:

- expose application payload to an application callback;
- accept a remote application operation;
- send application payload as an authenticated peer;
- create or mutate durable roster or governance state;
- issue an authenticated session handle;
- forward to an arbitrary relay destination;
- start unbounded decoding, queuing, fanout, or task creation.

A media profile may instantiate receivers or transport tracks before promotion. Samples remain in bounded quarantine or are discarded. Full application decode and delivery begin only after promotion unless the owner explicitly approves and measures a smaller safe pre-authentication decode stage.

### 6.4 Candidate racing

The connector may race direct, TURN, generic relay, Closed member relay, and other compatible candidates.

No security rule requires every higher-priority candidate to fail before a relay is attempted. Last-resort-only behavior is an optional local cost policy, not a security predicate.

The connector may select the first channel that satisfies the required operational and promotion conditions, or retain multiple authenticated channels for resilience.

### 6.5 No durable route identity

The connector must not require a durable ledger route object before attempting or using a path.

Local candidate and channel handles may exist for:

- callback correlation;
- resource accounting;
- diagnostics;
- cleanup;
- packet demultiplexing.

They must not become:

- durable mesh authority;
- cross-runtime route truth;
- application authorization;
- a globally current path record;
- a monotonic path generation.

### 6.6 Optional connector-native real-time flows

A connector may expose an optional real-time flow provider after a channel has been promoted into a live authenticated session. A connector may provision bounded native transport objects before promotion when its protocol requires them, but it may not expose or transmit application units before the promotion guard succeeds.

The common boundary may contain types such as:

```text
RealtimeFlowProvider
RealtimeFlowHandle
EncodedRealtimeUnit
RealtimeFlowObservation
```

Those types express only session binding, direction, lifecycle, bounded delivery, and connector capability. They must not assign application meaning.

The basal core must not define or require:

- `LaneKind::Video` or `LaneKind::Audio`;
- H.264, Opus, screen, camera, microphone, or product-specific codec semantics;
- a globally fixed media-lane count;
- track numbers as application or mesh authority;
- a media flow on every connector.

A WebRTC implementation may keep RTP, RTCP, transceivers, native track setup, m-line reuse, and drain behavior inside a WebRTC-specific extension. Application or compatibility adapters map application codec and purpose onto those native flows. A data-only connector that reports no real-time flow capability remains conforming.

During migration, legacy `MediaLaneOpen`, `MediaLaneClose`, `VideoSample`, `AudioSample`, H.264, and Opus APIs may remain only as a compatibility facade over the optional real-time flow provider. No new product behavior may be added to that facade, and it must have a named deletion arc.

## 7. Endpoint authentication and channel promotion

### 7.1 Required endpoint-authentication binding

The endpoint-authentication profile must bind:

- exact local and remote Device IDs;
- exact MeshContext digest;
- exact connected channel or channel exporter;
- fresh contributions from both endpoints;
- ordered endpoint roles;
- negotiated cryptographic profile;
- any connector transcript fields whose alteration could substitute the channel or endpoint.

A signaling account, ICE username, DTLS certificate not bound to the Device ID, TURN credential, IP address, or relay identity cannot substitute for this proof.

### 7.2 Promotion transition

Only the session runtime may promote a connected channel.

The promotion guard must include:

```text
channel is currently live
fresh mutual Device authentication succeeded
mesh context matches exactly
Open or Closed policy currently allows the peer
local principal is authenticated and allowed
post-authentication session resources are reserved
fresh opaque SessionCapability is reserved
```

The promotion state and handle exposure commit atomically or not at all.

### 7.3 Handle use

Every application operation must recheck:

- live `SessionCapability`;
- exact local and remote Device IDs;
- exact mesh context;
- current Open or Closed policy;
- authenticated local principal;
- current authenticated channel set;
- current resource reservation;
- session not closed.

A public session number or diagnostic identifier is never sufficient.

### 7.4 Restart

After runtime restart, old session, channel, candidate, replay-window, and local-principal capabilities are absent. Durable state may guide a new attempt but cannot recreate an old session.

No scalar session generation or durable session high-watermark is required by the basal architecture.

## 8. Open and Closed constraints

### 8.1 Open

A valid self-authored Open participation fact must not require:

- sponsorship;
- owner approval;
- pair permission;
- identity-count vote;
- proof of work;
- application approval.

A valid Open participant or an untrusted hint may begin bounded candidate work. Session promotion still requires exact endpoint authentication and the current Open participation rule.

### 8.2 Closed

Closed promotion requires the exact locally accepted Closed authorization proof selected by the context.

The connector may perform bounded speculative work while Closed proof validation occurs. An unauthorized or unknown endpoint is closed or left unpromoted after the proof result. No application payload is exposed.

Closed governance and relay authorization must not depend on carrier count, arrival order, socket health, or a central signaling service unless the selected Closed profile explicitly adopts such a premise.

## 9. Relays

### 9.1 Infrastructure relay

TURN and a generic opaque relay may carry endpoint packets for one exact A-C session. They are not mesh participants or application endpoints by that function.

### 9.2 Closed member relay

A Closed member relay is allowed when the selected Closed profile permits it.

The relay is visibly attributable to Device B. The basal profile must reject anonymous relay credentials.

Relay eligibility may be:

```text
current Closed authorization for B
+ current signed relay offer from B
+ local policy at A, B, and C
```

A stricter Closed profile may additionally require a durable relay capability granted by the selected governance system.

### 9.3 Relay allocation

A relay allocation must be ephemeral live state and must bind:

- exact mesh context;
- exact endpoints A and C;
- exact relay B or service instance;
- exact allocation capabilities for each endpoint;
- explicit provider lifetime state where the relay protocol requires it;
- lease-backed buffering, bandwidth, retry, and queued work.

The allocation must not accept:

- arbitrary host or port supplied in each packet;
- application fanout;
- another relay as recursive destination in the basal profile;
- application plaintext;
- mesh governance or durable fact mutation.

### 9.4 Relay authentication

B may authenticate setup using its Device key or an already authenticated Device channel. A separate relay operational key is optional only for narrower private-key custody and process isolation. It must be visibly delegated by B and must not be anonymous.

Relay packets must use transport or per-allocation packet authentication. B's long-term Device key is not used to sign every packet.

## 10. Handoff and recovery

### 10.1 Endpoint-driven handoff

A handoff is implemented by:

1. keeping the current authenticated channel usable where possible;
2. attempting replacement candidates speculatively;
3. establishing a working replacement channel;
4. performing fresh endpoint authentication or current-session channel key confirmation on that channel;
5. adding the channel to the live authenticated channel set;
6. selecting locally among authenticated channels;
7. closing or retaining old channels according to local policy.

### 10.2 Handoff prohibitions

The basal implementation must not require:

- durable `PathOffer`, `PathAccept`, `PathRetire`, or global `PathID` facts;
- a monotonic path generation;
- a global current-route record;
- relay-to-relay state transfer;
- old-relay authorization of the new relay;
- a simultaneous network-wide cutover.

### 10.3 Replay and delayed callback handling

A replacement channel uses fresh endpoint-authentication or key-confirmation material bound to that channel.

Old control messages may create only bounded duplicate candidate work. Old channel packets fail channel-specific replay and integrity checks. Delayed connector callbacks must present the exact live local capability they mutate.

### 10.4 Suspension and recovery

If no authenticated channel is currently usable, the session is `Suspended`. The connector may continue bounded recovery. The application receives no usable payload operation until an authenticated channel is restored or newly promoted.

## 11. Reachability

The runtime must keep durable participation or authorization separate from local reachability evidence.

At minimum, it should distinguish:

```text
Durable roster state
Signaling responsiveness observation
Candidate connectivity observation
Authenticated channel observation
Application session state
```

Freshness uses local monotonic observation time.

No missing observation, carrier disconnect, expired timer, or failed candidate may synthesize Open withdrawal, Closed removal, or application denial.

A diagnostic API may expose latency, loss, carrier kind, relay identity, and local observation age. Those fields are observations, not authority.

## 12. Persistence and compaction

### 12.1 Durable-only persistence

The durable store may persist:

- accepted durable facts and author proofs;
- derived durable state or materialized indexes;
- verified semantic bases;
- durable pending effect intents;
- bounded delivery provenance where selected.

It must not restore as live authority:

- candidates;
- sockets;
- relay allocations;
- transport channels;
- endpoint-authentication sessions;
- traffic keys;
- packet replay windows;
- reachability observations;
- application session handles;
- local-principal capabilities;
- runtime resource reservations.

### 12.2 Compaction

A replacement durable basis must be:

- sufficient for ordinary durable projection;
- independently verifiable under immutable context and domain commitments;
- sufficient for the adopted future durable continuation contract;
- explicit about unresolved exclusive conflicts.

Predecessor-base storage is optional only when deleting it does not change base verification, durable projection, or permitted durable continuation validation.

Compaction has no route, channel, or reachability meaning.

## 13. Application interface

The ordinary application API must expose:

```text
mesh roster view
reachability and session observations
request_session(mesh_context, remote_device_id)
watch_session(session_operation_or_handle)
close_session(session_handle)
a closed set of payload operations over SessionCapability
optional connector-native real-time flow capability when supported
```

Codec, media role, and product semantics belong to the application or an optional application-facing profile. The core may expose transport-native flow capability, but it must not expose H.264, Opus, screen, camera, or audio meaning as mesh semantics.

The ordinary API must not expose:

- raw durable fact construction;
- raw ephemeral transport-signal construction;
- candidate or route injection;
- relay destination selection;
- signaling publication control;
- endpoint-authentication transcript injection;
- a route graph;
- a persistent session generation as authority.

Carrier diagnostics are separate from peer identity and application authorization.

## 14. Resource model

### 14.1 Normative resource contract

Every protected allocation, retained value, task, queue entry, native object, and scheduled work unit must hold a live finite lease issued by the applicable resource provider. Basal MyOwnMesh defines no fixed semantic cardinality for Mesh runtimes, peers, connector attempts, sessions, or real-time flows.

The resource interface must provide equivalent responsibilities to:

```text
ResourceProvider
    acquire(ResourceClaim, ResourceAuthorityClass)
        -> ResourceLease
         | move-only PendingDemand
         | ResourcePressure(ResourceClass)
         | ResourceUnavailable(ResourceClass)
    request_retirement(exact owner of a reclaimable lease)
        -> owner notification only

ResourceClaim
    finite quantities by ResourceClass

ResourceLease
    exact provider, claim, owner, and live release authority

ResourceClass
    AccountedMemory
    QueuedBytes
    SocketOrHandle
    NativeTransportObject
    WorkerOrTask
    CallbackOrScheduledWork
    StorageBytes
    StorageObject
    RelayOrProviderAllocation
    ParsingOrCpuWork
    OpaqueDependencyResidual
```

A claim may combine several resource classes. An admitted object's count emerges from the claims and current provider grant. There is no `unlimited` sentinel. Admission is always fallible.

The process resource root owns the process grant. Each Mesh runtime receives an AttributionChildScope for accounting, not a new grant. Attempt, candidate, session, and flow owners receive descendant leases. Creating another scope cannot multiply capacity.

The basal requirements on the finite provider are properties, not a scheduling algorithm. A conforming provider must preserve all of:

```text
P1 Domain conservation
    the sum of live and failed-cleanup-retained claims in each resource
    dimension never exceeds the grant actually assigned to the process;
    a claim never exceeds the provider domain it is drawn from

P2 Cleanup ownership
    only the exact owner releases a claim, and only after cleanup; no
    provider, peer, message, or timer can forge a release, and resources
    a cleanup path requires stay retained until that cleanup completes

P3 No minting
    no scope, child scope, or identity creates capacity

P4 Work conservation
    capacity that is neither live nor reserved for an in-flight
    admission is borrowable by any scope that can use it. A provider
    may return immediate typed pressure instead of retaining a demand
    only when the claim does not currently fit. A claim that does fit
    is admitted, unless the refusal is justified by a proven structural
    limit of the provider, by an explicit isolation policy or optional
    local ceiling under P5, or by accounting that is unavailable,
    poisoned, or otherwise unable to prove the admission safe. Every
    such reason is declared. Arbitrary refusal is prohibited and can
    never stand as a hidden limit

P5 Explicit isolation
    every partition, reserved share, or isolation ceiling is explicit
    local policy, never a basal guarantee

P6 Partition invariance of scheduling
    one-way non-amplification. Repartitioning one fixed fairness root's
    identical demand trace across more attribution child scopes beneath
    it must not give that root earlier eligibility, additional
    selections or turns, or a larger admitted quantity, and must not
    delay a competing fixed root. It requires no equality of outcome
    and constrains nothing else. Stated precisely below

P7 Pressure is not authorization
    refusal, pressure, and unavailability are typed resource results,
    never an Open or Closed authorization outcome in either direction

P8 Time is not resource truth
    elapsed duration alone creates, releases, expires, and validates
    nothing
```

P6 uses one closed term, used with the same meaning everywhere it appears:

```text
FairnessRoot
    the trusted local attribution a provider schedules against: a
    process-local scheduling identity for one principal or ingress
    source, assigned by the local process and never minted, named,
    split, or multiplied by the claimant it attributes

    it is not a Device ID, Mesh Context, durable fact author, endpoint
    identity, authentication or authorization root or capability, or
    any wire-visible or peer-supplied value, and it carries no authority
    of any kind

AttributionChildScope
    an accounting subdivision beneath exactly one FairnessRoot;
    creating, cloning, or rotating AttributionChildScopes refines
    accounting only and creates no second root, no second share, and
    no second turn
```

A scope is an accounting subdivision. It is never itself a claimant or a FairnessRoot, and no wording in this document may be read as making it one.

P6 is discharged by one closed obligation, stated over finite traces:

```text
Repartition non-amplification
    let T be any finite trace of operations over a fixed set of
    FairnessRoots; let a FairnessRoot r issue in T a finite multiset
    of demands Dr, and let q be any competing FairnessRoot in T

    let T' be the trace obtained from T by partitioning Dr across
    additional AttributionChildScopes beneath r, preserving the
    demands themselves and their order, and changing nothing else

    then, comparing T' against T, all four must hold:

        r is not eligible earlier in T' than in T
        r receives no more selections or turns in T' than in T
        r's admitted quantity in T' is no greater than in T
        q is not delayed in T' relative to T
```

The obligation is one-directional. It bounds amplification only. It does not require that r fare no worse under repartition, and it does not require that q fare no better; a repartition that disadvantages r or advantages q is conforming. Equality of outcome is not required and must not be asserted.

The obligation is also finite-trace and stated over a fixed root set. It is not an asymptotic, statistical, or steady-state fairness claim, it fixes no share ratio between distinct roots, and it says nothing about how quickly any root is served. A conformance control must exhibit both traces and evaluate the four comparisons; a test showing only that some scope is eventually served does not discharge it.

**What P6 does not claim.** Repartition non-amplification concerns attribution beneath one FairnessRoot. It is not a real-world identity or claimant-count claim. It does not assert that a real adversary is confined to one FairnessRoot, that distinct roots correspond to distinct people, organizations, devices, or tenants, or that an adversary able to obtain several genuine roots is limited by this property. Sybil resistance, principal admission, and ingress identity are separate problems. P6 does not address them, no P6 control may be cited as evidence about them, and no Sybil or admission control may be cited as evidence for P6.

**Trusted local mapping is allowed and required.** Which local values a deployment maps onto a FairnessRoot is provider and deployment policy. An OS user, a local service account, an authenticated IPC peer, a local principal, or a named local ingress are all admissible choices. This document fixes no universal scheduler model, root taxonomy, or principal enumeration, and P6 requires none.

The mapping is performed by a trusted local verifier, and it may take verified facts as inputs. An authenticated local principal, a verified ingress classification, or another locally established and verified fact may legitimately determine which root a demand is attributed to. P6 does not require the mapping to be independent of the existence of such facts, and a provider that attributes demand per authenticated principal is conforming.

What P6 forbids is claimant control over the root structure itself. No claimant-supplied, peer-supplied, or wire-visible value may directly name, select, split, or multiply a FairnessRoot, and no party may increase the number of roots it is attributed to by asserting something that trusted local verification has not established. The distinguishing test is not "did any claimant-related fact influence the mapping" but "can a claimant, by its own action or assertion, obtain more roots or more turns than the trusted local mapping assigns it". Verified input is permitted; unverified assertion is not.

**Hostile-ingress progress is a separate contract.** P6 says nothing about whether a hostile or misbehaving ingress can delay or starve other work. Progress under hostile ingress is governed by the separate ingress progress and backpressure contract: bounded pre-authentication work, typed backpressure to the producer, and refusal naming an unavailable resource dimension. Neither contract is evidence for the other, and a control for one must not be reported against the other.

Pending-demand cardinality, selection order, and rotation are concrete provider policy. The provider implementation selects them, and any policy preserving P1 through P8 is conforming. No other component may depend on a particular selection order or rotation rule, and conformance tests must assert the properties rather than the schedule.

The provider shipped with basal MyOwnMesh implements one policy of this kind, and that policy does not yet satisfy P6: shared and work-conserving, with no weights, quotas, reserved shares, or partitions; unused process capacity borrowable across child scopes; at most one exact move-only pending demand per scope; pending demands selected in `Cleanup > Admitted > Speculative` authority order; and equal-class selection rotating across scopes after a demand resolves. Replacing that policy is a provider decision, not a semantic change.

**Disclosed P6 nonconformance of the shipped provider.**

*Mechanism.* The shipped provider's equal-class rotation cursor is keyed to `ResourceScopeId`. That identifier is derived from the allocation address of a fresh process-local scope identity at each scope construction, so each AttributionChildScope created beneath a FairnessRoot introduces another distinct rotation key. Nothing relates the several scope identities beneath one FairnessRoot back to that root. The provider therefore rotates over scope identities rather than over FairnessRoots.

*Consequence.* Fix one FairnessRoot r, a competing FairnessRoot q, and a finite trace. Repartitioning r's demands across N AttributionChildScopes beneath r yields r N rotation turns where the unpartitioned trace yields it one, and defers q's turn correspondingly. Repartition therefore gives r more selections, can make it eligible earlier, can increase its admitted quantity, and can delay q — the four comparisons P6 forbids. The shipped provider does not satisfy P6 today, and no statement in this document may be read as claiming that it does.

*Evidence status.* No control in this repository exhibits a repartitioned trace against its unpartitioned counterpart, and none may be cited as if it did. The existing rotation and yield tests show only that a scope's outstanding demand is eventually served; they evaluate none of the four comparisons and say nothing about the outcome attributed to a fixed FairnessRoot under repartition. Connector-local scheduling metadata is a separate claim about capacity authority and does not discharge P6. Disclosure of this gap is not evidence that the gap is closed.

*Remediation destination.* The correction belongs to the resource provider's fairness slice, which must bind each pending demand to its FairnessRoot rather than to a mintable scope identity, and must supply a control that fixes one root's trace, repartitions that root's demands across additional AttributionChildScopes beneath the same root, and evaluates the four comparisons against the unpartitioned trace. Until that control exists and passes, this obligation stays open and must be reported as failing.

P6 is unchanged and remains basal. The shortfall is in the provider, not in the property; an AttributionChildScope is not redefined as a FairnessRoot, and P6 is not relaxed to a per-scope guarantee. The shipped provider's standing under P1 through P5, P7, and P8 is asserted only where separately supported and is not implied by this paragraph.

When the selected demand cannot fit, the provider may request retirement from an exact owner whose lease contract declares that lease reclaimable. Reclaimability is a property of the owner contract, not a provider decision; the shipped policy treats `Speculative` leases as the reclaimable class. The provider does not release, revoke, replace, or reuse those claims. The notified owner performs cleanup and releases through lease Drop. If cleanup cannot be proven, the owner explicitly transfers the exact charge into failed-cleanup retention. No timer creates, releases, or expires resource truth.

No scheduling or cooperative retirement model guarantees later admission against nonreclaimable admitted pressure, an ignored retirement request, or capacity retained after failed cleanup. A policy that gives cleanup authority the first pending-demand opportunity does not thereby manufacture capacity, and it is not a promise that cleanup can start without its exact claim.

**Immediate pressure only for a non-fitting claim.** An immediate, nonwaiting acquisition may return typed pressure without creating a pending demand, but only when the exact claim cannot be met, in every dimension the claim requires, from capacity that is neither live nor reserved for an in-flight admission. A claim that fits must be admitted unless one of exactly three stated conditions holds: a proven structural limit forbids it; an explicit isolation policy or optional local ceiling refuses it; or the accounting needed to prove the admission safe is unavailable, poisoned, or cannot be proven safe. Each of those must be reported as itself, not as ordinary pressure.

Work conservation constrains refusal in the other direction. An immediate path may not refuse a fitting claim in order to hold capacity for an anticipated demand, to smooth one demand source's request rate, or to enforce an undeclared share. Any such withholding is a partition and is conforming only as explicit local isolation policy under P5.

**Narrow provider determinism.** The provider is deterministic only in this exact sense: given identical already-issued `ResourceScopeId` values, identical provider state, and the same operations applied in the same order, it produces the same decisions. Nothing stronger is claimed. Because a `ResourceScopeId` is derived from the allocation address of a fresh process-local scope identity at construction, the identifiers issued by a fresh run generally differ from those of a previous run, and any behavior keyed to their values or ordering may differ with them. Cross-run, cross-process, cross-allocator, and cross-schedule reproducibility is therefore not claimed, and no test may assume it. A determinism control must fix the already-issued identities rather than re-deriving them.

**Safe contraction of a committed grant.** Three quantities are distinct and must never be conflated:

```text
S    the sum of live claims and failed-cleanup-retained charges in one
     resource dimension
Gc   the provider-owned committed grant in that dimension
H    the host capacity a deployment currently observes or wants in that
     dimension
```

The invariant is `S <= Gc` at every instant, without exception or window. Contraction may lower `Gc` toward `H`, but never below `S`. A request to install a grant below `S` does not lower `Gc`; it is recorded, and it takes effect only as far as `S` permits.

Contraction releases, revokes, invalidates, and reuses nothing. It never forges a release and never admits a conflicting claim to make room. It may request retirement only from the exact owners whose lease contract declares those leases reclaimable, and such a request releases nothing. It applies only to admission decisions taken after it.

When `H < S`, the provider reports a typed degraded or overcommitted state **relative to `H`**. That state describes the gap between currently desired host capacity and current charges. It does not lower `Gc`, does not release or reduce any charge, and does not admit conflicting work in the affected dimension; new admission there is refused with typed pressure naming that dimension. `Gc` contracts toward `H` only as owner-driven releases reduce `S` enough to make each smaller grant safe, one safe step at a time.

`S > Gc` is not a reachable state and must never be described as one. P1 is not suspended, relaxed, deferred, or evaluated against a historical grant during contraction; conservation holds continuously throughout. Any wording suggesting a window in which charges exceed the committed grant is incorrect and must be corrected rather than explained. Contraction is never a reclamation mechanism.

A contraction is not an instantaneous probe of current use, and the two must never be substituted for each other. A probe reports `S` at an instant and changes nothing; a contraction lowers `Gc`, subject to `S <= Gc`, and changes the admission ceiling going forward. The typed degraded or overcommitted report is caused by `H < S`, not by the contraction itself, and it never indicates that `Gc` fell below `S`. Reporting a probe as a contraction would let a transient measurement appear to authorize a permanent ceiling change; reporting a contraction as a probe would let a ceiling change appear to be a mere observation.

*Contraction status.* This paragraph constrains any contraction path that is added. The shipped provider takes its grant at construction and exposes no contraction entry point, so no control exercises this contract today. It must therefore be treated as an unexercised obligation on future work, not as a satisfied property.

The current resource classes describe an accounting vocabulary, not proof that every dependency exposes that dimension. Exactness is limited to the quantity actually charged. Allocator slack, native WebRTC state, runtime internals, kernel handles, driver state, and external provider allocations must remain named residuals until the responsible adapter can conservatively claim or isolate them.

### 14.2 Limit classification

Every limit must be classified as exactly one of:

```text
Protocol-shape bound
    required for canonical or valid wire shape

Provider structural limit
    imposed by a transport, codec, kernel, hardware device, or dependency

Runtime resource availability
    a current provider grant consumed through leases

Optional local policy ceiling
    an explicit administrator, cost, isolation, Closed deployment, appliance,
    test, or temporary compatibility restriction
```

An implementation must not turn a measured workload size into a protocol bound, turn an optional policy ceiling into basal semantics, or describe an opaque dependency allocation as exact.

### 14.3 Pre-authentication resource class

Pre-authentication claims include accepted connections and handshakes, parser bytes and work, fact verification work, signaling work, candidate storage, sockets and transport objects, DNS, STUN, ICE and relay work, speculative packet quarantine, callbacks, scheduled work, diagnostics, and cleanup ownership.

The process component is checked regardless of identity. Per-ingress accounting may guide fairness or optional policy, but identity rotation cannot create a new process grant.

### 14.4 Post-authentication resource class

Post-authentication claims include authenticated sessions, application-facing queues, codec work, relay buffering, recovery, callbacks, handles, and subscriptions. A successful pre-authentication lease cannot be reused as proof that post-authentication resources exist. Promotion performs an explicit resource transition.

### 14.5 Queue and delayed-work contracts

No queue may grow without leases for its retained storage and scheduled work. Basal MyOwnMesh does not define one universal queue-item count.

```text
connector lifecycle
    fixed non-lossy state transition owner

reliable endpoint stream
    resource-backed bytes plus producer backpressure or typed failure

interactive real-time flow
    provider or application-selected complete-unit pressure semantics

satellite or store-and-forward
    delayed-delivery spool backed by storage leases

raw storage or removable media
    storage-object and storage-byte leases
```

Elapsed time does not create or release a lease. A slow operation may retain its finite claim until an explicit owner transition releases or replaces it. A provider retirement request changes no claim. The exact owner releases through Drop after cleanup, or transfers the charge into failed-cleanup retention when release cannot be proven.

### 14.6 Opaque native and operating-system resources

Every opaque family must be reported as one of:

```text
exactly observable and leasable
conservatively claimable
isolatable in a worker, process, job, cgroup, rlimit, or equivalent domain
observable but not enforceable yet
unobservable residual
```

The implementation must prefer host-enforced resource domains and narrow provider guards where available. It must not substitute a guessed peer or flow count for an unobservable native allocation.

### 14.7 Optional local ceilings

An optional `LocalCeilingPolicy` or equivalent wrapper may impose stricter counts or resource partitions for a locked-down appliance, Closed deployment, carrier cost boundary, compatibility provider, or test.

This wrapper is explicitly optional. It is not required for ordinary V4 construction, it cannot mint authority or capacity, and basal conformance must never assume it is present. Every isolation domain or reserved share it introduces is local policy, not a basal guarantee, and must be reported as such.

### 14.8 Effect execution

State and effect intents commit before external execution. Every effect carries exact live capabilities and leases and rechecks them before use. Cleanup effects remain available even when authority for new work disappears.

## 15. Fundamental invariants

### I1. Hybrid architecture

Durable semantics, signaling, connector work, endpoint authentication, and application sessions are all first-class MyOwnMesh components.

### I2. Transport independence

Transport substitution cannot change the authority or meaning of an accepted durable fact.

### I3. Transport is not removed

A usable networking implementation requires live signaling or discovery where needed, a connector profile, endpoint authentication, and packet carriage.

### I4. Projection is durable derivation only

`Project` never means route creation, route selection, topology truth, or forecasting.

### I5. Open remains open

Open self-participation has no third-party admission predicate.

### I6. Closed alone adds governance authorization

Closed may be fully locked down under its selected proof system.

### I7. Durable and ephemeral signaling are distinct

Transient transport negotiation is not automatically retained as durable history.

### I8. Speculative work is allowed

Untrusted input may cause bounded candidate and handshake work.

### I9. Speculative work is confined

Pre-authentication work cannot create durable authority, application delivery, or an authenticated session handle.

### I10. Work is reserved before allocation

Every protected parser, candidate, socket, relay, handshake, queue entry, task, native object, and session allocation is dominated by a live finite resource lease.

### I10a. Basal semantic cardinality is open

Basal MyOwnMesh defines no fixed maximum for Mesh runtimes, peers, connector attempts, sessions, or real-time flows. Each new object is admitted by its actual composite claim and may fail with typed resource pressure or unavailability.

### I10b. Child scopes share one cooperative process grant

Mesh and descendant scopes share one finite process grant. No basal weights, quotas, shares, or partitions exist. Claims never exceed the actual provider domain, no scope mints capacity, unused capacity is work-conservingly borrowable, any isolation or reserved share is explicit local policy, and repartitioning one FairnessRoot's demands across additional AttributionChildScopes beneath that same root does not make that root eligible earlier, give it more selections or turns, increase its admitted quantity, or delay a competing root. That last property is a basal requirement that the shipped provider does not yet meet: it rotates over mintable scope identities rather than over FairnessRoots, so repartitioning a root's demands across additional AttributionChildScopes gives that root more turns and defers a competing root. The gap is disclosed in section 14.1 and remains an open obligation on the resource provider's fairness slice. Only the exact owner releases a claim, after cleanup; no forged release exists, and cleanup retains the resources it requires. The pending-demand cardinality, selection order, and rotation rule that satisfy these properties are concrete provider policy, not mesh semantics. The provider may ask an owner whose contract declares its lease reclaimable to retire, but it never releases that owner's claim. Admission remains fallible under nonreclaimable admitted pressure, ignored retirement, or failed-cleanup retention.

### I10c. Time is not resource authority

Elapsed duration alone cannot create, release, expire, or validate a resource lease.

### I11. A working socket is not a session

Channel promotion requires exact endpoint authentication, exact context, mesh policy, local principal, resources, and a fresh capability.

### I12. No durable route identity is required

The basal network does not require a ledger route object, global path record, or monotonic path generation.

### I13. Local connector capabilities own callbacks

A delayed callback cannot mutate a replacement object without the exact live capability.

### I14. Carrier is not endpoint identity

Direct, TURN, generic relay, and Closed member relay preserve the same A-C endpoint identity after promotion.

### I15. Closed member relay is visible

The relay is attributable to its Device identity. Anonymous relay attestation is prohibited in the basal profile.

### I16. Relay allocation is exact and bounded

A relay allocation has one exact endpoint pair, no arbitrary destination, no fanout, and finite resources.

### I17. Relay cannot promote or switch

A relay cannot add a channel to an endpoint's authenticated set or authorize a handoff.

### I18. No relay-to-relay handoff dependency

Replacement transport can be established without old-relay to new-relay signaling.

### I19. Handoff is endpoint-driven

Only endpoint authentication or current-session channel confirmation can make a replacement channel usable.

### I20. No global current path

Endpoints may temporarily use different or multiple authenticated channels.

### I21. Signaling and payload are disjoint

No supported signaling operation carries ordinary application payload.

### I21a. Media semantics are not core authority

Connector-native real-time flows may be part of the live session data plane, but codec, media purpose, lane numbering, and product meaning cannot affect mesh identity, durable authority, channel promotion, or session authorization.

### I22. Application payload requires a live session capability

A record, hint, candidate, channel, or relay allocation alone is insufficient.

### I23. Reachability is positive local evidence

Absence, expiry, and transport failure do not synthesize durable roster change.

### I24. Durable store opening does not restore live networking

Sockets, keys, replay state, connectors, observations, and handles start absent.

### I25. Compaction affects durable semantics only

Compaction has no authority over routes or live channel state.

### I26. One owner for each state class

The semantic core owns durable projection, the connector owns candidate and channel state, and the session runtime owns promotion and application session state.

### I27. Adapters cannot bypass owners

Carrier parsers and callbacks enter as typed inputs and cannot mutate another component's state directly.

### I28. Stale effects are suppressed

Effects recheck exact capabilities, policy, and resources before execution.

### I29. Complete eclipse is not claimed solved

The runtime does not claim global completeness or guaranteed revocation freshness without an explicit additional premise.

### I30. Optional contracts are confined

Application consensus or smart-contract domains do not become basal networking requirements.

## 16. Conformance matrix

A release must pass at least the following groups.

### 16.1 Durable semantics

- canonical positive and negative vectors;
- Open permissionless positive controls;
- Closed unauthorized-key negatives;
- delivery-order and duplicate equivalence;
- exclusive-fork confinement;
- compaction equivalence.

### 16.2 Signaling

- durable and ephemeral parser separation;
- carrier identity non-authority;
- no carrier-synthesized roster changes;
- lease-backed frame, queue, retry, and provenance state;
- no application payload construction.

### 16.3 Speculative transport

- raw hints can create bounded candidate work;
- process resource grants hold under identity rotation;
- admission continues for another object whenever its exact claim is granted;
- refusal names the unavailable resource class rather than a basal object-count ceiling;
- multiple Mesh scopes cannot multiply the process grant;
- claims never exceed the actual provider domain in any resource dimension;
- unused capacity is work-conservingly borrowable;
- the basal provider has no weights, quotas, reserved shares, or partitions;
- repartition non-amplification on a finite trace over a fixed root set: repartitioning one FairnessRoot's demands across additional AttributionChildScopes beneath that same root, changing nothing else, does not make that root eligible earlier, give it more selections or turns, increase its admitted quantity, or delay a competing root. The control must exhibit both traces and evaluate those four comparisons, and must not require equality of outcome in either direction — **open and failing against the shipped provider; see the P6 status note at the end of this subsection**;
- the FairnessRoot mapping is performed by trusted local verification, which may take verified local facts such as an authenticated principal as inputs, while no claimant-supplied, peer-supplied, or wire-visible value can directly name, select, split, or multiply a root, and no unverified assertion increases the roots a party is attributed to;
- no repartition non-amplification control is reported as a Sybil, claimant-count, or real-world identity result, and no Sybil or principal-admission control is reported against P6;
- hostile-ingress progress and backpressure are exercised as their own contract and are never reported as fairness evidence, in either direction;
- an immediate nonwaiting acquisition returns typed pressure only for a claim that does not fit in some required dimension, and a fitting claim is refused only under a stated structural limit, an explicit isolation or optional ceiling policy, or accounting that is unavailable, poisoned, or unprovable-safe;
- no immediate path withholds a fitting claim to reserve capacity for anticipated demand, to smooth a rate, or to enforce an undeclared share;
- determinism is exercised only across identical already-issued `ResourceScopeId` values, identical state, and the same ordered operations, and no control assumes cross-run identifier stability;
- `Gc` is never installed or reduced below `S`, so `S <= Gc` holds continuously and no control may exhibit or describe `S > Gc`;
- where observed or desired host capacity `H` is below `S`, the provider reports a typed degraded or overcommitted state relative to `H`, retains `Gc` and every unreleased charge, admits no conflicting new work in that dimension, requests retirement only from exact reclaimable owners, and contracts `Gc` only once owner-driven releases make each step safe;
- grant contraction is never exercised as, or substituted for, an instantaneous use probe;
- pressure and refusal never become an authorization result in either direction;
- elapsed time alone creates, releases, expires, and validates nothing;
- a retirement request never releases the claim it targets;
- only the exact owner releases, through Drop after cleanup, or the exact charge enters failed-cleanup retention;
- cleanup retains the resources it requires and cannot depend on a forged release;
- no admission guarantee is claimed against nonreclaimable admitted pressure, ignored retirement, or failed cleanup;
- optional local ceilings, isolation domains, and reserved shares remain explicit wrappers;
- selection order, rotation rule, and pending-demand cardinality are provider policy, so conformance asserts the properties above rather than a particular schedule;
- when the shipped provider policy is in use, one move-only pending demand exists per scope, pending demand is selected in `Cleanup > Admitted > Speculative` order with equal-class per-scope rotation, and retirement is requested only from exact owners whose contract declares the lease reclaimable;
- malformed and unauthorized inputs cannot cross promotion;
- media and packets remain quarantined before promotion;
- cleanup completes at every failure point.

P6 status at this disposition: the shipped provider does not satisfy the repartition non-amplification obligation above, and no named control in this repository evaluates it. Its equal-class rotation is keyed to `ResourceScopeId`, which is derived from the allocation address of a fresh process-local scope identity at each scope construction, so repartitioning one FairnessRoot's demands across additional AttributionChildScopes beneath that same root gives that root more rotation turns and defers a competing root. The provider rotates over scope identities rather than over FairnessRoots. This is a blocking obligation on the resource provider's fairness slice. It must not be reported as passing, no existing control may be cited as evidence for it, and the gate must not be reworded into something the current provider already satisfies. The connector-local scheduling-metadata obligation is a separate claim about capacity authority and does not discharge P6.

### 16.4 Promotion

- independently remove every `MayPromote` conjunct;
- endpoint identity mismatch closes the channel;
- cross-context and cross-channel replay fail;
- old durable facts and old control signals do not recreate handles;
- every send and receive rejects stale or foreign-principal capabilities.

### 16.5 Connectors and recovery

- direct, TURN, generic relay, and Closed member relay positive controls;
- candidate racing and first-working-path behavior;
- restrictive-network matrix;
- two authenticated channels active concurrently;
- handoff with no relay-to-relay messages;
- delayed old callbacks cannot mutate replacement state;
- forced old-path failure cannot promote an unauthenticated new path;
- native real-time flows are optional connector capabilities bound to a live session;
- fixed codec and application-media semantics are absent from the basal core;
- pre-promotion track setup cannot reach application delivery.

### 16.6 Relay

- exact endpoint allocation;
- no arbitrary destination or fanout;
- visible member-relay identity;
- anonymous relay credential rejection;
- relay endpoint-substitution negatives;
- exact allocation ownership, lease-backed buffering and retry, provider bandwidth constraints, and optional local cost policy.

### 16.7 Reachability and application boundary

- observation age uses local monotonic time;
- failed observations do not mutate roster;
- signaling success with no carrier returns a no-path result;
- application receives no data before promotion;
- explicit application intermediary remains a separate application workflow.

### 16.8 Persistence and crash

- store opening creates no live transport or session state;
- pending effect recovery is idempotent;
- current durable basis is independently reopenable;
- rollback without an independent witness preserves the documented impossibility result.

## 17. Required implementation artifacts

A conforming implementation supplies:

1. package and dependency graph;
2. complete accepted-input and effect inventory;
3. durable canonical test vectors;
4. endpoint-authentication and channel-binding test vectors;
5. connector profile specifications;
6. resource-provider and integration report for every supported target, giving exactness and residual classification per resource dimension, the host isolation domains used, the concrete scheduling policy the provider implements, and evidence that the policy preserves the basal properties in section 14.1;
7. model or property tests for durable projection and conflict;
8. speculative-work and promotion state model;
9. crash and effect-idempotency model;
10. red-team evidence bundle for the target catalog;
11. proof that application payload cannot reach signaling constructors or effects;
12. proof that no durable route or monotonic path-generation dependency remains in the basal path.

## 18. Owner decisions

The owner must select:

- exact cryptographic profiles;
- Closed governance proof and relay authorization profile;
- signaling and connector profiles;
- required egress and restrictive-network environments;
- resource-provider integration and host isolation for each deployment form;
- any optional local ceiling or cost policy;
- session recovery and multi-channel policy;
- reachability display and freshness policy;
- application data-operation set;
- optional durable application contract domains.

These selections are delivered as a provider and integration report, not as a dossier of chosen numbers. The report names each provider and deployment form, states which resource dimensions are exactly observable, conservatively claimable, isolatable in a host-enforced domain, or unobservable residuals, and records the concrete scheduling policy in use with evidence that it preserves the basal properties in section 14.1.

Every numeric protocol or provider limit requires proof from that protocol or provider. Every optional local policy value requires owner review and is never assumed present by basal conformance. Measurements characterize performance, cost, scheduling, regression, and opaque residuals. They do not define universal semantic cardinality.
