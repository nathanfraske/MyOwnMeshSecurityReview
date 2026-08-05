# Arc 03 resource ownership report

Status: normative target and draft working-tree disposition for the elastic
resource correction. The connector lifecycle and authority behavior at
`8a2351d` remains accepted. This report is not exact-head execution evidence and
does not claim that the current branch accounts for every native or OS
allocation.

This revision reframes the report in response to PR #5 review 4865297956,
anchored at `378dd82`, and review 4869373979, anchored at `f58dab6`. Those
anchors are cited as provenance for the review text only. They are never
execution evidence, and this revision records no re-verification at either.
Nothing below is an
exact-head execution claim; every statement about the working tree remains a
draft disposition until an owner reruns the evidence program in Section 8.

## 0. What this report is

This is a **provider/integration boundary report**, not a numeric owner dossier.

It states *which owner charges which resource dimension* and *which dimensions
remain named residuals*. It does not state how much capacity exists, and it
does not supply, recommend, or imply a numeric grant, ceiling, or budget.

```text
integration report  (this document)
    which owner holds which lease in which dimension
    where ownership transfers, and where it ends
    which dimensions are named residuals rather than charges

provider report  (the deployment or embedder)
    how much capacity exists in each dimension
    where that capacity came from
    which optional local ceilings, if any, are selected
```

Any number appearing below is a structural ownership-domain count derived from
the code's shape: how many distinct records, leases, or residual domains an
owner holds. Structural counts are not deployment-capacity recommendations,
universal protocol limits, or evidence of exact physical resource quantity.

Reading rule: if a statement here fixes a magnitude, it is a defect in this
report, not a requirement on an implementation.

## 1. Contract

Every protected allocation, retained value, task, queue entry, native object, and scheduled work unit holds a live finite lease from the applicable resource provider.

Basal MyOwnMesh defines no fixed maximum number of Mesh runtimes, peers, connector attempts, sessions, or real-time flows. A finite host still has finite resources. A new operation is admitted when its exact composite claim fits the current process grant. Otherwise it receives typed resource pressure or unavailability.

```text
ResourceProvider
    -> ResourceClaim by actual resource dimension
    -> ResourceLease held by the exact owner
    -> explicit release, transfer, permitted reclamation, or failed retention

ProcessResourceRoot
    -> one process grant
    -> shared Mesh accounting scopes
    -> attempt and connector owners
    -> callback, cleanup, candidate, and real-time descendants
```

Creating a Mesh scope does not create capacity. No accounting, attribution, or observation path mints capacity. Concurrently held charges never exceed the grant in any dimension, exact release restores exactly that capacity, and every immediate acquisition path applies the admission gate to its full charge, including child-scope and reservation bookkeeping. Unused capacity remains borrowable unless an explicit local isolation policy forbids it. During an exact pending reclamation turn, only the charge still needed by that demand is reserved; surplus capacity remains borrowable even in an overlapping dimension. These are properties required of any conforming provider.

A pending demand may request retirement from the exact owner of a lease whose owner contract declares it reclaimable. That notification does not release, transfer, or invalidate the lease. The owner must finish concrete cleanup and drop the exact lease, or retain the exact charge through its failed-cleanup state. Time passage creates neither a reclaim request nor a release. This provides a bounded service opportunity only when the conflicting capacity is held by registered reclaimable speculation and its owner completes cleanup. It does not promise admission against nonreclaimable admitted work, ignored retirement, or failed cleanup.

### 1.1 Provider boundary

The provider is an injected port, not a fixed implementation. This document fixes the properties above and writes no capacity value.

```text
production
    host-backed provider   capacity derived from actual host or OS facts
    isolated provider      capacity bounded by an enforced container, cgroup, or appliance boundary
    injected provider      capacity supplied by the embedding process owner

tests and explicit local envelopes
    deterministic finite provider over one explicit finite grant

optional local ceilings
    explicitly optional, owner-selected, never a basal limit
```

Current state, stated as disposition rather than as verified evidence: the deterministic finite provider is the only implementation in the tree. It derives capacity from one explicit finite grant and computes none of it. Tests install it over fixture grants; the connector-capable daemon path installs it over a grant whose every dimension the deployment owner must supply explicitly, with no default and no fallback. A host-backed or isolated production provider does not exist yet. That absence is a named gap, not a silent one.

**Concrete deterministic-provider policy.** The following describes the installed provider's arbitration. It is that provider's policy, verified against that provider. It is not basal architecture, and a different conforming provider may satisfy Section 1 with different arbitration without reopening the property contract.

Under overlapping pressure the deterministic finite provider represents one exact move-only pending demand per scope, selects `Cleanup`, then `Admitted`, then `Speculative`, and rotates equal-authority turns across process-local AttributionChildScope identities rather than across FairnessRoots. That rotation key is the disclosed fairness gap recorded in Section 5.2. It publishes a reclaim request only after proving the selected victim set can satisfy the deficit. Its arbitration reads no clock, no entropy, and no host fact, so identical claim sequences over identical grants produce identical admission outcomes.

**Optional local ceilings.** Every ceiling named in this report is owner-selected and separable. Removing all of them leaves a conforming system that still admits work solely through provider claims. A ceiling is never a protocol bound and never a provider structural limit, and no ceiling value originates in this document.

### 1.2 Fairness attribution vocabulary

This vocabulary is closed. Scheduling attribution has exactly two terms, and any other phrase used elsewhere for the same idea must be read as one of them.

**FairnessRoot.** Process-local scheduling attribution. It is selected by the trusted provider or ingress owner, never by the claimant, and a claimant cannot mint one. It carries no authority and selects no universal scheduler or turn model.

A FairnessRoot is explicitly **not** a Device identity, a Mesh identity, a durable identity, an endpoint identity, an authentication or authorization root or capability, or any wire value. Nothing a remote peer sends can create, name, split, or select one. Scheduling attribution and authority are separate concerns, and reading a FairnessRoot as authority is a category error.

**AttributionChildScope.** Refines accounting below exactly one FairnessRoot. It exists to attribute charges more finely for measurement and ownership. It **cannot create a share and cannot create a turn.** Minting, cloning, or rotating any number of AttributionChildScopes under one root must leave that root's service share unchanged.

The obligation that follows from the closed vocabulary: service share is a property of FairnessRoots, and accounting detail is a property of AttributionChildScopes. Any provider whose arbitration rotates over AttributionChildScope identities rather than over FairnessRoots grants a claimant more turns for holding more child scopes, which the vocabulary forbids. Section 5.2 discloses that the installed provider does exactly this.

## 2. Limit classes

| Class | Meaning | Basal effect |
| --- | --- | --- |
| Protocol-shape bound | Canonical parser or wire validity | Invalid input is rejected |
| Provider structural limit | Actual transport, codec, kernel, hardware, or dependency constraint | Provider reports unsupported or unavailable |
| Runtime resource availability | Current memory, handles, sockets, tasks, storage, and work grant | Provider grants a lease or returns typed pressure |
| Optional local policy ceiling | Explicit administrator, Closed, cost, appliance, test, or compatibility restriction | Wrapper may refuse a claim the provider could otherwise grant |

No class may silently stand in for another. In particular, an optional local policy ceiling may never be reported as a protocol-shape bound or a provider structural limit, and a provider structural limit may never be presented as a recommended deployment value. No value in any class originates in this document.

## 3. Field-by-field static policy disposition

The current source has two distinct policy surfaces. The process provider grant is runtime capacity. The WebRTC profile contains either optional local restrictions or explicit temporary compatibility shape. Neither surface creates mesh authority.

| Current field | Current disposition | Basal meaning |
| --- | --- | --- |
| `WebRtcConnectorCapablePolicy.resources` | Required process-backed provider port | Shares one process grant; cloning the policy creates no capacity |
| `ConnectorCallbackPolicy.local_mailboxes.control` | Optional local item ceiling; absent from `elastic_data_only` and `elastic_realtime` | Not a basal callback count |
| `ConnectorCallbackPolicy.local_mailboxes.endpoint_data` | Optional local item ceiling; absent from elastic constructors | Not a basal callback count |
| `ConnectorCallbackServiceWeights.control` | Optional connector-local scheduling quantum | Does not reserve provider capacity or guarantee cross-scope admission |
| `ConnectorCallbackServiceWeights.endpoint_data` | Optional connector-local scheduling quantum | Does not reserve provider capacity or guarantee cross-scope admission |
| `ConnectorCallbackServiceWeights.realtime` | Optional connector-local scheduling quantum when real-time work is enabled | Does not reserve provider capacity or select a codec |
| `RealtimeConnectorPolicy::Disabled` | Explicitly disables generic real-time ownership | Valid data-only profile |
| `RealtimeConnectorPolicy::Enabled(None)` | Enables generic provider-backed real-time ownership without the static local envelope below | Does not install H.264, Opus, tracks, or application flow meaning |
| `EnabledRealtimeConnectorPolicy.max_unit_bytes` | Optional local or compatibility ceiling | Not a basal endpoint-frame limit |
| `ConnectorRealtimeFlowPolicy.max_inbound_active_flows` | Optional local or compatibility ceiling | Live flow admission otherwise follows provider claims |
| `ConnectorRealtimeFlowPolicy.max_outbound_active_flows` | Optional local or compatibility ceiling | Live flow admission otherwise follows provider claims |
| `ConnectorRealtimeFlowPolicy.queue_capacity_per_flow` | Optional local or compatibility item ceiling | Queued content and work still require provider leases |
| `ConnectorRealtimeFlowPolicy.max_inbound_fragment_bytes` | Optional local ceiling; may also be constrained by an active compatibility provider | Not a generic codec rule |
| `ConnectorRealtimeFlowPolicy.max_inbound_fragments_per_unit` | Optional local ceiling; checked against the temporary H.264 hard stop when that adapter is selected | Not basal MyOwnMesh semantics |
| `ConnectorRealtimeFlowPolicy.max_in_progress_units_per_flow` | Optional local or compatibility ceiling | Live storage and work claims remain required |
| `ConnectorRealtimeFlowPolicy.max_pre_auth_packets` | Optional cumulative compatibility or deployment envelope | Not a time or rate authority |
| `ConnectorRealtimeFlowPolicy.max_pre_auth_content_bytes` | Optional cumulative compatibility or deployment envelope | Not a claim of exact retained memory |
| `ConnectorRealtimeByteBudgets.max_inbound_bytes` | Optional connector-local inbound partition | Covers connector-visible retained bytes only |
| `ConnectorRealtimeByteBudgets.max_outbound_bytes` | Optional connector-local outbound partition | Covers connector-visible retained bytes only |
| `ConnectorRealtimeFlowPolicy.overflow_rule` | Explicit connector-local complete-unit pressure behavior; the current closed set accepts only `DropNewest` | Not a codec choice, application delivery guarantee, or numeric capacity |
| `PendingRemoteCandidateLocalCeiling.max_unique_items` | Optional per-attempt ingress ceiling; absent from `PendingRemoteCandidatePolicy::elastic` | Not a basal candidate count |
| `PendingRemoteCandidateLocalCeiling.max_content_bytes` | Optional per-attempt visible-content ceiling | Not exact retained memory |
| `PendingRemoteCandidateLocalCeiling.max_duplicate_submissions` | Optional per-attempt work ceiling | Not a provider capacity grant |
| `PendingRemoteCandidateLocalCeiling.max_application_work` | Optional per-attempt native-application ceiling | Not a provider capacity grant |
| `LegacyWebRtcMediaProfile.max_lanes_per_kind` | Temporary feature-gated compatibility shape, validated against the adapter hard stop | Not a basal flow or session limit |
| `LegacyWebRtcMediaProfile.preprovisioned_video_lanes` | Explicit temporary compatibility deployment choice | No video meaning enters basal authority |
| `LegacyWebRtcMediaProfile.preprovisioned_audio_lanes` | Explicit temporary compatibility deployment choice | No audio meaning enters basal authority |
| `LEGACY_H264_MAX_FRAGMENTS_PER_UNIT` | Fixed hard stop of the temporary H.264 adapter | Provider structural limit, not a production policy recommendation |
| `LEGACY_MEDIA_MAX_LANES_PER_KIND` | Fixed identity-space limit of the temporary H.264 and Opus adapter | Compatibility structural limit, not a basal Mesh limit |

Every row above marked optional is optional in the strong sense: the owner selects it, the owner supplies its value, and the system remains conforming with the entire set absent. The daemon requires the owner to select whether the optional local ceiling set is `none` or `enabled`. It supplies no default and invents no value. Selecting `none` removes the listed product-count ceilings, but it does not make native or OS resources exact, and it does not remove the provider claims that admit the work. Provider fairness remains structural and conditional on the exact reclaimability and cleanup conditions above.

The terminal candidate-attempt, lifecycle, cleanup, close, restart, codec-neutrality, and compatibility authority semantics remain unchanged. A provider refusal retires the exact speculative attempt where the accepted Arc 03 owner already requires terminal refusal.

## 4. Current resource ownership and residual matrix

This section is the integration half of the boundary in Section 0. Each row names which owner charges which dimension and where that charge stops being exact. No row states how much capacity exists; that is the provider's half. Unit counts below are structural ownership-domain counts: they are not deployment-capacity recommendations, universal protocol limits, or evidence of exact physical resource quantity.

**Open question, Slice C: residual enforcement.** The "Explicit residual or gap" column names dimensions this integration does not charge. How those named residuals become enforced charges is **not decided here and remains open.** The candidate answers are not equivalent — an adapter hook that claims the dimension directly, an isolation boundary that bounds it externally, a conservative over-charge that covers it inexactly, or an owner decision that it stays permanently unenforced and disclosed. Each has different exactness and different failure behavior.

This report does not choose among them, does not rank them, and does not assert that any residual is enforceable in principle. Nothing in Sections 5 or 7 closes this question, and no control below may be cited as having closed it. A residual named here is an honest gap, and it stays a gap until Slice C resolves it explicitly.

| Resource dimension | Current Arc 03 charge | Exact current boundary | Explicit residual or gap |
| --- | --- | --- | --- |
| Accounted memory | Selected Rust-visible records, payload lengths, and conservative capacities | Exact only for the charged byte quantity | Allocator headers, slack, shared allocation layout, and native dependency memory are not complete |
| Queued bytes | Visible candidate, callback, endpoint, and real-time content while queue-owned | Exact logical content for the live queue lease; the production candidate wrapper separately charges its actual retained String capacities before node insertion | Allocator metadata and native internal queues remain separate residuals |
| Socket or handle | Exposed in the provider grant vocabulary | The current WebRTC connector floor does not charge this dimension before native peer construction | ICE, UDP, TURN, event, and other native handles are an OS or dependency residual until an adapter hook or isolation boundary owns them |
| Native transport object | One unit in the connector candidate floor for the native peer connection | Retained through the close owner; failed close retains the connector claim | ICE-agent internals, transceivers, tracks, and dependency-created children are not each counted as native objects |
| Worker or task | One connector-worker unit in the connector floor, explicit scheduled-work claims, and one process cleanup-infrastructure claim acquired before constructing its runtime and OS thread | Exact for the charged connector and persistent cleanup obligations | The cleanup runtime heap, native thread-stack size, and dependency-created tasks remain opaque residuals rather than exact byte charges |
| Callback or scheduled work | Connector cleanup is reserved in the opening floor; callback, candidate, and real-time operations acquire specific work leases | Exact for each charged obligation | A work unit is not CPU time and does not imply scheduler fairness |
| Storage bytes | Provider primitive exists; Arc 03 connector ownership does not add a durable byte-storage path | Exact only where a store adapter acquires this class | Filesystem allocation units, metadata, journals, and device caches remain provider or filesystem residuals |
| Storage objects | Applied remote-candidate retention charges the ownership records it keeps for attempt lifetime | Exact for the charged retained-record count | The class does not describe allocator bytes or native ICE storage |
| Relay or provider allocation | Exposed in the provider grant vocabulary | The current WebRTC and TURN connector path does not charge this dimension for each native relay allocation | TURN server allocation state, provider quotas, and external cost remain unaccounted by the connector until an adapter hook exists |
| Parsing or CPU work | Candidate, callback, and real-time paths acquire discrete work units | Exact for admitted work-unit count | CPU duration, runtime scheduling, and native-library work are observational unless isolated |
| Opaque dependency residual | Conservative units accompany connector, scope, callback, candidate, and flow ownership | Exact only as a named ownership domain | It is not bytes, handles, native-object count, or proof of complete dependency accounting |

Local ICE conversion owns one structural work lease and one named opaque residual before `to_json`. Returned String content and capacities are charged before MyOwnMesh retains the result. `RTCIceCandidate::from`, `to_ice`, `CandidateBase`, formatting temporaries, allocator metadata, and the initial output allocation remain dependency residuals because the pinned API exposes no allocation plan or caller-owned fallible output buffer. The pre-conversion claim bounds concurrent conversion work, not bytes consumed by one dependency call.

Remote candidate retention is split by owner. The connector-neutral attempt owns the digest and application record. The production pending value owns the `LocalIceCandidate` String capacities, logical queued content, wrapper, queue node, and production digest node. After native application, String ownership is released. The retained application record then charges two storage-object units for its ordered and linked attempt records plus three opaque residual units for their backing nodes and the native ICE-agent copy that `webrtc-rs` does not expose. These are ownership-domain counts, not retained-byte claims.

V4 remote SDP handling begins from the raw input String. It acquires that String capacity, parsing work, one scheduled-work unit, and named parser, allocator, and native-description residuals before credential extraction or the pinned native SDP constructor. An allocation-free pass computes the media-section, binding-record, and credential-string shape. The lease transitions to a conservative input-bounded claim for preallocated parser sections, bindings, String copies, and location keys before the parser runs. Hash-table buckets and allocator metadata remain named residuals. The lease then transitions to measured Rust-visible records and String capacities before retention. Native success releases the scheduled-work unit. One shared credential resource owner transfers to the connector close owner before native application. Each retained owner charges its close-registry Arc pointer, owner struct, Arc reference counters, one storage object, and two named Arc and linked-list allocation residuals. The pinned dependency can queue description work after the call returns, so successful renegotiation owners remain charged until connector close. Provider pressure bounds that accumulation. Cancellation, native error, state-commit mismatch, and failed native close keep the native-description residual charged. Process-local credential clones do not duplicate retained Strings or capacity. Signaling bridge queues, fanout, and duplicate hashing before connector entry are an explicit hostile-ingress residual outside Arc 03.

The pinned `webrtc-ice 0.13.0` adapter is locally patched so remote-candidate
application awaits the dependency's internal insertion and mDNS resolution.
The MyOwnMesh attempt operation lease therefore remains live until that
dependency work returns. Failed or disabled mDNS resolution returns an error;
it cannot be recorded as a successfully applied candidate. This closes the old
detached-task gap across ICE restart without changing ICE selection, STUN, or
TURN.

Native peer construction remains an opaque dependency boundary. The close
owner marks native allocation before entering the constructor. If cancellation
requests close before a returned native port attaches, that owner remains
`Closing`, accepts the exact late port, and releases the lease only after close
succeeds. A constructor that definitively returns without a closeable port
retains the exact connector claim and reports terminal failure. It does not
claim that hidden constructor tasks stopped or make the capacity reusable.

The daemon currently requires the deployment owner to supply every provider dimension explicitly, with no default and no fallback. This is the explicit-local-envelope case of Section 1.1: the deterministic finite provider enforcing a grant the owner wrote. It is not a host-backed or isolated provider, and it must not be described as one. A supplied `SocketOrHandle` or `RelayOrProviderAllocation` grant does not by itself make the WebRTC adapter consume that dimension. Those fields are forward-compatible policy inputs and must not be reported as enforced native limits until the corresponding adapter claim exists.

The `transport-lab` feature is the tests case of Section 1.1. It exposes fixture-only grant derivation helpers. They sum production structural claims for the connector profiles and Mesh scopes supplied by a test, then add conservative candidate and remote-SDP claims from explicit fixture bounds. Candidate strings, content, concurrent parsing work, queue records, digest records, provider bookkeeping, remote-SDP parser storage, and remote-description retention are separate components. The helpers select no profile, workload, or production value and are absent from the default V4 API. The TURN control funds four data-only profiles and four Mesh scope records for its two sequential scenarios. At most two are active concurrently. It adds signaling-frame-derived candidate and remote-SDP bounds to one process provider. This proves shared-provider enforcement for that finite test workload. The profile and scope counts it funds are the structural shape of that fixture. Structural counts are not deployment-capacity recommendations, universal protocol limits, or evidence of exact physical resource quantity. It does not claim exact native WebRTC allocation accounting or recommend a deployment grant.

## 5. Pressure and admission

### 5.1 Properties required of any provider

The process provider checks the composite claim before admission. An AttributionChildScope receives no fixed share.

This document requires no pending-demand mechanism. A conforming provider may refuse outright, may queue, may retain capacity for a waiting demand, or may do none of these. Selected turns, exact-charge reservation, cooperative entry, and drop-cancellation are mechanics of one provider design and are stated in Section 5.2, not here.

**Conditional safety.** If a provider does retain or reserve capacity for a pending demand, then that retention:

- mints no capacity, in that dimension or any other;
- releases, transfers, or invalidates no other owner's lease;
- blocks no surplus beyond what the pending demand itself requires, absent an explicit, named local isolation policy that forbids borrowing;
- creates no admission guarantee against nonreclaimable admitted pressure, ignored retirement, or failed cleanup;
- ends when the demand ends, without a timer and without consuming another owner's capacity.

A provider that implements no retention at all satisfies this clause vacuously and remains conforming.

Connector cleanup work is reserved with the connector before pressure, so native close does not need a new speculative permit after failure. When pressure selects a reclaimable speculative connector, the provider requests retirement through its opaque target and the connector's existing close owner performs cleanup. The provider never reuses the charge until the exact lease is dropped. If cleanup fails, the failed owner keeps that claim charged and later admission receives typed pressure. Resource refusal is an availability result and never an Open or Closed authorization denial.

One large claim may consume more capacity than many small claims. Tests must compare resource quantities, not object counts.

Connector-local scheduling metadata is not capacity. A connector-local scheduling weight or quantum orders work inside its own owner. It reserves no provider capacity, guarantees no cross-scope admission, and multiplying it multiplies no grant. This is a claim about capacity authority and does not discharge the FairnessRoot share obligation.

Non-multipliable service weight is a separate obligation, stated in the closed vocabulary of Section 1.2: minting, cloning, or rotating any number of AttributionChildScopes under one FairnessRoot must not improve that root's service share against another FairnessRoot. It is not satisfied at this disposition; see Section 5.2.

### 5.2 Concrete deterministic-provider policy

The installed deterministic finite provider does retain capacity for a pending demand, so Section 5.1's conditional safety clause applies to it non-vacuously. Its retention mechanics are:

- outside a selected pending turn, AttributionChildScopes may borrow all currently unused capacity;
- during a turn, the selected demand's exact charge is reserved, and surplus remains borrowable including surplus in an overlapping dimension;
- a demand that cannot fit enters a provider-owned turn only through the cooperative API;
- dropping the demand cancels the turn without releasing another owner's capacity.

The turn is move-only and scoped to overlapping resource dimensions. Arbitration is ordered by `Cleanup`, `Admitted`, then `Speculative`, and rotated across equal-authority process-local AttributionChildScope identities.

All of the above is that provider's arbitration policy. It is verified against that provider and is not required of a conforming replacement. A provider that never retains pending-demand capacity has no analogue of any bullet in this list and is not thereby nonconforming.

The authority-class taxonomy is part of the provider port and stays architectural. The order in which those classes are served is provider policy. A conforming provider must still satisfy Section 5.1 and must still never release an owner's lease, but it may arbitrate its own way.

**Disclosed fairness nonconformance of the installed provider.** Stated in the closed vocabulary of Section 1.2: equal-authority rotation is keyed to AttributionChildScope identities rather than to FairnessRoots, and those identities are mintable by the claimant they attribute to. A claimant holding N child scopes therefore receives N turns against another claimant's one. An AttributionChildScope is thereby creating a turn, which Section 1.2 forbids, so the installed provider does not satisfy the non-multipliable service weight obligation.

This is a disclosed gap, not a passing result. Review 4865297956 §8 defers the correction to Slice D, which must bind a pending demand to a FairnessRoot selected by the trusted provider or ingress owner rather than to a mintable scope identity. The gap is fairness-only and does not affect the conservation, exact-release, no-minting, or cleanup-ownership dispositions recorded elsewhere in this report. It is separate from, and does not overlap, the host-backed and isolated provider gap in Section 1.1 or the residual-enforcement question in Section 4.

## 6. Queue contracts

```text
connector lifecycle
    fixed non-lossy state owner

reliable endpoint stream
    byte and work leases with producer backpressure or typed failure

interactive real-time flow
    complete-unit leases and provider or application pressure semantics

satellite or store-and-forward
    persistent spool with storage-byte and storage-object leases

raw storage or removable media
    storage leases, not a live-network packet queue
```

No queue may grow without leases. A slow operation is not invalid merely because it is slow. Time passage alone does not release its claim.

## 7. Required controls

### 7.1 Property-level controls

These hold for any conforming provider. They are the controls the transition gate depends on.

- no basal `MAX_MESHES`, `MAX_PEERS`, `MAX_ATTEMPTS`, or `MAX_FLOWS`;
- no hidden default cardinality, `unlimited` sentinel, or default grant exists;
- one more object is admitted whenever its claim fits the shared grant and provider bookkeeping;
- many small peers or flows coexist while resources remain;
- one large claim may cost more than many small claims, so no object count implies admissibility;
- more Mesh scopes do not multiply the process grant, and no accounting or observation path mints capacity;
- exact lease release restores exactly that capacity;
- concurrently held charges never exceed the grant in any dimension;
- **conditional, pending-demand retention:** if a provider retains or reserves capacity for a pending demand, that retention mints no capacity, releases or invalidates no other owner's lease, and blocks no surplus beyond what that demand itself requires absent an explicit, named local isolation policy. A provider that never retains satisfies this vacuously and is not thereby nonconforming;
- refusal names a resource dimension rather than an object count;
- refusal is an availability result and never an Open or Closed authorization denial;
- a nonwaiting acquisition returns typed pressure without requesting another owner's cleanup;
- **conditional, cooperative retirement:** if a provider implements a cooperative retirement path, it wakes the exact owner of a lease its contract declares reclaimable and does not release, transfer, or invalidate that lease;
- failed cleanup retains the charge, and no provider reuses that charge until the exact lease is dropped;
- connector cleanup can proceed from its pre-reserved claim even after the shared grant is full;
- a connector-local scheduling weight reserves no provider capacity and multiplying it multiplies no grant (connector-local scheduling metadata is not capacity; this does not discharge the FairnessRoot share obligation below);
- minting, cloning, or rotating any number of AttributionChildScopes under one FairnessRoot cannot improve that root's service share against another FairnessRoot — **no named control implements this, and it is not satisfied at this disposition**;
- unused capacity is borrowable unless an explicit, named local isolation policy forbids it;
- no valid slow lease is expired or reclaimed merely by elapsed time;
- slow work retains its finite lease without time-derived expiry;
- storage-backed work consumes storage leases;
- an optional local ceiling can deliberately restrict a deployment, and removing every ceiling still leaves a conforming system;
- the fairness claim is limited to reclaimable speculative conflicts whose owner completes cleanup, and does not cover nonreclaimable admitted pressure.

**Missing control, blocking.** The FairnessRoot share obligation above has no implementing control in this repository, and the installed provider does not satisfy it: equal-authority rotation is keyed to mintable AttributionChildScope identities rather than to FairnessRoots. No control in Section 7.2 may be cited as evidence for it — those verify per-scope rotation, which is the mechanism at issue rather than a proof of FairnessRoot fairness. Section 7.1 is therefore not fully discharged at this disposition. Closing it is a Slice D obligation under review 4865297956 §8.

This is distinct from the Slice C residual-enforcement question in Section 4. Slice D concerns whose turn is next among charges the provider already accounts. Slice C concerns dimensions the integration does not charge at all. Neither closes the other.

### 7.2 Concrete deterministic-provider controls

These are verified against the installed deterministic finite provider. A conforming replacement changes what is verified here without reopening Section 7.1.

- one move-only pending demand exists per scope;
- a selected pending demand reserves its exact charge while leaving surplus capacity borrowable, including surplus in an overlapping dimension;
- plain scope bookkeeping cannot consume the charge reserved for that demand;
- a demand that cannot fit enters the turn only through the cooperative API, and dropping it cancels the turn without releasing another owner's capacity;
- a released speculative claim lets the selected demand retry;
- a pending demand selects structural authority before equal-class per-scope rotation;
- reclaim requests are published only after the provider proves the selected victim set can satisfy the deficit;
- the selected requester's scope cannot reacquire capacity ahead of its own turn;
- arbitration reads no clock, entropy, or host fact, so identical claim sequences over identical grants produce identical admission outcomes;
- the provider derives its capacity from one explicit finite grant and computes none of it.

The accepted lifecycle, cleanup, malformed-candidate, restart, direct WebRTC, TURN-selected, compiler-boundary, and compatibility controls remain required.

## 8. Measurements

Measurements remain useful for performance characterization, provider-cost estimation, regression detection, scheduler validation, opaque-allocation discovery, and choosing optional deployment policy. They do not define universal correctness or product cardinality.

For every run, retain the exact commit, platform and target, input workload, raw logs, failures, CPU and RSS observations, queue occupancy, service delay, candidate distribution, close result, and every sample. Do not infer a production ceiling from those observations.

A measurement never becomes a grant by being recorded. Crossing from the integration side of Section 0 to the provider side is an explicit owner decision made against a named provider, with the measurement as evidence and not as the value. This report proposes no such crossing.
