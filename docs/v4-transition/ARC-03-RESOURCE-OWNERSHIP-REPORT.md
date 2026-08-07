# Arc 03 resource ownership report

Status: normative target and draft working-tree disposition for the elastic
resource correction. The connector lifecycle and authority behavior at
`8a2351d` remains accepted. This report is not exact-head execution evidence and
does not claim that the current branch accounts for every native or OS
allocation.

This revision reframes the report in response to PR #5 review 4865297956,
anchored at `378dd82`, review 4869373979, anchored at `f58dab6`, and review
4869979096, anchored at `ea1c7e87bfbd5bab76602d61b863fe8a7e5a8545`, review
4870701740, controlling owner review 4870850580, anchored at exact head
`7e2ba9e5ee042d3aa6c39f16670ab9a646b44e41`, and owner review 4871447845,
anchored at `8c8597f47b1dd82a62abbce5da6a276b12beac77`, and reviews 4876022720
and 4876150752, whose absolute-capacity formulation supersedes the earlier
`AccountingFit` wording. Those anchors are cited as
provenance for the review text only. They are never execution evidence, and
this revision records no re-verification at any of them.

Property numbering P1 through P8 and the closed FairnessRoot and
AttributionChildScope definitions are fixed by `ARCHITECTURE.md`. This report
uses them and does not redefine them. Where this report and `ARCHITECTURE.md`
appear to differ, `ARCHITECTURE.md` governs and the difference is a defect
here.

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

### 0.1 Evidence layers

Earlier revisions let four different kinds of claim share one voice, so an
obligation could be misread as a result and a source reading could be misread
as a measurement. The layers are distinct, they are not substitutable, and no
statement may silently change layer.

```text
L1  normative target
        what any conforming provider or owner must satisfy
        holds independently of this repository
        Sections 1, 1.1, 1.2, 2, 5.1, 6, 7.1

L2  static source disposition
        what the current source appears to do, established by reading it
        a reading, not an execution result
        Sections 3, 4, 5.2, and the current-state notes in 1.1

L3  exact-head correctness evidence
        that a named control actually passed at a named commit
        lives in the Section 7 control lists and in PR CI, nowhere else
        this report records none of it

L4  performance and opaque-resource characterization
        observed cost, timing, occupancy, and residual discovery
        Section 8
```

Layer rules:

- An L1 obligation is never discharged by an L2 reading. "The source appears to
  do this" is not "this is required" and is not "this was verified".
- An L2 disposition is never evidence that a control passed. Only L3 is, and L3
  lives in the Section 7 control lists and PR CI at a named commit. This report
  asserts no L3 result.
- An L4 measurement is never an L1 obligation and never becomes a grant. See
  Section 8.
- A gap disclosed at any layer stays disclosed. Disclosure is not discharge.

**Accepted CI at exact head `7e2ba9e` is runtime non-regression evidence only,
and becomes prior-head evidence the moment the branch moves.** While `7e2ba9e`
is the exact head, an accepted run there shows that retained runtime behavior
still runs as accepted at that head, and nothing more. Once the branch advances
past it, that run is prior-head evidence: it describes a commit that is no
longer the head and carries no claim about the current one. In neither case does
it prove P6 partition non-amplification, grant contraction over `S`, `Gc`, `O`,
`T`, `E`, or `B`, hostile-ingress progress or backpressure, an enforceable
isolation envelope, an actual reserved guarantee, or Slice C closure. No control
for any of those exists at that head, so a passing run cannot have exercised
them.

**Accepted CI at exact head `6a22911` is runtime non-regression evidence only.**
It is an L3 result about a narrow question: that retained runtime behavior still
runs as accepted at that head. It does **not** prove P6 partition
non-amplification, does not prove grant contraction over `S`, `Gc`, `O`, `T`, or
`B`, does not prove hostile-ingress progress or backpressure, does not prove
an enforceable isolation envelope, does not prove an actual reserved
guarantee, and does not close the Slice C residual-enforcement question. None of those has a control at that head, so a
passing run cannot have exercised them. No part of that CI result may be cited
toward any of them.

**Measurements are required, and are never capacity.** Every arc that touches a
resource path must produce L4 characterization; omitting it is a defect. That
requirement does not let an L4 observation set, justify, or imply a grant,
ceiling, budget, or admissible-object count. Crossing from measurement to grant
is an explicit owner decision made against a named provider, with the
measurement as evidence and never as the value.

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

**`E` and `B` are orthogonal premises, not a hierarchy.** `E` is an enforceable isolation envelope or ceiling: a cgroup, job object, process limit, or appliance bound that will stop the process from exceeding it. That is *containment*. It says nothing about whether the capacity is available — a process inside a 2 GiB envelope has no guarantee that 2 GiB is obtainable, only that it will be stopped at 2 GiB. `B` is an *actual reserved or owned guarantee*: capacity held for this process.

Neither implies the other, in either direction. Containment without reservation is ordinary: an envelope caps you and guarantees nothing. Reservation without containment is equally possible: capacity may be genuinely held for a process that nothing stops from trying to exceed it. The four combinations are all real, and they are decided **per resource dimension** — a provider may hold `E` in one dimension, `B` in another, both in a third, and neither in a fourth.

```text
E proved?   B proved?   what may be claimed
no          no          neither containment nor reservation
yes         no          containment only
no          yes         reservation only
yes         yes         both, each on its own proof
```

**Provider class names describe which premises are proved, and rank nothing:**

```text
accounting-only
    neither E nor B proved for the dimension
    the grant is a bookkeeping vector the process was told to respect
    exceeding it is prevented by this process's own arithmetic alone

isolated
    E proved: something outside stops the process at E
    says nothing about whether B holds

backed
    B proved: capacity is actually held for this process
    says nothing about whether E holds
```

"Backed" is not a stronger form of "isolated", and neither subsumes the other. A provider proves each premise it wishes to claim, separately and per dimension, and claims nothing it has not proved. Treating `E` as `B` — or inferring either from the other — is the exact overclaim this split exists to prevent.

**`Gc` is an accounting commitment and nothing more.** It is the value this process has committed to hold itself to, and the absolute quantity `AccountingCapacity` starts from. It is **never proof that the capacity is contained** — that would be `E` — and **never proof that the capacity is available** — that would be `B`. A grant of 8 GiB does not mean 8 GiB is obtainable, reserved, or bounded; it means this process has undertaken not to commit past 8 GiB by its own arithmetic. Reading `Gc` as either containment or availability is the overclaim this whole model exists to prevent.

**Current state, as disposition rather than verified evidence.** The deterministic finite provider is the only implementation in the tree, and it is **accounting-only**. It takes one explicit finite grant vector and computes none of it. The connector-capable daemon path requires the deployment owner to supply every dimension explicitly, with no default and no fallback — and **an owner-supplied vector is not host backing**. It is a number the owner asked this process to respect. It establishes no `E` and no `B`, and it must never be reported as either. No provider proving `E` or `B` exists in the tree. That absence is a named gap, not a silent one.

**A provider never presents unproved containment or backing as established.** An accounting-only committed grant is explicitly an accounting commitment — not proof that substrate capacity exists, and not proof that allocation will succeed.

**Accounting-only is honest, and it is not sufficient on its own for final production closure.** Both halves matter. It is honest: a provider that says "I have committed to this vector and nothing outside enforces or reserves it" states exactly what is true, which is worth far more than a system quietly implying containment it does not have. But it is not enough to close production on, because where nothing is proved `EffectiveCapacity` equals `AccountingCapacity` and no substrate premise narrows it — nothing outside the process stops it, and nothing holds the capacity for it. Closing production requires proving `E` or `B` in the dimensions that matter. That proof does not exist today and is not claimed.

**A successful admission is not a guarantee of success.** A successful fit, including one narrowed by a proved `E` or `B`, does not guarantee that the allocator, the kernel, the runtime, the transport, an external relay, or the hardware will succeed. Those failures remain real and application-visible. Admission means the claim fit the commitment and whatever premises were proved; it never means the underlying operation cannot fail. Application code must still handle allocation failure, transport failure, relay failure, and hardware failure, and no statement in this report may be read as removing that obligation.

**Optional local ceilings** remain explicitly optional and owner-selected. Removing all of them leaves a conforming system that still admits work solely through provider claims. An optional ceiling is not an `E`: it is this process's own policy, enforced by the same arithmetic as the grant, not from outside.

**Concrete deterministic-provider policy.** The following describes the installed provider's arbitration. It is that provider's policy, verified against that provider. It is not basal architecture, and a different conforming provider may satisfy Section 1 with different arbitration without reopening the property contract.

Under overlapping pressure the deterministic finite provider represents one exact move-only pending demand per FairnessRoot, selects `Cleanup`, then `Admitted`, then `Speculative`, and rotates equal-authority turns across FairnessRoots. Both the demand cursor and the reclaim cursor are root-keyed, which is what removes the per-scope amplification mechanism recorded in Section 5.2. It publishes a reclaim request only after proving the selected victim set can satisfy the deficit. Its arbitration reads no clock, no entropy, and no host fact. The determinism this supports is narrow and is stated exactly in Section 7.2: it holds over identical already-issued `ResourceScopeId`s, identical provider state, and an identically ordered operation sequence. It is not a claim that two runs of the process agree.

**Optional local ceilings.** Every ceiling named in this report is owner-selected and separable. Removing all of them leaves a conforming system that still admits work solely through provider claims. A ceiling is never a protocol bound and never a provider structural limit, and no ceiling value originates in this document.

### 1.2 Fairness attribution vocabulary

`ARCHITECTURE.md` owns the closed definitions of **FairnessRoot** and **AttributionChildScope** and states P6. Those definitions are not restated or varied here. `FORMAL-PROOFS.md` Note 14.5e governs the exact P6 model and comparison; the statement below is this integration's summary of that note, not an independent formulation, and where the two appear to differ the proof note governs. This subsection records only what P6 means for this integration, what P6 does not claim, and what a deployment may choose.

**P6 as partition non-amplification, also called subdivision monotonicity.** The obligation is checkable on a bounded execution and needs no limit argument.

**What is fixed is the input workload, not a trace of outcomes.** An earlier revision fixed "one finite trace" including its releases. That was wrong: when an owner releases depends on when its work was admitted, so a release time is *derived* from the schedule under test. Fixing releases compares two different workloads and can manufacture or hide a difference. What is held fixed is only input:

```text
fixed input workload
    a finite set of FairnessRoots
    the initial provider state, including Gc in every dimension
    the arrival events: which demand arrives at which point, from which root
    per demand: a stable DemandId, its exact claim, its authority class,
        and its reclaimability
    one deterministic owner response rule for admitted work

derived, never fixed
    releases
    the decision sequence itself
    every observable compared below
```

**The two runs are topology-normalized.** Both runs use the **identical, pre-existing root and child-scope topology** and the **identical bookkeeping claims** for that topology. The scopes already exist in both runs and are charged identically in both. `DemandId`s are stable across the two runs. The *only* difference permitted between baseline and subdivided is the **mapping from `DemandId` to `AttributionChildScope`**.

This normalization is what makes the comparison sound. Earlier revisions tried to neutralize scope-creation cost by choosing a non-binding bookkeeping dimension or by prefunding; normalizing the topology instead removes the confound at its source, because no scope is created inside the comparison at all.

**Bookkeeping is real, finite, and fallible, and this normalization promises nothing otherwise.** Scope and reservation bookkeeping consume actual charged resource, that charge can fail, and scope creation can be refused under pressure like any other claim. Holding the topology fixed for the purpose of a comparison is a property of the *comparison*, not a claim that scopes are free, unbounded, or always creatable. Nothing here promises unlimited scopes.

**A deterministic, clock-free environment drives both runs.** The environment is a reducer over the fixed workload: it interleaves **exogenous** actions (arrivals from the workload) with **derived** owner actions (whatever the deterministic owner response rule produces from work actually admitted). It reads no clock, no entropy, and no host fact, so the interleaving is a function of the workload and the provider's own decisions and nothing else. **Terminal stuttering** is permitted: once a run has no further action, it stutters with no-op steps so both runs remain comparable over the same prefix length rather than one simply ending sooner.

The baseline run maps `A`'s demands onto `A`'s topology unsubdivided. The subdivided run maps the same `DemandId`s onto more of the same pre-existing child scopes beneath `A`. Demands, order, claims, authority, and reclaimability are identical; only the mapping differs.

**The comparison is prefix-wise over decisions.** An end-state comparison is too weak: it permits a provider to amplify `A` early and repay the difference later. Every decision prefix must hold. Let a decision prefix `k` be the first `k` provider decisions in a run:

```text
for every decision prefix k:

    cumulative selections of A
        (subdivided)  <=  (baseline)

    for every resource dimension d:
        cumulative admitted quantity of A in dimension d
            (subdivided)  <=  (baseline)

for every competitor B != A,
and for every selection of B in the baseline:
    that selection occurs in the subdivided run at a decision
    index no later than its baseline index

absence convention
    a selection that never occurs has index infinity, so a selection
    that the baseline makes and the subdivided run never makes
    counts as later and fails
```

Three quantifiers all bind at once: every decision prefix `k`, every resource dimension `d` for admitted quantity, and every competitor `B != A`. Dropping any one weakens the property — a per-dimension check omitted lets subdivision amplify in an unwatched dimension, and a single chosen competitor lets it amplify against the others. Both `A` bounds are over *cumulative* quantities at each `k`, not totals.

**P6 is one-way, not equality.** Subdividing beneath `A` must not buy `A` anything and must not cost any competitor anything. It is not required to leave the run identical. P6 deliberately does **not** require total outcome equality, share equality, or an identical decision sequence. A subdivision that leaves `A` *worse off*, or that leaves a competitor *better off*, is fully conforming — the property is a ceiling on what subdivision can gain, not a guarantee that subdivision is free. Reading it as "the partition is invisible" is too strong and would fail providers that are behaving correctly.

The property is therefore not a quantitative fairness target. It fixes no share, no ratio, no quantum, and no scheduler. A conforming provider may give roots wildly unequal outcomes for any local reason and still satisfy P6, provided no subdivision beneath a root breaks a prefix inequality for that root in any dimension or pushes any competitor's baseline selection later.

**What P6 does not claim.** P6 is scheduling attribution, and its guarantee stops at the process boundary.

- It does **not** claim that one FairnessRoot corresponds to one real-world claimant, principal, human, device, account, organization, or network peer.
- It provides **no Sybil resistance**. P6 constrains subdivision *beneath* a root and says nothing about how many roots exist or how they came to exist. If an actor is assigned several FairnessRoots, P6 places **no bound on that actor's aggregate treatment** — it neither promises nor denies any particular aggregate outcome, because root count is outside the property entirely. Bounding aggregate treatment across roots requires a separate mechanism, and this report supplies none.
- It is **not** an authorization, admission, identity, or anti-abuse property, and satisfying it implies nothing about the other seven properties.

These are unsupported claims, not open work items. No control in this report may be cited as evidence for any of them, and a future correction to the disclosed P6 gap will not supply them either.

**Trusted-local mapping is allowed.** Which local values a deployment maps onto a FairnessRoot is provider and deployment policy. A trusted provider or ingress owner may map a local ingress source, carrier, listener, connector instance, local account, or any other locally selected value onto a root. This report fixes no root taxonomy, no principal enumeration, and no universal scheduler model, and P6 requires none.

The boundary is between locally verified input and unverified assertion, not between kinds of real-world entity:

- The trusted provider or ingress owner **may** use facts it has itself verified or authenticated as mapping inputs — an authenticated local principal, a verified or isolated ingress domain, and similar locally established facts.
- The FairnessRoot value itself **remains opaque.** It is process-local, never transmitted, and never compared across processes; the mapping input is not the root.
- **No unverified claimant, peer, or wire assertion may directly name, select, split, rotate, or multiply a root.** Mere submission over the wire is never sufficient — local verification is what makes an input usable.

This is a provenance rule about what the provider may trust as input. It is not a premise that a root corresponds to a real-world identity, and it does not weaken the nonclaims above.

The consequence for this integration: scheduling outcome is a property of FairnessRoots, and accounting detail is a property of AttributionChildScopes. Any provider whose arbitration rotates over AttributionChildScope identities rather than over FairnessRoots makes its decision sequence depend on how a root's demand is subdivided beneath it, which is exactly the prefix inequalities above failing. The installed provider rotates over FairnessRoots; Section 5.2 records that status and its limits.

## 2. Limit classes

| Class | Meaning | Basal effect |
| --- | --- | --- |
| Protocol-shape bound | Canonical parser or wire validity | Invalid input is rejected |
| Provider structural limit | Actual transport, codec, kernel, hardware, or dependency constraint | Provider reports unsupported or unavailable |
| Runtime resource availability | Current memory, handles, sockets, tasks, storage, and work grant | Provider grants a lease or returns typed pressure |
| Optional local policy ceiling | Explicit administrator, Closed, cost, appliance, test, or compatibility restriction | Wrapper may refuse a claim the provider could otherwise grant |

No class may silently stand in for another. In particular, an optional local policy ceiling may never be reported as a protocol-shape bound or a provider structural limit, and a provider structural limit may never be presented as a recommended deployment value. No value in any class originates in this document.

## 3. Field-by-field static policy disposition

Layer: L2 static source disposition. Every row below is a reading of the current source, not an execution result and not an obligation.

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

Layer: L2 static source disposition. This section is the integration half of the boundary in Section 0, established by reading the source rather than by running it. Each row names which owner charges which dimension and where that charge stops being exact. No row states how much capacity exists; that is the provider's half. Unit counts below are structural ownership-domain counts: they are not deployment-capacity recommendations, universal protocol limits, or evidence of exact physical resource quantity.

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

The daemon currently requires the deployment owner to supply every provider dimension explicitly, with no default and no fallback. This is the **accounting-only** case of Section 1.1: the deterministic finite provider respecting a vector the owner wrote. An owner-supplied vector is not host backing — it establishes no `E` and no `B` — and this path must not be described as an isolated or backed provider. A supplied `SocketOrHandle` or `RelayOrProviderAllocation` grant does not by itself make the WebRTC adapter consume that dimension. Those fields are forward-compatible policy inputs and must not be reported as enforced native limits until the corresponding adapter claim exists.

The `transport-lab` feature is the tests case of Section 1.1. It exposes fixture-only grant derivation helpers. They sum production structural claims for the connector profiles and Mesh scopes supplied by a test, then add conservative candidate and remote-SDP claims from explicit fixture bounds. Candidate strings, content, concurrent parsing work, queue records, digest records, provider bookkeeping, remote-SDP parser storage, and remote-description retention are separate components. The helpers select no profile, workload, or production value and are absent from the default V4 API. The TURN control funds four data-only profiles and four Mesh scope records for its two sequential scenarios. At most two are active concurrently. It adds signaling-frame-derived candidate and remote-SDP bounds to one process provider. This proves shared-provider enforcement for that finite test workload. The profile and scope counts it funds are the structural shape of that fixture. Structural counts are not deployment-capacity recommendations, universal protocol limits, or evidence of exact physical resource quantity. It does not claim exact native WebRTC allocation accounting or recommend a deployment grant.

## 5. Pressure and admission

### 5.1 Properties required of any provider

The process provider checks the composite claim before admission. An AttributionChildScope receives no fixed share.

This document requires no pending-demand mechanism. A provider may queue, may retain capacity for a waiting demand, or may implement no retention at all and answer with immediate typed pressure instead. That choice is design latitude, and it is available **only for a claim that does not currently fit**. It is not a licence to refuse a fitting claim: declining to implement retention decides *how* a non-fitting claim is answered, never *whether* a fitting one is admitted. Selected turns, exact-charge reservation, cooperative entry, and drop-cancellation are mechanics of one provider design and are stated in Section 5.2, not here.

**Conditional safety.** If a provider does retain or reserve capacity for a pending demand, then that retention:

- mints no capacity, in that dimension or any other;
- releases, transfers, or invalidates no other owner's lease;
- blocks no surplus beyond what the pending demand itself requires, absent an explicit, named local isolation policy that forbids borrowing;
- creates no admission guarantee against nonreclaimable admitted pressure, ignored retirement, or failed cleanup;
- ends when the demand ends, without a timer and without consuming another owner's capacity.

**Immediate refusal is permitted, and P4 constrains it narrowly.** A provider that implements no retention at all has nothing to check in the conditional clause above. That is not a licence to refuse freely.

Answering with immediate typed pressure rather than pending retention is available **only when the claim does not currently fit.** A claim that does fit must be admitted. P4 work conservation is the binding rule: capacity that is neither live nor reserved for an in-flight admission is borrowable by any scope that can use it, so refusing a fitting claim while such capacity sits idle and unreserved is a P4 violation whether or not the provider retains. "Always refuse" is therefore nonconforming, and the earlier reading that a refuse-only provider trivially conforms was wrong.

Exactly three classes of exception permit refusing a fitting claim. This report recognizes no others:

1. **a proven provider structural limit applies.** An actual transport, codec, kernel, hardware, or dependency constraint makes the operation unsupported or unavailable regardless of capacity — the Provider structural limit class of Section 2. The limit must be proven, not assumed; an unproven claimed limit is a stop condition, not an exception.
2. **an explicit, named local isolation policy or optional local ceiling** forbids the borrow (P5). The refusal names that policy, and removing every optional ceiling removes this exception with it.
3. **accounting unavailable, poisoned, or unable to prove the admission safe.** Where checked arithmetic overflows, a scope's accounting state is poisoned, or the provider otherwise cannot prove the resulting state safe, it refuses. Refusing because safety is unprovable is correct; admitting on unprovable accounting is not, and this exception may never be used to mask an ordinary shortfall.

Each exception is a typed resource result under P7, never an authorization outcome.

Two conditions are deliberately **not** additional classes:

- **Capacity reserved for an in-flight admission.** That capacity is not available to the claim, so the claim does not currently fit. This is the fit condition, not an exception to it.
- **Typed premise loss, meaning a premise below `S(d) + R_flight(d)`.** The degraded state of the contraction model below is an affected-capacity, unprovable-safe-accounting, and degraded-state condition, and it is already covered by class 3 together with the fit condition. It is not a separate third class, and adding one would double-count it. Note that the trigger is the premise falling below committed use, never `E < Gc` or `B < Gc` on its own, and never `O`: an observation alone establishes nothing about fit.

Refusal never implies liveness, a queue, or a deadline, and it remains a typed availability result under P7 rather than an authorization outcome.

**Safe committed-grant contraction.** An earlier revision used one quantity for "host observation or desired capacity". That conflated three different things carrying three different authorities: something merely measured, something the owner decided, and something that actually enforces. Contraction is modeled over five distinct quantities, per resource dimension:

**These symbols are defined by `FORMAL-PROOFS.md` §14.5, and this section summarizes rather than redefines them.** Where this summary and FORMAL appear to differ, **FORMAL governs and the difference is a defect here**. This report keeps no parallel notation glossary; symbols it does not need are simply left to FORMAL.

```text
S    charged sum: live claims plus failed-cleanup-retained claims

Gc   provider-owned committed grant — an accounting commitment
         the absolute value AccountingCapacity starts from
         never proof of containment, and never proof of availability

O    non-authoritative observation or measurement
         optional and inert; carries no authority whatsoever

T    explicit owner-selected contraction target
         a named owner policy decision to shrink toward a value

E    enforceable isolation envelope or ceiling
         containment only: the process is stopped at E from outside
         it reserves nothing and guarantees nothing

B    actual reserved or owned guarantee
         capacity held for this process, not merely permitted to it
```

Their authorities differ and must not be interchanged:

- **`O` is optional and inert.** An observation or measurement changes no grant, no admission result, and no contraction state, and it **never automatically sets anything**. It is not required to exist at all: a deployment with no observation whatsoever is fully conforming. `O` creates no provider class — observing a number does not make a provider isolated or backed.
- **`T` is set by named owner policy.** A `T` arises in exactly one of two ways: **set directly** by a named owner policy, or **derived** by a named owner policy that considers `O` among its inputs. Both are named policy decisions. What may not happen is `O` becoming a `T` on its own. `T < Gc` *requests* contraction; `Gc` follows `T` downward only after owner release has lowered committed use, and never below `S(d) + R_flight(d)`.
- **P4 fit is computed from absolute capacity and independently proved premises**, per dimension:

**The definitions below are `FORMAL-PROOFS.md` §14.5's, restated for readability only.** FORMAL is authoritative for their exact form; if this restatement and FORMAL diverge in any respect, FORMAL is correct and this text is the defect.

Capacity is stated as an **absolute** quantity per dimension `d`, and fit is the headroom remaining within it:

```text
AccountingCapacity(d)
    the absolute Gc(d), narrowed only by an explicit P5 restriction
    naming the exact subject
    an accounting commitment, not containment and not availability

EffectiveCapacity(d)
    AccountingCapacity(d), intersected with E where E is proved
    and with B where B is proved, per dimension and independently

EffectiveFit(d)
    max(0, EffectiveCapacity(d) - S(d) - R_flight(d))

admission
    q(d) <= EffectiveFit(d)
```

  A claim `q` fits in a dimension exactly when `q <= EffectiveFit` there. **A composite claim fits only when it fits in every dimension it names**; headroom in one dimension never compensates for its absence in another.

  Three details of that shape are load-bearing, and FORMAL states why. `S(d)` and `R_flight(d)` are subtracted **last**, because `E` and `B` are absolute substrate bounds — intersecting them with a figure that already had charges deducted would compare a residual against an absolute and silently understate the bound. `R_flight(d)` is subtracted at all so that **concurrent admissions cannot each read the same headroom as free**; it is the **aggregate** exact capacity reserved for **all** admissions currently in flight, and zero when none is. It is a distinct symbol from the global `R`, which FORMAL uses for the multiset of live and failed-cleanup-retained lease claims; the two are never interchanged. The `max(0, ...)` clamp is not cosmetic: the inner expression can go negative when a proved premise falls below existing committed use, and the clamp makes the fit test refuse rather than yielding a negative bound that arithmetic elsewhere might treat as slack.

  The two intersections apply independently, since an `E` bound is not implied by a proved `B` and a `B` bound is not implied by a proved `E`. Across the four combinations:

```text
E?    B?    EffectiveCapacity(d)
no    no    = AccountingCapacity(d)
yes   no    = AccountingCapacity(d) intersect E
no    yes   = AccountingCapacity(d) intersect B
yes   yes   = AccountingCapacity(d) intersect E intersect B
```

  That `EffectiveCapacity` equals `AccountingCapacity` in the first row is not a statement that the dimension is well-founded. It says only that no substrate premise narrows the accounting commitment there, because none was proved.

**The P5 restriction vocabulary is closed.** An explicit P5 restriction narrowing `AccountingCapacity` is exactly one of the three forms `FORMAL-PROOFS.md` §14.5 enumerates:

```text
named local isolation domain
    an explicitly named domain confining a scope to part of the
    dimension

named partition or reserved share
    an explicitly named division of the dimension, or a quantity
    withheld from general admission and held for a named scope

named optional local ceiling or cost boundary
    an explicitly named upper bound below Gc, whether selected for
    policy, appliance, deployment, or cost reasons
```

  Each is explicit, named, and recorded. **Nothing outside this list narrows `AccountingCapacity`** — not an observation, a target, a measurement, a generic owner preference, a workload calibration, an anticipated future demand, a rate-smoothing behavior, an inferred restriction, or an undeclared product policy. An undeclared narrowing is an arbitrary refusal, which P4 forbids, and calling it a policy does not make it a P5 restriction.

  **Neither `O` nor `T` is ever a fit input**, in either definition, under any combination. An observation is inert and a contraction target is an owner decision about `Gc`; neither participates in deciding whether a claim fits. A provider applies only the bounds it has actually proved for that dimension: it may not bound against an `E` it does not have, and may not bound against a `B` it cannot prove.

The invariants:

- **`S <= Gc` always, and the contraction floor is `S(d) + R_flight(d)`.** `Gc(d)` is never installed or reduced below `S(d) + R_flight(d)`. The floor is not `S` alone: contracting to `S` would strand capacity already reserved for an admission in flight, so the floor sits at or above `S(d)` and covers every in-flight reservation. This is a bound the provider may not cross, not a target to approach.
- **Premise loss recomputes; it does not automatically freeze.** When a proved `E` or `B` falls, the provider recomputes `EffectiveCapacity(d)` and compares it against what is already committed:

```text
premise >= S(d) + R_flight(d)
    residual headroom remains and is usable. EffectiveFit(d) is
    recomputed against the reduced premise and stays non-negative, so
    ordinary admission continues within it.
    This condition alone requires no loss report

premise <  S(d) + R_flight(d)
    the premise is now below committed use. The provider reports a
    typed containment-loss, backing-loss, or external-overcommitment
    result, and admits no new work that would conflict with the
    shortfall in that dimension
```

  **The first regime matters as much as the second.** A premise that falls but still covers committed use has created no shortfall, and **requires no loss report at all**. Treating every fall as an emergency would refuse work the provider can honor while reporting a loss that has not occurred.

  **The threshold is `S(d) + R_flight(d)`, never `Gc`.** A provider must not report loss, or stop admitting, merely because `E < Gc` or `B < Gc`. That compares a premise against the accounting commitment rather than against what is actually committed. A premise may fall well below `Gc` and still leave genuine headroom above `S + R_flight`; withholding that headroom would refuse capacity that is demonstrably available — a P4 work-conservation violation, and an undeclared narrowing outside the closed P5 vocabulary.

  **In both regimes every charge in `S(d)` and every reservation in `R_flight(d)` is retained.** Nothing is released, revoked, reduced, or written off, and no release is inferred or forced: a premise falling is not a release. `Gc` is not lowered below `S(d) + R_flight(d)`. The provider may request retirement only from exact owners whose contracts declare their leases reclaimable, and releases nothing itself. Above all it does not pretend the capacity exists, and **no part of a shortfall is reported as available**. Containment loss, backing loss, and external overcommitment are reported distinctly, because losing containment, losing a guarantee, and being overcommitted from outside are different facts.
- **No conflicting admission while degraded.** Nothing is admitted that draws on the shortfall.
- **Requests go only to exact reclaimable owners.** Degradation may prompt retirement requests, only to the exact owner of a lease its own contract declares reclaimable. The request is sticky, carries no timer, and alters no claim.
- **All unreleased charges stay retained.** Contraction releases, revokes, invalidates, shrinks, and forges nothing (P2). Owner Drop after cleanup, or explicit failed-cleanup retention, remains the only path out of a charge.
- **`Gc` contracts only after releases.** Contraction is an outcome of owner-driven release, never a cause of it.

**If an envelope or a guarantee cannot be proved, that is the open Slice C question.** A provider that cannot establish `E` or `B` has not thereby failed — it is accounting-only, it may assert neither containment nor reservation, and the dimension remains an unproved-backing residual. Section 4 keeps that question open, and nothing in this section closes it.

**Slice C handoff, recorded here as a future requirement and not implemented.** The mapping proof obligations are stated by `FORMAL-PROOFS.md`, which governs their exact content and count; this is a summary of them and adds none of its own. Every `Gc <= E` or `Gc <= B` claim requires a mapping between the MyOwnMesh `ResourceClaim` quantity and the substrate quantity actually contained or reserved. That mapping must satisfy the three original properties **and five further obligations**:

```text
dimension-specific   established for that dimension, not inferred
                     from another
unit-correct         relating charged unit to substrate unit with no
                     silent conversion or reinterpretation
monotone             a larger charged quantity never maps to a smaller
                     substrate quantity
coverage             every charged quantity in the dimension lies in
                     the mapping's domain; a partially mapped dimension
                     is not a mapped dimension
composition          the mapping respects aggregation, with no
                     cancellation that conceals a charge
subject alignment    the contained or reserved subject is exactly the
                     one being charged — same principal, process, and
                     boundary, neither broader nor narrower
lifetime and loss    the mapping holds for the whole lifetime of the
                     charge, and its loss is detectable and reportable
                     rather than silent
B exclusivity        reserved capacity is exclusive to that subject;
                     capacity another party may consume is not
                     reserved, and a shared pool is not B
```

  The first three remain load-bearing for the reasons already given: *dimension-specific* because no single mapping serves every class; *unit-correct* because a claim counted in one unit cannot be compared against a bound expressed in another; *monotone* because a mapping that does not preserve ordering would let a larger claim appear to fit where a smaller one did not. **`B exclusivity` applies to reservation only** — containment is inherently shareable, so an `E` may bound several subjects at once, whereas a reservation that is double-promised was never a reservation.

Where no such mapping exists for a dimension, that dimension **stays accounting-only and is recorded as an explicit residual**. It does not become `E` or `B` by assertion, by proximity to a dimension that has one, or by the existence of a number.

The named dimensions requiring individual treatment are the `ResourceClass` variants: `AccountedMemoryBytes`, `QueuedBytes`, `SocketOrHandle`, `NativeTransportObject`, `WorkerOrTask`, `CallbackOrScheduledWork`, `StorageBytes`, `StorageObject`, `RelayOrProviderAllocation`, `ParsingOrCpuWork`, and `OpaqueDependencyResidual`. Each needs its own mapping or its own residual disposition; none inherits another's.

**`OpaqueDependencyResidual` is a specific limitation, not merely another row.** It is a named ownership domain rather than a measured substrate quantity, so it does not become `E` or `B` merely because it carries a number. A count of opaque residual units is not bytes, handles, native objects, or any substrate quantity that could be contained or reserved, and no unit-correct mapping to a substrate bound can be constructed from it as it stands. It is expected to remain accounting-only and residual unless Slice C replaces it with something measurable.

This is a textual handoff. No mapping is defined, proposed, or implemented here, and Slice C is not started.

Contraction is therefore never a reclamation mechanism. It restricts future admission, it resolves as owners release, and any interval of typed containment loss, backing loss, or external overcommitment is disclosed rather than smoothed.

**Every typed report above is bounded by liveness and observability.** A typed result can only be produced while the process is **alive** and the condition is **observable to it**. That bound is not a detail; it is the limit of what any claim in this section means.

- An out-of-memory kill or other fail-stop **produces no typed result.** The process is gone before it can classify what happened. There is no typed envelope-shortfall or backing-loss result for the case where the environment simply terminates the process.
- Process death **destroys live in-process capabilities.** Leases, pending demands, and in-memory ownership records cease to exist rather than being released, retired, or reported, and no cleanup path runs for them.
- Recovery is **ordinary restart**, with no special resource-model path. A restarted process reconstructs no leases, inherits no charges, and replays no prior resource state; it begins from an installed grant exactly as a first start does.

**What happens outside the process is not settled by this model, and this report does not claim it is.** The statements above are scoped to in-process capabilities. They deliberately do **not** assert that every external reservation, provider allocation, retained charge, or cleanup obligation ceases when the process dies. A substrate-owned resource — a TURN or relay allocation held by a server, an assigned hard domain, a provider-side allocation, an OS or filesystem object — may well **survive** process death, and its disposition is determined by whoever owns it, not by anything in this document.

That leaves genuine uncertainty at the boundary, and naming it is more honest than resolving it by assertion. A restarted process does not know what the previous process still holds somewhere else. **Reconciling substrate-owned resources after process death is an open concern**, not something the resource model discharges and not something any control here covers. Assuming such resources vanish with the process would be the convenient answer and is not a supported one.

So the honest scope of the typed states above is: conditions a live process can see and classify, over capabilities it holds in memory. A condition that kills the process is outside them, what survives outside the process is outside them, and no control, report, or CI result may be read as covering either.

**Hostile ingress is a separate obligation.** Progress and backpressure under hostile ingress are their own obligation and are not supplied by P6, by any fairness property, or by the provider alone. P6 governs how a schedule treats subdivision beneath a root; it says nothing about an attacker driving unbounded ingress at a listener.

The obligation is that ingress owners bound admission before work is created, apply backpressure or typed refusal at the ingress boundary, and keep unrelated work progressing while a hostile source is active. Satisfying every property in this section leaves that obligation entirely open. Signaling bridge queues, fanout, and duplicate hashing before connector entry remain an explicit hostile-ingress residual outside Arc 03, and nothing in this report may be cited as bounding them.

Connector cleanup work is reserved with the connector before pressure, so native close does not need a new speculative permit after failure. When pressure selects a reclaimable speculative connector, the provider requests retirement through its opaque target and the connector's existing close owner performs cleanup. The provider never reuses the charge until the exact lease is dropped. If cleanup fails, the failed owner keeps that claim charged and later admission receives typed pressure. Resource refusal is an availability result and never an Open or Closed authorization denial.

One large claim may consume more capacity than many small claims. Tests must compare resource quantities, not object counts.

Connector-local scheduling metadata is not capacity. A connector-local scheduling weight or quantum orders work inside its own owner. It reserves no provider capacity, guarantees no cross-scope admission, and multiplying it multiplies no grant. This is a claim about capacity authority and does not discharge P6 non-amplification.

Partition non-amplification, also called subdivision monotonicity (P6), is a separate obligation, stated in Section 1.2 over a fixed input workload with releases derived: subdividing one root's demand across AttributionChildScopes beneath it must, at every decision prefix, give that root no greater cumulative selections and no greater cumulative admitted quantity than the unsubdivided baseline, and must delay no competitor's baseline selection. The installed provider's scheduling is root-keyed and its controls are landed in the working tree, with no execution result claimed here; see Sections 5.2 and 7.1 for their scope and limits.

### 5.2 Concrete deterministic-provider policy

Layer: L2 static source disposition, established by reading the provider source. No bullet below is an execution result.

The installed deterministic finite provider does retain capacity for a pending demand, so Section 5.1's conditional safety clause applies to it with something to check. Its retention mechanics are:

- outside a selected pending turn, AttributionChildScopes may borrow all currently unused capacity;
- during a turn, the selected demand's exact charge is reserved, and surplus remains borrowable including surplus in an overlapping dimension;
- a demand that cannot fit enters a provider-owned turn only through the cooperative API;
- dropping the demand cancels the turn without releasing another owner's capacity.

The turn is move-only and scoped to overlapping resource dimensions. Arbitration is ordered by `Cleanup`, `Admitted`, then `Speculative`, and rotated across equal-authority FairnessRoots.

All of the above is that provider's arbitration policy. It is verified against that provider and is not required of a conforming replacement. A provider that never retains pending-demand capacity has no analogue of any bullet in this list and is not thereby nonconforming.

The authority-class taxonomy is part of the provider port and stays architectural. The order in which those classes are served is provider policy. A conforming provider must still satisfy Section 5.1 and must still never release an owner's lease, but it may arbitrate its own way.

**Root-keyed scheduling in the installed provider.** The previously disclosed P6 nonconformance is resolved in the working tree. Equal-authority rotation and reclamation are now keyed to the FairnessRoot, not to AttributionChildScope identities: the provider's demand cursor is a per-authority-class turn key over roots, and its reclaim cursor holds a `FairnessRoot`. Subdividing one fixed root's demand across more child scopes beneath it creates no additional turn key — every scope beneath a root maps to that root's turn, and the cursor advances a whole root at a time — so the disclosed cursor counterexample is removed. That is a fact about the rotation key. It is not a general claim that the Section 1.2 prefix inequalities hold over every workload; what was actually compared is stated in the control-status note in Section 7.1.

**Roots are provider-private, and children inherit.** A root is minted only where a scope is created with no parent; the caller receives an ordinary `ResourceScope` and never supplies, names, observes, or rebinds the root value. Every ordinary child arrives with a parent and inherits that root verbatim. Public child-scope creation therefore cannot name, mint, or rebind a root, which is what makes the root non-mintable by the claimant it attributes.

**The production consequence, stated exactly.** Production currently has **one scheduling root**. Beneath it, **child subdivision cannot multiply turns** — every scope beneath a root maps to that root's turn, and the cursor advances a whole root at a time. That is the whole of what root-keying buys production today.

**Cross-root production fairness is not claimed.** With a single scheduling root there is no cross-root arbitration in production to be fair or unfair, so no such claim is made or implied. Additional trusted-root minting is `#[cfg(test)]` and crate-local, and the cross-root exercises run only under test.

**Future trusted-root assignment belongs to its owning provider or ingress arc**, not to Arc 03 and not to this report. No deployment-level mapping from local subjects to distinct roots exists, none is designed here, and none may be reported as shipped. This report adds no production root taxonomy.

The correction deferred to Slice D under review 4865297956 §8 — binding a pending demand to a FairnessRoot rather than to a mintable scope identity — is what the working tree now implements. That change is fairness-only and alters none of the conservation, exact-release, no-minting, or cleanup-ownership dispositions recorded elsewhere in this report. It also closes nothing else: the provider-class gap in Section 1.1 stands, no `E` or `B` is proved in any dimension, and the residual-enforcement question in Section 4 remains open.

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

Layer note: the obligations below are L1. A control **passing** is L3, and an L3 result exists only against a named commit in PR CI. This report lists what must be proven and records no passing result. A bullet appearing here is never evidence that it holds.

- no basal `MAX_MESHES`, `MAX_PEERS`, `MAX_ATTEMPTS`, or `MAX_FLOWS`;
- no hidden default cardinality, `unlimited` sentinel, or default grant exists;
- one more object is admitted whenever its claim fits the shared grant and provider bookkeeping;
- many small peers or flows coexist while resources remain;
- one large claim may cost more than many small claims, so no object count implies admissibility;
- more Mesh scopes do not multiply the process grant, and no accounting or observation path mints capacity;
- exact lease release restores exactly that capacity;
- concurrently held charges never exceed the grant in any dimension;
- **conditional, pending-demand retention:** if a provider retains or reserves capacity for a pending demand, that retention mints no capacity, releases or invalidates no other owner's lease, and blocks no surplus beyond what that demand itself requires absent an explicit, named local isolation policy. A provider that never retains has nothing to check here — but see the next bullet, which binds it regardless;
- **P4-constrained immediate refusal:** answering with immediate typed pressure rather than pending retention is available only when the claim does not currently fit; a fitting claim must be admitted, subject only to the three exception classes in Section 5.1 — (1) a proven provider structural limit applies, (2) an explicit local isolation policy or optional ceiling refuses it, (3) provider accounting is unavailable, poisoned, or cannot prove safety. Capacity reserved for an in-flight admission is already subtracted as `R_flight(d)`, so it means the claim does not currently fit and is not a separate exception; typed containment loss, backing loss, or external overcommitment — triggered by a premise falling below `S(d) + R_flight(d)`, never by `E < Gc` or `B < Gc` alone — is covered by class 3 with the fit condition and is not a separate class. A refuse-only provider is nonconforming, not trivially conforming;
- **safe committed-grant contraction:** with `S` the committed charge, `R_flight(d)` the aggregate in-flight admission reservation, `Gc` the provider-owned committed grant, `O` an optional inert observation, `T` an explicit owner-selected contraction target, `E` an enforceable isolation envelope providing containment only, and `B` an actual reserved or owned guarantee — `S <= Gc` holds always and `Gc(d)` is never set below `S(d) + R_flight(d)`, so contraction cannot strand an in-flight reservation; `O` sets nothing automatically and creates no provider class; a `T` arises only by being set directly by a named owner policy or derived by a named owner policy that considers `O`; `T < Gc` requests gradual contraction and `Gc` follows only after owner release has lowered committed use;
- **premise loss has two regimes keyed on `S(d) + R_flight(d)`, never on `Gc`:** where the fallen premise still stands at or above `S(d) + R_flight(d)`, residual headroom remains usable, `EffectiveFit(d)` is recomputed against the reduced premise, and **no loss report is required**; only where the premise falls below committed use does the provider report a typed containment-loss, backing-loss, or external-overcommitment result and refuse conflicting new work. In both regimes every charge and every reservation is retained, nothing is released or written off, and no part of a shortfall is reported as available;
- **each premise is proved separately, per dimension:** `E` and `B` are orthogonal and neither implies the other. A provider proves containment and reservation independently, may hold one, both, or neither in any given dimension, and claims only what it has proved. "Backed" is not a stronger "isolated". An owner-supplied grant vector is **not** host backing and establishes neither. The installed provider proves neither and is **accounting-only**;
- **capacity is absolute, fit is its residual, and neither takes `O` or `T`:** `AccountingCapacity` is the absolute committed grant in a dimension narrowed only by an explicit P5 restriction from FORMAL's closed vocabulary; `EffectiveCapacity` intersects that with `E` and with `B` only where each is proved in that dimension, and remains absolute; `EffectiveFit(d)` is `max(0, EffectiveCapacity(d) - S(d) - R_flight(d))`. A claim fits when `q(d) <= EffectiveFit(d)`, and a composite claim fits only when it fits in every dimension it names. `O` and `T` participate nowhere in the computation;
- **`Gc` is an accounting commitment:** it is never presented as proof of containment or of availability, and no provider presents unproved containment or backing as established;
- **admission is not a success guarantee:** a successful fit does not guarantee allocator, kernel, runtime, transport, external-relay, or hardware success, and those failures remain application-visible;
- **typed reporting is bounded by liveness and observability:** every typed state above is producible only while the process is alive and the condition observable to it. An OOM kill or other fail-stop produces no typed result, destroys live in-process capabilities, and is recovered by ordinary restart carrying no resource state across. This says nothing about substrate-owned resources: an external reservation, provider allocation, or OS-owned object may survive process death, and reconciling it is an open concern no control here covers;
- refusal names a resource dimension rather than an object count;
- refusal is an availability result and never an Open or Closed authorization denial;
- a nonwaiting acquisition returns typed pressure without requesting another owner's cleanup;
- **conditional, cooperative retirement:** if a provider implements a cooperative retirement path, it wakes the exact owner of a lease its contract declares reclaimable and does not release, transfer, or invalidate that lease;
- failed cleanup retains the charge, and no provider reuses that charge until the exact lease is dropped;
- connector cleanup can proceed from its pre-reserved claim even after the shared grant is full;
- a connector-local scheduling weight reserves no provider capacity and multiplying it multiplies no grant (connector-local scheduling metadata is not capacity; this does not discharge P6 non-amplification below);
- **P6 partition non-amplification (subdivision monotonicity)** — controls landed in the working tree, with no execution result claimed here; see the control-status note below for scope and limits. The obligation stands as stated: over one fixed *input workload* — finite root set, initial provider state including `Gc`, arrival events, per-demand claim, authority and reclaimability, and one deterministic owner response rule, with releases derived rather than fixed — subdividing root `A`'s demand across additional AttributionChildScopes beneath `A` must satisfy, **at every decision prefix `k`**: cumulative selections of `A` no greater than baseline, cumulative admitted quantity of `A` no greater than baseline **in every resource dimension `d`**, and every baseline selection of every competitor `B != A` occurring at a decision index no later than its baseline index, with a selection that never occurs taking index infinity. The control must not assert total outcome or share equality, must not fail a subdivision that leaves `A` worse off or a competitor better off, and must not substitute a proof that each scope is eventually served;
- **P6 first control, topology-normalized over a bounded prefix:** the first such control uses the **identical pre-existing root and child-scope topology** and **identical bookkeeping claims** in both runs, with **stable `DemandId`s**, so that the only difference is the `DemandId`-to-`AttributionChildScope` mapping. It drives both runs from the deterministic clock-free environment described in Section 1.2, interleaving exogenous arrivals with derived owner actions and permitting terminal stuttering. It evaluates a **bounded decision prefix that starts identical in both runs** and during which **none of the compared newly admitted work releases** — unrelated releases elsewhere in the workload need not be prohibited, and forbidding them would over-constrain the control for no benefit. Normalizing the topology is what removes scope-creation cost from the comparison; it is not a claim that scopes are free, unbounded, or always creatable, and the control must not be read as promising unlimited scopes;
- **P6 nonclaims are not controls:** no control asserts that a FairnessRoot corresponds to a real-world claimant, and none provides Sybil resistance over the number of roots. These are unsupported claims rather than pending work, and no future P6 correction supplies them;
- **hostile-ingress progress and backpressure is a separate obligation:** ingress owners bound admission before work is created, apply backpressure or typed refusal at the ingress boundary, and keep unrelated work progressing while a hostile source is active. No property control in this list discharges it, and it remains open;
- unused capacity is borrowable unless an explicit, named local isolation policy forbids it;
- no valid slow lease is expired or reclaimed merely by elapsed time;
- slow work retains its finite lease without time-derived expiry;
- storage-backed work consumes storage leases;
- an optional local ceiling can deliberately restrict a deployment, and removing every ceiling still leaves a conforming system;
- the fairness claim is limited to reclaimable speculative conflicts whose owner completes cleanup, and does not cover nonreclaimable admitted pressure.

**Control status: landed in the working tree, not yet executed.**

`construction_a_against_live_provider_does_not_amplify` runs a baseline and a subdivided mapping against the live provider through `evaluate_live_non_amplification`, over `State.decision_log: Vec<ProviderDecision>` read via `decision_log_for_test()`. `live_oracle_rejects_scope_keyed_selection` drives the *same* live provider through the *same* oracle with `set_scope_keyed_selection_for_test` restoring the superseded scope-keyed rule, and requires the oracle to reject — a control that cannot be made to fail proves nothing, so the negative fixture is what gives a positive result weight.

**Withdrawal history, kept deliberately.** An earlier revision of this report called the *previous* selection-only test the formal Construction A control. **That was an overclaim and was withdrawn.** The correction below is what replaced it, and the history is retained so the claim cannot quietly reappear.

**What the trace is, stated exactly.** `decision_log` is an ordered trace of **cooperative-admission dispositions on the non-failing path**: the outcomes reachable through `acquire_cooperatively` and `create_scope_and_acquire_cooperatively`, the arbitration that resolves the demands they create, and **owner** cancellation through `cancel_demand`. Within that scope it is complete — `PendingAccepted`, `PendingRefused`, `ImmediateGrant`, `ArbitrationGrant`, `TerminalPressure`, and owner `Cancelled` all appear, so a control cannot be blind to immediate admission or to refusals and terminal outcomes.

Two cancellation paths are **specifically outside** it and are not recorded: fail-closed **invariant cancellation** inside `arbitrate`, where an impossible arithmetic or commit failure resolves the demand `Cancelled` and poisons the provider; and **teardown cancellation** in `release_scope`, where retiring a scope cancels any demand it still owns. Both set the outcome without appending, deliberately — neither is part of the controlled execution, and a poisoned or torn-down provider is not producing a trace anyone should reason about. The trace also does not record non-cooperative admission through `acquire` or `acquire_reclaimable_now`, scope creation or release, reclaim requests, or pre-admission validation failures such as an unknown scope, a mismatched reclaim target, a poisoned domain, or a claim that can never fit.

Stating this narrowly is the point: claiming completeness over paths the trace does not record would replace the selection-only overclaim with a broader one.

**This document claims no execution result for either disposition.** Both are landed in the working tree. Citing them as evidence requires exact-state local verification and exact-head hosted evidence, recorded externally — not here. Nothing in this report is exact-head or hosted CI, and no pass is claimed here.

**Two defects are recorded. Their statuses differ and must not be merged.**

**Defect 1 — requester-root propagation. Disposition landed in the working tree.** A pending `NewChild` demand is owned and stored under the existing parent scope, but `PendingDemand::lease_scope_id` returns the prospective child id. `arbitrate` passed that id into `select_reclaim_victims`, and because the child was not yet installed, `root_of(state, prospective_child_id)` returned `None`. `NewChild` requests therefore lost requester-root-last victim sequencing and could route around same-root treatment.

*Disposition, verified present in the working tree:* `requester_root` is derived from the exact existing pending-owner scope and carried separately through arbitration; `lease_scope_id` remains the prospective child solely for exact lease ownership and diagnostics; victim scope, reservation, and target remain exact.

The selector parameter is **non-optional and fails closed**: `select_reclaim_victims` takes `requester_root: FairnessRoot`, not an `Option`. Every selected pending owner has a scope record and therefore a root, so an unresolvable requester is an impossible state rather than a refusal; if `arbitrate` cannot resolve the pending owner's root it **poisons the provider and returns** instead of reclaiming. Accepting an absent root would have kept the silent path open — reclaiming without attribution is precisely the route-around this rule exists to prevent. Working-tree evidence, not exact-head and not hosted CI.

**Defect 2 — proof-control fidelity. Disposition landed in the working tree; no execution result claimed here.** The superseded trace observed only arbitration grants, with admitted quantity **assumed rather than observed**, and no ordering for refusals or terminal outcomes. Concretely, as it stood:

- the selection record was appended in exactly one place, the arbitration grant path, so **immediate grants never entered it at all**; the fixture panicked if an immediate grant occurred, which was a guard against that blindness rather than evidence there was none;
- the admitted quantity carried in each decision was the test's own unit constant, **not a value the provider reported**, so the per-dimension comparison was over an assumed quantity — the core of the overclaim;
- refusals were counted in aggregate totals but were **not ordered** into the trace, and terminal pressure and cancellation were not recorded at all;
- logical `DemandId`s were **reconstructed positionally after the fact** from a per-scope queue rather than bound at issue. That strand was not merely weak but **unsound**: the baseline refuses two demands from the same child, so a scope-keyed map overwrote and attributed both to the last id.

The oracle's prefix horizon was therefore the **selection sequence**, not FORMAL's ordered disposition sequence — refusals, pending admissions, immediate grants, and pressure or cancellation can move a competitor's position without changing selection-only indices.

*Disposition, verified present in the working tree:* logical ids bind at issue time rather than being reconstructed afterwards from scope and ordering, and **the binding mechanism is variant-specific**. `PendingAccepted`, `ArbitrationGrant`, `TerminalPressure`, and `Cancelled` carry the provider-minted `demand_key` where applicable; `PendingRefused` and `ImmediateGrant` do not, and are bound by **exact per-call decision-log index** instead. The ordered cooperative-admission disposition trace described above replaces the selection record, and the oracle compares over the full disposition prefix with stuttering, all dimensions, and all competitors, with the scope-keyed negative fixture retained.

*On the recorded quantities, which are also variant-specific.* It is **not** the case that each decision records `requested` alongside `charged`:

```text
requested only   PendingAccepted, PendingRefused
requested + charged   ImmediateGrant, ArbitrationGrant
neither claim quantity   TerminalPressure, Cancelled
```

Only the grant variants carry `charged`. The P6 oracle accumulates provider-recorded **`requested`** claims **from grant events only**; `charged` is diagnostic and must never be accumulated in its place. That distinction is load-bearing and is easy to lose: `FORMAL-PROOFS.md` §14.5e defines `cum_admitted` over the demand's exact claim, whereas the internal charge is inflated by bookkeeping — a reservation charge adds a unit in `OpaqueDependencyResidual`, and a new-child transaction adds another. An oracle accumulating charges would accumulate a quantity the model does not define, and its per-dimension comparison would not be the P6 comparison. What makes this a genuine fix to the original overclaim is that `requested` is **observed from provider state** rather than assumed by the test; what changed is *which* provider-recorded quantity is accumulated, not whether it is observed.

**On execution.** This report **claims no execution result** for the corrected controls. Any citation of them requires exact-state local verification and exact-head hosted evidence recorded externally. The earlier pass of the superseded selection-only test establishes nothing about the corrected ones, and unqualified "passing" would be an overclaim of exactly the kind these corrections remove.

**On the negative fixture.** It drives the *same* live provider through the *same* oracle with production selection reverted to scope keying. It is not a separate model, and that is the only reason a positive result carries any weight.

Four limits apply to what these controls can show, all load-bearing:

- **Bounded, not a whole-model proof.** What the implementation removes is the concrete per-scope amplification mechanism; what the control exercises is one workload compared over the cooperative-admission disposition prefix, with a non-vacuous negative fixture proving the oracle can fail. Neither is a mechanized proof over every possible P6 workload. The canonical property in Section 1.2 remains the standing obligation, and a bounded conformance result must never be promoted into a whole-model proof.
- **Scoped to cooperative admission.** The trace is complete for cooperative-admission dispositions and no wider, so the control says nothing about `acquire`, `acquire_reclaimable_now`, scope creation or release, reclaim requests, or pre-admission validation failures.
- **Working-tree scope only.** These controls are landed in the working tree, and this report records no execution result for them. They are not exact-head evidence and not hosted CI; citation requires exact-state local verification and exact-head hosted evidence recorded externally, the same distinction applied to `7e2ba9e` and `6a22911`.
- **The control's `DemandId`s are test-side.** They are logical ids bound at issue time to the provider-minted `demand_key` and per-call log index. They are not caller-supplied provider identifiers, the provider exposes no such identifier, and this is not evidence that any public API carries demand identity.

What remains open is unchanged and is not discharged by this control: no `E` and no `B` are proved in any dimension, the provider remains accounting-only, the Slice C mapping obligations are untouched, and hostile-ingress progress and backpressure remain a separate obligation that no fairness result addresses.

This is distinct from the Slice C residual-enforcement question in Section 4. Slice D concerns whose turn is next among charges the provider already accounts. Slice C concerns dimensions the integration does not charge at all. Neither closes the other.

### 7.2 Concrete deterministic-provider controls

These are verified against the installed deterministic finite provider. A conforming replacement changes what is verified here without reopening Section 7.1.

- one move-only pending demand exists per FairnessRoot;
- a selected pending demand reserves its exact charge while leaving surplus capacity borrowable, including surplus in an overlapping dimension;
- plain scope bookkeeping cannot consume the charge reserved for that demand;
- a demand that cannot fit enters the turn only through the cooperative API, and dropping it cancels the turn without releasing another owner's capacity;
- a released speculative claim lets the selected demand retry;
- a pending demand selects structural authority before equal-class per-root rotation;
- reclaim requests are published only after the provider proves the selected victim set can satisfy the deficit;
- the selected requester's scope cannot reacquire capacity ahead of its own turn;
- arbitration reads no clock, entropy, or host fact. **The determinism claim is narrow.** It holds only over a fixed set of already-issued `ResourceScopeId`s, an identical starting provider state, and an identically ordered sequence of operations: replaying that sequence yields identical admission outcomes. It is **not** a claim that two process runs agree: scope identities are allocation addresses issued per run, an address may be reused once its scope drops, and an identity is unique only among live scopes rather than over the life of the process, so no caller, control, or diagnostic may treat one as stable, meaningfully ordered, or comparable across time. It is **not** a claim about concurrent operations whose arrival order differs, because order is the input being fixed; and it is **not** reproducibility of the process, of timing, or of any measurement in Section 8;
- the provider derives its capacity from one explicit finite grant and computes none of it.

The accepted lifecycle, cleanup, malformed-candidate, restart, direct WebRTC, TURN-selected, compiler-boundary, and compatibility controls remain required.

## 8. Performance and opaque-resource characterization

This section is L4 and only L4. It is performance and opaque-resource characterization, not correctness evidence. An L3 correctness result lives in the Section 7 control lists and PR CI at a named commit; nothing here substitutes for one, and a good measurement never means a control passed.

**Characterization is required.** Every arc that touches a resource path must produce it, and omitting it is a defect. Measurement is how opaque residuals in Section 4 are discovered at all — an unmeasured residual is invisible rather than absent.

**Characterization is never capacity.** Being required does not let an observation set, justify, or imply a grant, ceiling, budget, or admissible-object count. The requirement to measure and the prohibition on deriving grants are both in force at once, and neither weakens the other.

Measurements remain useful for performance characterization, provider-cost estimation, regression detection, scheduler validation, opaque-allocation discovery, and choosing optional deployment policy. They do not define universal correctness or product cardinality.

For every run, retain the exact commit, platform and target, input workload, raw logs, failures, CPU and RSS observations, queue occupancy, service delay, candidate distribution, close result, and every sample. Do not infer a production ceiling from those observations.

A measurement never becomes a grant by being recorded. Crossing from the integration side of Section 0 to the provider side is an explicit owner decision made against a named provider, with the measurement as evidence and not as the value. This report proposes no such crossing.
