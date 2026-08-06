# Resource admission and observation boundary

## Purpose

This module contains two separate mechanisms:

- `provider` grants finite resource leases and may refuse work;
- the accountant in `resource/mod.rs` records caller-reported use and grants no authority.

A provider lease is admission evidence for the exact resource claim it carries. An observation lease is measurement evidence only. Neither proves identity, mesh authority, endpoint authentication, or application permission.

## Admission provider

`ResourceProviderPort` is the authority-bearing process entry point. The process owner installs one finite provider grant. Mesh, attempt, candidate, callback, cleanup, and real-time owners receive scopes or leases over that same grant.

The port fixes properties, not an arbitration algorithm. Any provider installed behind it must hold:

- creating or cloning a scope creates no capacity, and no accounting or observation path mints any;
- concurrently held charges never exceed the grant in any dimension, and exact release restores exactly that capacity;
- no basal weights, quotas, reserved shares, or partitions exist;
- unused capacity is borrowable unless an explicit local isolation policy forbids it. Such a policy is explicit, named, and recorded, and is never derived from a transient observation `O`;
- arbitration distributes existing capacity only; it never releases, revokes, replaces, or reuses another owner's live claim;
- arbitration attributes a demand to a FairnessRoot: a trusted local process or ingress scheduling attribution, assigned by the local process and never minted, chosen, or supplied by the claimant it attributes. A FairnessRoot is never a Device ID, Mesh Context, durable identity, endpoint identity, authentication or authorization root or capability, or wire-visible value, and carries no authority. The root is not those values, which does not prevent the local owner from using facts it has itself verified or authenticated as inputs when it assigns one. An AttributionChildScope refines accounting beneath exactly one FairnessRoot;
- P6 partition non-amplification, also called subdivision monotonicity. What is held fixed is the input workload, not a trace of outcomes: a finite set of FairnessRoots, one initial provider state including the committed grant `Gc` in every dimension, one identical finite sequence of demand arrivals, each arrival's exact claim by dimension, authority class, and reclaimability under its owner contract, and one deterministic owner response rule fixed in advance. Releases are derived by applying that rule to the work actually admitted; they are never supplied as inputs, because when an owner releases depends on when its work was admitted. Run the workload once with one fixed root `A` unsubdivided, then again with `A`'s arrivals spread across any number of AttributionChildScopes beneath that same root and nothing else changed. The bound is a set of prefix inequalities over the provider's ordered decision points `k`: for every `k`, `A`'s cumulative selections in the subdivided run must not exceed its baseline value; for every `k` and every resource dimension `d`, `A`'s cumulative admitted quantity in `d` must not exceed its baseline value; and for every competitor root `B` other than `A` and every demand of `B`, that demand's selection position in the subdivided run must be no later than in the baseline, with a selection that never occurs taking position infinity. The bound is one-way: it requires no equality of outcome, no share ratio, and no scheduler; a subdivision that leaves `A` worse off or a competitor better off is conforming. [`FORMAL-PROOFS.md`](../../../../FORMAL-PROOFS.md) Note 14.5e states this model and comparison canonically and governs if this summary ever diverges from it;
- work conservation constrains immediate refusal. An immediate, nonwaiting acquisition returns typed pressure instead of retaining a demand only for a claim that does not fit, meaning one that cannot be met from capacity that is neither live nor reserved for an in-flight admission, in every dimension the claim requires. Fit is computed against the committed and actually backed admission domain with P5 policy applied: `Gc` net of `S`, additionally bounded by `B` in any dimension where the provider claims backing, and further narrowed by an explicit local isolation policy or optional local ceiling. Fit never reads a transient observation `O` and never reads a contraction target `T`. A fitting claim is admitted, except under a proven structural limit, under an explicit local isolation policy or optional local ceiling, or when the accounting needed to admit it safely is unavailable, unsafe, or poisoned. Refusal may not be used to hold capacity for an anticipated demand, to smooth a demand rate, or to enforce an undeclared share; any such reservation is a partition and is conforming only as explicit local isolation policy;
- only a lease whose owner contract declares it reclaimable can be selected for reclamation;
- `Cleanup` and `Admitted` leases are never reclamation victims, and cleanup capacity that must be available under every condition is still reserved before allocation;
- refusal names an unavailable resource dimension and is a resource result, never an authorization result;
- elapsed time creates, releases, and expires nothing.

**What P6, partition non-amplification, does and does not claim.** Which local values map onto a FairnessRoot is provider and deployment policy. A trusted local owner may use one root for the whole process, or one per local principal, per listener, per ingress class, or per Mesh runtime. The mapping may take verified inputs: the trusted local provider or ingress owner may use facts it has itself verified or authenticated, including an authenticated local principal, an authenticated remote identity, or an isolated ingress path. What no mapping may do is let a claimant-supplied or wire-visible value directly name, select, split, or multiply a root, or let any party increase the number of roots it is attributed to by asserting something. Verification and assignment stay with the local owner: the mapping need not be independent of verified facts, but it must be independent of unverified assertion. A coarser mapping reduces exposure to an actor that can obtain several roots and reduces fairness granularity; a finer mapping does the reverse. This module fixes no scheduler model, root taxonomy, or principal enumeration.

P6 is stated over one fixed input workload and compared prefix-wise, so its nonclaims are explicit. It asserts no equality of outcome, no share ratio, no scheduling policy, no root taxonomy, and no timer or elapsed-time behavior. It asserts nothing about infinite runs, eventual admission, throughput, or latency: a provider that refuses every arrival in the workload is still non-amplifying, so this property alone proves no progress. It asserts no correspondence between a FairnessRoot and a real-world claimant or actor, so it is not Sybil resistance and rests on no real-world claimant identity premise; if one actor legitimately holds several roots, the property is silent about the total share that actor obtains, and countering that belongs to deployment admission and root-assignment policy. It is not the hostile-ingress obligation: progress, backpressure, and bounded admission for unknown remote input are separate obligations of the pre-authentication ingress path, where each retained unit holds a finite claim, pressure is typed and dimension-named, and no unbounded producer queue exists. A fairness argument is not evidence for those obligations, and an ingress backpressure control is not evidence for fairness.

**Safe contraction of a committed grant.** Five quantities are distinct per dimension and may never be conflated: `S`, the sum of live claims and failed-cleanup-retained charges; `Gc`, the provider-owned committed grant that admission is checked against; `B`, the capacity actually backing the dimension that the provider can prove; `T`, an owner-selected contraction target; and `O`, an external observation of host capacity.

`O` is inert. It is an input, never a grant, never a limit, and never a fit test. It may be stale, wrong, adversarially influenced, in foreign units, or absent. No admission decision reads it and no refusal is justified by it. Only a named, recorded local owner policy may convert `O` into an explicit owner-selected `T`; this boundary prescribes no schema for that policy beyond its being named, recorded, and owner-selected. `T` is a request, not an act: it asks `Gc` to descend toward it, and by itself it lowers no grant, releases no charge, and refuses no admission. `Gc` descends toward `T` only after owner-driven release lowers `S` enough to make each step safe, one safe step at a time, and `Gc` is never installed or reduced below `S`. `S <= Gc` holds at every instant, with no exception and no window, so `S > Gc` is not a reachable state and must not be described as one. Contraction applies only to admission decisions taken after it, leaves every committed lease owned and charged, releases, revokes, invalidates, and reuses nothing, and is never a reclamation mechanism. A probe that reports `S` at an instant is not a contraction, and the two must never be substituted for each other.

A provider that claims backing for a dimension proves `Gc <= B` in that dimension at admission. A provider that makes no backing claim proves nothing of the kind, and admission does not universally require a backing proof. If `B` falls below `Gc` the provider reports typed backing loss for that dimension; if `B` falls below `S` it reports typed external overcommitment. In both states every charge is retained, no release is forged or inferred, conflicting admission is refused with a typed result naming the dimension, and `Gc` is still not lowered below `S`. A backing proof taken at admission is historical: it does not make physical backing exist later, and when `B` falls, substrate availability may genuinely have failed. Charges remain charged and commitments remain owed, but the underlying resource may simply not be there. These states are conservative accounting, not an assurance of physical backing, and must never be reported as one. Where an adapter cannot prove what actually backs a dimension, that shortfall is a named Slice C residual: it is not silently treated as backed and is not counted into `B`.

The shipped provider fixes its grant at construction, exposes no contraction entry point, models no `O`, derives no `T`, and proves no `B`. It therefore exercises none of the obligations in this subsection, no control exercises them, and the absence of a contraction path is not evidence that contraction is safe.

**Concrete policy of the shipped `FiniteResourceProvider`.** The paragraph below describes this provider's arbitration, verified against this provider. It is not universal or basal semantics. A different conforming provider may satisfy the properties above with different arbitration, and would then supply its own concrete-policy evidence.

**Disclosed nonconformance with P6, partition non-amplification, above.** This provider does not satisfy it. Its equal-authority rotation is keyed to `ResourceScopeId`, which is derived from the allocation address of a fresh process-local scope identity at each scope construction, so each AttributionChildScope created beneath one FairnessRoot introduces another distinct rotation key and nothing relates those keys back to the root. Run the same fixed input workload twice: with root `A` unsubdivided, and with `A`'s arrivals spread across N AttributionChildScopes beneath `A`. At some decision prefix the subdivided run gives `A` strictly more cumulative selections than the baseline, and a competitor's demand is selected at a later decision position than its baseline position. Both prefix inequalities are violated, which is the amplification P6 forbids.

No named control runs the two executions and compares the prefix inequalities, and none may be cited as if it did; disclosure does not discharge the obligation. The correction is an open obligation on this provider's fairness slice, which must bind each pending demand to the FairnessRoot that owns it rather than to a per-scope identity, and must add that comparison as a control. The first such control fixes a bounded decision prefix chosen so that none of the compared newly admitted demands releases within it, which makes the comparison well defined without depending on release timing; within that prefix it is a genuine conformance result for the decisions it covers, it is never globally sufficient, and it is never reported as a whole-model proof. A later generalization may carry a deterministic owner automaton instead of a bounded prefix. Either form must isolate the bookkeeping that subdivision itself creates by exactly one of two methods: charge the extra bookkeeping to a dimension shown non-binding in both executions, or prefund equivalent bookkeeping in both executions before the comparison begins. Merely stating that charge, or netting it against `A`'s admitted quantity, is not isolation and must not be offered as such.

Until that control exists and passes, P6 must be reported as failing and must not be reworded into a per-scope guarantee this provider already meets. The disclosure is limited to subdivision-driven scheduling amplification: the conservation, cleanup-ownership, no-minting, borrowing, refusal, and time properties above are unaffected.

The shipped provider is shared and work-conserving outside an exact pending demand. Under pressure, one move-only demand per provider scope receives `Cleanup`, `Admitted`, then `Speculative` arbitration, and equal-authority scopes rotate by process-local scope identity. The determinism of that arbitration is narrow, and it is a positive claim with an exact scope. Given identical already-issued `ResourceScopeId` values, identical provider state, and the same ordered sequence of provider operations, arbitration is deterministic: the same demand is selected and the same result is produced. Nothing beyond that is claimed. `ResourceScopeId` is the allocation address of the scope identity, so which identities are issued, and therefore the equal-authority rotation order, is not reproducible across runs, processes, allocators, builds, platforms, or thread schedules, and an address may be reused once its scope identity drops. A scope identity is unique only among live scopes, never over the life of the process. No caller, control, or diagnostic may treat it as stable, meaningfully ordered, comparable across time, or unique over time, and no behavior may depend on a particular equal-class rotation sequence. A pending turn blocks conflicting equal- or lower-authority acquisitions only in the dimensions required by that turn; other dimensions remain borrowable. Reclamation selects only a lease admitted through the cooperative path, and only while it remains `Speculative`. That ordering and rotation together prevent starvation by construction in this provider: a cleanup-class demand is not deferred indefinitely behind speculative demand, and no scope reacquires indefinitely ahead of an equal-authority scope's outstanding demand. This non-starvation behavior is an obligation of this concrete policy, not a property required of every conforming provider.

Under any conforming provider, a retirement request is a sticky notification to the exact owner. It does not release the lease, infer cleanup from elapsed time, or make the charge reusable. The owner must fence new work and either drop the lease after cleanup succeeds or retain the exact charge after cleanup failure. Without a pending demand, a slow reclaimable lease may remain live indefinitely. Arbitration cannot manufacture capacity held by non-reclaimable work.

Every successful acquisition returns one non-cloneable `ResourceLease`. The lease retains its declared claim until an explicit transition, release, provider-approved reclamation, or failed-cleanup retention. Each resource dimension is independent. No value is an unlimited sentinel.

Exactness is limited to the quantity named by the claim. Allocator overhead, native WebRTC memory, dependency tasks, kernel handles, driver state, and external relay allocations remain explicit residuals until an adapter can claim or isolate them.

## Observation hierarchy

Production observations use one fixed hierarchy:

```text
process root
  -> one live Mesh runtime
    -> one live joined network instance
      -> one attempt or peer connection
```

A leaf observation updates the leaf and all three ancestors. Sibling network instances and sibling peers do not observe each other. The process root aggregates measurements and grants no authority.

The network-instance scope describes a live runtime owner. It is not called an exact Mesh Context because it is not bound to an immutable context identity. Carrier, ingress source, attempt, and known-origin attribution are separate dimensions. They must not be inferred from the runtime aggregation path.

Each scope keeps fixed-size report state for the closed resource families. The hierarchy has no child registry, per-active-lease collection, or hierarchy-wide mutex. Begin, replacement, and completion update each scope independently. A diagnostic snapshot can therefore observe a transient difference between an ancestor and a descendant. It does not claim global linearizability.

## Measurements

`ResourceUse` has four independent axes:

- items;
- logical bytes;
- retained bytes;
- tasks.

Logical bytes describe live content. Retained bytes use the producer's documented measurement contract and include unused capacity only when that producer reports it. The two values are not substituted for each other. A producer that reports Rust `String` or `Vec` capacity does not thereby measure allocator metadata, stack use, native dependency memory, or process RSS.

Each family report includes current and peak use, current and peak lease counts, the oldest active lifetime when known, completed lease count, final completed quantities, total completed lifetime, and a sticky `measurement_inexact` flag.

Oldest-lease tracking uses constant metadata. If the oldest of several leases ends, the next-oldest start cannot be recovered without retaining one timestamp per active lease. The report sets `oldest_active_lifetime_inexact` and stops reporting an exact oldest lifetime until the family becomes empty. Other exact counters remain exact.

## Observation ownership and cleanup

Callers provide a family and a measured `ResourceUse`. The accountant returns an `ObservationLease`. Dropping that lease removes the active measurement and records its lifetime at every scope in its path.

A caller that owns a growing or shrinking collection may replace the lease's measured quantity with a fresh measurement from that same object. This changes measurement only.

Arithmetic is checked before saturation. Overflow, an unsupported platform-sized measurement, inconsistent subtraction, or a poisoned scope lock marks the affected report inexact. Counters do not wrap or underflow. Production measurement code has no deliberate panic path for measurement failure.

Measurements are memory-only. Process restart destroys them. They are not reconstructed from durable state.

## Observation restrictions

The accountant must not:

- define or infer a numeric limit;
- accept or refuse work;
- reserve capacity;
- create an admission permit or authority capability;
- authorize an identity, mesh, connection, session, route, or application action;
- provide backpressure, eviction, prioritization, or admission policy;
- perform networking or mutate production domain state.

An `ObservationLease` proves only that a caller-reported quantity is being measured. It is never evidence that work was admitted, authenticated, or safe.

## Arc 03 integration status

Arc 03 installs provider-backed ownership for the bounded WebRTC connector paths named in its report. Connector construction, candidate content and application, callbacks, cleanup, and selected real-time work hold finite claims at their declared boundaries. The library selects no production grant and no universal Mesh, peer, attempt, session, queue, or flow count. A deployment supplies the finite process grant and any optional local ceilings.

This is not repository-wide resource closure. Signaling queues, complete WebRTC and ICE internals, sockets, DNS, dependency-created tasks, native tracks, and external TURN allocations remain either later work or explicit residuals where the current adapter cannot enforce them. Where the adapter cannot prove what actually backs a dimension, that shortfall is a named Slice C residual and is never counted as backed.

Accepted CI at exact head `6a22911` establishes runtime non-regression only: the retained behavior still runs as accepted at that head. It is not proof of P6 partition non-amplification, not proof of any contraction behavior over `S`, `Gc`, `O`, `T`, or `B`, not proof of the hostile-ingress progress and backpressure obligation, not proof of substrate backing, and not a resolution of the Slice C unproved-backing residual. None of those has a control at that head, so a passing run cannot have exercised them, and no part of that result may be cited toward them.
