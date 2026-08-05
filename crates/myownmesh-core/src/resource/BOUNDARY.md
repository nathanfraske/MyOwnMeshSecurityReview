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
- unused capacity is borrowable unless an explicit local isolation policy forbids it;
- arbitration distributes existing capacity only; it never releases, revokes, replaces, or reuses another owner's live claim;
- only a lease whose owner contract declares it reclaimable can be selected for reclamation;
- `Cleanup` and `Admitted` leases are never reclamation victims, and cleanup capacity that must be available under every condition is still reserved before allocation;
- refusal names an unavailable resource dimension and is a resource result, never an authorization result;
- elapsed time creates, releases, and expires nothing.

**Concrete policy of the shipped `FiniteResourceProvider`.** The paragraph below describes this provider's arbitration, verified against this provider. It is not universal or basal semantics. A different conforming provider may satisfy the properties above with different arbitration, and would then supply its own concrete-policy evidence.

The shipped provider is shared and work-conserving outside an exact pending demand. Under pressure, one move-only demand per provider scope receives deterministic `Cleanup`, `Admitted`, then `Speculative` arbitration, and equal-authority scopes rotate by process-local scope identity. A pending turn blocks conflicting equal- or lower-authority acquisitions only in the dimensions required by that turn; other dimensions remain borrowable. Reclamation selects only a lease admitted through the cooperative path, and only while it remains `Speculative`. That ordering and rotation together prevent starvation by construction in this provider: a cleanup-class demand is not deferred indefinitely behind speculative demand, and no scope reacquires indefinitely ahead of an equal-authority scope's outstanding demand. This non-starvation behavior is an obligation of this concrete policy, not a property required of every conforming provider.

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

This is not repository-wide resource closure. Signaling queues, complete WebRTC and ICE internals, sockets, DNS, dependency-created tasks, native tracks, and external TURN allocations remain either later work or explicit residuals where the current adapter cannot enforce them.
