# MyOwnMesh existing-repository transition playbook

Status: stepped execution contract for transitioning the existing Rust repository to the adopted transport-independent hybrid networking architecture.

Repository target:

```text
upstream source:  mrjeeves/MyOwnMesh
architecture-owned fork: nathanfraske/MyOwnMeshSecurityReview
inspected upstream main: 9b5b4862d21ddbb92e9ff4fbbade47b41fe6fa75
inspected fork main:     28c9e27f89fdb8c2af9a9691a0fe0271befbe060
```

At inspection, upstream was two logging-focused commits ahead of the writable fork. Recheck both heads immediately before execution.

This playbook migrates the existing system. It does not authorize a clean-room rewrite.

## 1. Mission

The transition must preserve the working, field-tested network while replacing the authority model, state ownership, and cross-subsystem boundaries that conflict with the adopted architecture.

The migration formula is:

```text
wrap the working mechanism
    -> prove the target boundary
    -> redirect production callers
    -> delete the legacy authority path
```

The first product objective is a working end-to-end session on the new promotion boundary:

```text
existing signaling
    -> existing WebRTC/ICE transport work
    -> ConnectedChannelCapability
    -> channel-bound mutual Device authentication
    -> current Open or Closed policy
    -> principal-bound SessionCapability
    -> one existing application payload operation
```

Everything else builds outward from that vertical slice.

## 2. Non-negotiable constraints

1. **Transition, do not restart.** WebRTC, ICE recovery, Nostr, mDNS, STUN/TURN, native RTP media transport, daemon, GUI, installer, updater, diagnostics, and field-derived tests are assets. Fixed H.264, Opus, video, audio, and lane semantics are compatibility behavior to generalize, not basal architecture.
2. **Usability first, promotion secure.** Untrusted hints may cause bounded speculative networking work. They may not create durable authority, deliver application data, or promote a session.
3. **Transport independence, not transport removal.** The connector remains first-class and does real discovery, racing, measurement, migration, and recovery.
4. **No durable route ceremony.** Ordinary candidates, routes, current path, handoff, and reachability remain live connector/session state.
5. **One state class, one owner.** No `Arc<Mutex<GlobalState>>`, replacement engine grab bag, or global command/event enum.
6. **Open remains open.** Resource control cannot become disguised admission.
7. **Closed alone adds governance authorization.** Existing `auto_approve`, local roster mutation, or transport state cannot satisfy it.
8. **No ordinary mesh forwarding.** A relay is an explicit exact allocation carrying opaque endpoint packets.
9. **No new behavior in compatibility adapters.** Every adapter has a deletion arc.
10. **Do not invent numeric budgets.** Instrument the complete path, measure supported targets, and surface values for owner review.
11. **Own properties, not magnitudes.** This package fixes the *properties* of resource ownership. Capacity magnitudes come from a named provider supplied by the deployment or embedder, never from a document, default, or library constant. A concrete provider's arbitration algorithm is that provider's policy, not a basal architectural requirement.

## 3. Source-of-truth document set

Read in this order:

1. [`ARCHITECTURE.md`](ARCHITECTURE.md), the minimal system shape.
2. [`APPLICATION-INTEGRATION.md`](APPLICATION-INTEGRATION.md), the product-facing boundary.
3. [`IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`](IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md), the concrete implementation contract.
4. [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md), the proof obligations.
5. [`red-teams/MESH-ATTACK-VECTORS.md`](red-teams/MESH-ATTACK-VECTORS.md), source findings and adversarial gates.
6. [`ARCHITECTURE-OWNERSHIP.md`](ARCHITECTURE-OWNERSHIP.md), conflict and upstream policy.
7. [`CURRENT-TO-TARGET-MIGRATION-MATRIX.md`](CURRENT-TO-TARGET-MIGRATION-MATRIX.md), state-owner mapping.

No implementation PR may redefine a term already fixed by these documents.

## 4. Repository and branch setup

### Step 4.1. Synchronize the writable fork

1. Add or verify `upstream` points to `mrjeeves/MyOwnMesh`.
2. Fetch current upstream and record its exact commit.
3. Classify the difference from the fork using `ARCHITECTURE-OWNERSHIP.md`.
4. Fast-forward or cherry-pick all U0/U1 changes. At the inspected baseline, the two pending changes are logging-only and should be taken.
5. Run the full existing workspace and GUI checks.
6. Tag the exact pre-transition source. The final tag name is owner-selected; the tag must contain the upstream commit and date in its annotation.

### Step 4.2. Establish branch roles

Recommended roles:

```text
upstream/main
    read-only tracking reference

main
    architecture-owned, continuously buildable product branch

arc/<number>-<scope>
    one migration arc or tightly coupled vertical slice

intake/upstream-<date>-<short-sha>
    temporary branch for classifying and porting upstream work

repro/<case-id>
    isolated red-team or field-failure reproduction only
```

Branch names are workflow labels, not semantic authority.

### Step 4.3. Install the fundamental documents

Place this package at repository root, preserving the canonical names:

```text
ARCHITECTURE.md
FORMAL-PROOFS.md
IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md
APPLICATION-INTEGRATION.md
TRANSITION-PLAYBOOK.md
ARCHITECTURE-OWNERSHIP.md
CURRENT-TO-TARGET-MIGRATION-MATRIX.md
red-teams/MESH-ATTACK-VECTORS.md
diagrams/*
```

Do not retain a competing architecture document under another canonical name.

## 5. Migration operating model

### 5.1. Keep the current engine alive as a temporary supervisor

The existing per-network driver is the safest migration seam because it already serializes current events. During the transition it may:

- start and stop target nodes;
- translate legacy commands into narrow typed ports;
- translate target events back into legacy API events;
- preserve current behavior while callers migrate.

It may not gain new domain decisions. Its state must monotonically shrink.

### 5.2. Establish target nodes before crate extraction

Do not create a large new crate graph before state ownership is proven. Create narrow modules and actor/task owners inside `myownmesh-core` first:

```text
runtime/semantic
runtime/signaling
runtime/attempt
runtime/session_broker
runtime/peer_session
runtime/reachability
runtime/relay
connector
endpoint_auth
capability
resource
application_gateway
```

Extract crates only after:

- the owner has exclusive state custody;
- its ports are stable;
- legacy callers are gone;
- dependency direction is proven by tests.

### 5.3. Universal PR contract

Every migration PR must state:

```text
State class moved:
Old owner:
New sole owner:
New typed inputs:
New typed outputs:
Capability transition added or changed:
Pre-auth and post-auth resource effects:
Legacy adapter introduced:
Deletion arc for that adapter:
Production callers redirected:
Positive controls:
Negative controls:
Red-team cases:
Performance measurements:
Documentation updated:
```

A PR fails review if it adds a new `NetworkCmd`, global event, helper module, or shared mutable map without proving why the target owner cannot own the operation directly.

## 6. Target node ownership

| Node | Sole mutable state | Current sources initially feeding it | Must never own |
|---|---|---|---|
| Semantic Node | accepted durable facts, Open projection, Closed projection, durable grants/revocations, policy guards, verified durable basis | `roster.rs`, `network_state.rs`, `engine/governance.rs`, persistence | sockets, candidates, traffic keys, application queues |
| Signaling Node | carrier connections, durable anti-entropy, ephemeral-control routing, bounded carrier provenance | `engine/signaling_bridge.rs`, Nostr, mDNS, LocalBroker | roster decisions, endpoint identity, application delivery |
| Attempt Node | one attempt's candidates, speculative permits, race policy, cancellation, ephemeral correlation | `ensure_peer_session`, reconnect intents, signaling offer/answer flow | durable facts, application payload, session authority |
| Connector Worker | native connector state, a live connected channel, and optional connector-native data-plane providers | `transport/webrtc.rs`, ICE/TURN code, future relay connectors | mesh authorization, application codec or product meaning |
| Endpoint Auth Task | fresh channel-bound Device-authentication transcript, the closed crypto profile, and the sole issuance of `AuthenticatedChannelCapability` (`endpoint_auth/`) | `engine/handshake.rs`, `signing.rs` | Open/Closed policy, application authorization, wire frames, peer-registry effects, the channel-binding term |
| Session Broker | atomic promotion, current policy guard, principal binding, post-auth permits, capability minting | current approval/Active transition | packet loops, candidate gathering, durable governance |
| Peer Session Node | authenticated channels, traffic/replay state, session data-plane capabilities, application queues, recovery and local path selection | active peer state, heartbeat, ladder, reliable delivery, current media-flow ownership | durable fact construction, global topology authority, codec or screen/camera/audio semantics |
| Reachability Node | local signaling, candidate, channel, and session observations with local age | connection tracer, traffic recency, heartbeat, carrier diagnostics | participation or authorization |
| Relay Node | exact bounded opaque allocations and queues | `services/relay.rs`, TURN/generic relay code | endpoint keys, application parsing, fanout |
| Application Gateway | local principal, IPC connections, public handle leases, subscriptions | daemon control, `handle.rs`, GUI facade | internal SessionCapability construction, connector control |
| Runtime Supervisor | node lifecycle and configuration routing | current driver/service manager | domain state or authorization decisions |

## 7. Delivery plan: two macro-slices

The sixteen-arc queue is retired as a delivery plan. It produced sixteen
miniature products, each with its own review gate, evidence essay, and guard
suite, around a product that could not yet hold a session. Work is now
delivered as two atomic macro-slices, and the arcs survive only as the coverage
checklist in 7.4 -- not as future PRs.

### 7.1. Macro-slice 1: Live Runtime Cutover (PR #6)

Finish and simplify Endpoint Auth; implement one minimal Session Broker that
consumes `AuthenticatedChannelCapability` and mints a private, non-serializable
`SessionCapability`; move every MyOwnMesh-owned application operation behind
that capability; expose only product-neutral, opaque real-time flows at the
connector/session edge; and establish the minimum live runtime ownership the
functional path needs. This macro-slice is confined to MyOwnMesh. Downstream
application migration is a separately authorized future program, not a branch,
fixture, dependency, or integration gate of PR #6. Delete each MyOwnMesh bypass
as the generic session-bound path replaces it; do not preserve a second
authority path merely to keep a hard-alpha downstream caller compiling.

Exit condition:

```text
working direct and TURN connectors preserve the same remote Device identity
exact endpoint authentication plus current policy and a local principal mint a live SessionCapability
a generic MyOwnMesh application operation succeeds only through that session
connected but unauthenticated channels deliver nothing
authenticated but policy-denied channels deliver nothing
replacement and restart invalidate the session
optional realtime flows carry opaque encoded units without basal product semantics
all MyOwnMesh application paths use the session boundary
no pre-V4 or mixed-version authority path remains
no migrated operation has an old bypass
```

### 7.2. Macro-slice 2: Authority, durability, relay, and legacy removal

Created only from merged Macro-slice 1. Typed durable-semantic and
ephemeral-transport signaling lanes; final Open and Closed semantics with the
selected governance proof; exact opaque-infrastructure and Closed-member relay
profiles; durable store reopening and compaction the applications actually
require; a final resource-closure pass over the completed owner graph; deletion
of the remaining `NetworkState`/legacy-driver ownership, ordinary forwarding,
obsolete governance, compatibility adapters, and dead APIs; and one coherent
new-mode MyOwnMesh release. Downstream consumer migration begins only when the
owner separately authorizes that program. Its last phase is the closure gate in
7.3, which is what makes the deletions above verifiable rather than asserted.

### 7.3. Repository Closure and Nodularity Gate

The final phase of Macro-slice 2, and the last thing that happens before the
transition is declared complete. It is not a third macro-slice and not another
architecture program: it introduces no product semantics, and every item it
requires is a deletion, a consolidation, or a move to the owner that should
already have held the thing. Nothing here can be satisfied by adding a layer.

The gate is met only when all of the following are absent from the repository:

```text
no LegacyV1 or mixed-version path
no temporary compatibility adapter
no obsolete protocol variant or config field
no dead permit, constructor, feature or public re-export
no old peer-string / socket / route authority bypass
no stale direct-send or media-lane API
no transition-only #[allow(dead_code)] keeping removed design alive
no obsolete CI job, regex guard, mutation harness or evidence dossier
no unused dependency
no duplicate mutable truth beside the accepted capability owner
no application or transport semantics in the wrong architectural node
no grab-bag module owning unrelated state classes
canonical documentation describes the code that actually remains
```

Two of those are easy to satisfy dishonestly and are therefore stated exactly.
"No duplicate mutable truth" means one owner per mutable state class, not one
owner plus a cache that agrees today. "Canonical documentation describes the
code that actually remains" means the current contract and nothing else: a
comment recording what a file used to contain is not documentation of what
remains, and a removed variant does not keep a grave marker in production
source.

### 7.4. Coverage checklist (internal, not a PR queue)

| Former arc | Disposition |
| --- | --- |
| 00 Baseline, 01 Inventory, 02 Capability/resource spine, 03 Connector worker | Landed. Their evidence essays and per-arc harnesses are deleted; the boundary is carried by Rust visibility, private constructors, type checking, and the two compile-fail probe harnesses. |
| 04 Endpoint Auth | Macro-slice 1. No further lettered checkpoints. |
| 05 Session Broker, 06 Application payload gating, 06A Media generalization | Macro-slice 1. |
| 10 Attempt nodes, 11 Peer session node, 13 Reachability | Macro-slice 1, as the ownership the integrated path requires -- not as separate certified arcs. |
| 07 Typed signaling lanes, 08 Open semantics, 09 Closed semantics | Macro-slice 2. |
| 12 Relay profiles, 14 Durable persistence, 15 Resource closure, 16 Legacy removal, 18 Release rollout | Macro-slice 2. |
| 17 Causal-contract/application domains | Optional. Out of the completion critical path. |

## 8. Test and evidence program

### 8.1 Compile-time boundaries

Require compile-fail or visibility tests proving:

- application code cannot construct signaling records or connector control;
- connector code cannot mint SessionCapability;
- signaling code cannot deliver application data;
- relay code cannot access endpoint traffic keys;
- public IDs cannot reconstruct local capabilities;
- durable semantic code imports no transport runtime.

### 8.2 Pure semantic tests

Cover canonical encoding, signatures, exact context, Open self-participation, Closed proof confinement, independent/joinable/exclusive concurrency, compaction equivalence, and store-opening non-revival.

### 8.3 Deterministic networking simulation

Build fakes for signaling carriers, connectors, connected channels, relay, time, entropy, resources, and fault injection. Exercise every callback order, duplicate, cancellation, crash boundary, and policy invalidation relevant to promotion and recovery.

### 8.4 Real integration matrix

Preserve and expand current cross-platform and field scenarios:

- direct LAN;
- Nostr signaling;
- mDNS signaling;
- TURN;
- network change;
- sleep/wake;
- stale ICE state while traffic flows;
- apparently connected transport with no traffic;
- media;
- daemon and GUI IPC;
- process restart;
- mixed-version behavior where supported.

### 8.5 Performance evidence

Measure at minimum:

```text
time to first hint
time to first candidate
time to first connected channel
time to endpoint authentication
time to policy result
time to promoted session
time to first application byte
recovery time by failure class
pre-auth bytes, tasks, sockets, and CPU
post-auth queue and media costs
cleanup time and retained state
```

Do not collapse these into one connection time, because the architecture separates them intentionally.

These measurements are required, and they are never capacity. Producing them is an obligation for every arc that touches a resource path; omitting them is a defect. That obligation does not let any observation set, justify, or imply a grant, ceiling, budget, or admissible-object count. Performance characterization is also not correctness evidence: a control passes only against a named commit in CI, and a favorable measurement never stands in for that.

**A passing CI run proves only what it has controls for, and only about the commit it ran on.** Accepted CI at exact head `7e2ba9e`, and at `6a22911` before it, is runtime non-regression evidence only: retained runtime behavior still runs as accepted at that commit. **Once the branch moves past a head, its run becomes prior-head evidence** — it describes a commit that is no longer current and carries no claim about the new head. In neither case does such a run prove P6 partition non-amplification, grant contraction over `S`, `Gc`, `O`, `T`, `E`, or `B`, hostile-ingress progress or backpressure, an enforceable isolation envelope, an actual reserved guarantee, or Slice C closure. No control for any of those exists at those heads, so the runs cannot have exercised them, and no part of those results may be cited toward them. State this limit wherever such a run is cited as evidence.

## 9. Upstream intake during transition

1. Fetch upstream on a regular owner-selected cadence and before every release.
2. Create an `intake/` branch at the exact upstream commit.
3. Classify each commit U0-U5.
4. Merge U0 and proven U1 changes.
5. For U2, port the failure reproduction, test, and mechanism into the target owner. Do not merge the legacy state owner.
6. Reject U3 behavior with a written invariant reference.
7. Send U4 to owner review with measured tradeoffs.
8. Update the migration matrix when a path becomes architecture-owned.

A field fix is not lost because its old module is rejected. The bug reproduction and mechanism are preserved in the correct owner.

## 10. Stop conditions

Pause the arc and surface an owner decision when:

- a claimed protocol or provider limit has not been proven;
- a proposed optional local ceiling lacks owner review;
- the selected Closed proof profile is still undefined;
- a competing design presents a real usability/security tradeoff;
- migration would silently reinterpret existing durable authority;
- a current field behavior cannot be reproduced or explained;
- a state class cannot be assigned one owner without changing product semantics;
- a compatibility adapter would need permanent product behavior;
- a supported platform or required transport profile regresses;
- the proposed change would reintroduce a durable route, global current path, or transport-removed design.

## 11. Definition of architecture-complete

The transition is complete when all of the following are true:

1. the connector attempts and races viable transport paths under bounded speculative resources;
2. a working channel is not application authority;
3. exact mutual Device authentication is bound to the working channel;
4. Open or Closed policy and local-principal admission gate promotion;
5. every application send, receive, callback, optional real-time flow operation, and recovery action uses a live SessionCapability;
6. signaling and application payload types are disjoint;
7. durable semantics are transport-independent, while transport remains first-class;
8. Open has no hidden sponsor or pair-permission gate;
9. Closed alone carries governance authorization;
10. ordinary mesh-member payload forwarding is absent;
11. relays use exact bounded opaque allocations;
12. handoff is endpoint-driven, with no route ledger or relay-to-relay requirement;
13. reachability is useful local evidence, not authority;
14. store opening restores durable state but no live networking capability;
15. every protected resource family has a live lease, a named provider, typed pressure behavior, and an explicit exactness or residual classification, with the Arc 15 property gate satisfied and no arbitration algorithm required of a conforming provider;
16. every mutable state class has one owner;
17. the legacy driver, `NetworkState` grab bag, authority bypasses, and compatibility adapters are deleted, and the Repository Closure and Nodularity Gate in 7.3 is met in full;
18. the full conformance and red-team suite passes on built artifacts;
19. supported deployment, GUI, daemon, installer, updater, and platform behavior remains accepted by the owner.

## 12. Owner decisions that remain explicit

The playbook does not invent:

- the final protocol/profile identifier;
- the Closed governance proof and recovery rule;
- local-principal authentication per platform;
- the installed resource provider, the origin of its capacity, its retention behavior, and its arbitration policy;
- which of `E` and `B` the provider claims in each dimension, and what proves each independently;
- the contraction policy: whether any `O` is collected at all, the named owner policy that sets or derives `T`, and what establishes `E` or `B` where either is claimed;
- the FairnessRoot selection rule, including which trusted provider or ingress owner selects a root and how roots are separated;
- the disposition of each named residual: adapter hook, external isolation boundary, conservative over-charge, or disclosed non-enforcement;
- whether the optional local ceiling set is absent or enabled, and every value in it when enabled;
- optional local resource, queue, retry, timeout, cache, cost, isolation, and bandwidth policy values;
- required restrictive-network connector profiles;
- mixed-version compatibility duration;
- application data-operation set and optional connector-native real-time flow contract;
- performance regression tolerances;
- release cohort and rollback policy.

Each optional policy is surfaced with measurements and concrete alternatives for owner review. Measurements do not define basal product cardinality. Structural counts are not deployment-capacity recommendations, universal protocol limits, or evidence of exact physical resource quantity.
