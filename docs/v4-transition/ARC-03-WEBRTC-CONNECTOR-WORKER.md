# V4 Arc 03 WebRTC connector ownership

Status: elastic resource-contract correction on `arc/03i-final-connector-boundary` in draft fork PR #5. The connector lifecycle and authority work at `8a2351d` remains accepted. Arc 03 is reopened only where its static resource policy conflicts with the adopted elastic provider contract. PR #5 is not merge-approved. Arc 04 has not started.

## 1. Scope

Arc 03 puts the existing WebRTC connector behind explicit process, Mesh runtime, attempt, candidate, callback, cleanup, and Endpoint Auth provenance owners. It preserves the existing ICE, STUN, TURN, DTLS, direct path, native RTP, mDNS, Nostr, reconnect, and recovery implementations. H.264 and Opus remain in a temporary compatibility adapter, not in basal connector semantics.

This arc does not add route identities, durable connector records, path generations, pair permissions, authentication before pathfinding, Endpoint Auth transcript verification, authenticated session authority, final application flow policy, or final codec policy. It does not add Arc 03 responsibilities to `PeerStateData`, `NetworkCmd`, or `NetworkState`.

Endpoint payload uses an endpoint WebRTC session. TURN may be its selected ICE carrier. Signaling never carries endpoint payload.

## 2. Ownership and open semantic cardinality

```text
one ProcessResourceRoot
    -> one process resource provider port
    -> one accounting and fairness child scope for each live Mesh runtime

one Mesh connector child scope
    -> shares the process resource grant
    -> may borrow unused capacity under work-conserving fairness

one connection attempt
    -> multiple connector candidates

one WebRTC connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and pairs

DataChannelOpen from the exact live connector
    -> ConnectedChannelCapability
    -> EndpointAuthTask owns connected-channel provenance
```

`ConnectorCandidateCapability` represents one connector candidate, not one trickled `LocalIceCandidate`. The attempt defines its composite resource claim but cannot manufacture capacity. Admission must acquire a finite process-backed lease and attribute it to the exact Mesh child. External code cannot construct resource authority.

Basal MyOwnMesh defines no fixed maximum Mesh, peer, connector-attempt, session, or flow count. Admission depends on actual claim size and current resource availability. One large connector may cost more than many small connectors. Creating another Mesh scope cannot multiply the process grant.

## 3. Resource provider and optional local policy

The target Arc 03 resource port grants actual resource dimensions, including accounted memory, queued bytes, sockets or handles, native transport objects, tasks, callbacks and scheduled work, storage, relay or provider allocations, enforceable parsing or CPU work, and explicit opaque residual claims.

Static Arc 03 fields are classified in [`ARC-03-RESOURCE-OWNERSHIP-REPORT.md`](ARC-03-RESOURCE-OWNERSHIP-REPORT.md). Basal product-object ceilings move to resource leases. Actual WebRTC or compatibility shape limits remain provider or compatibility constraints. Optional local ceilings remain explicit wrappers for locked-down, Closed, cost-controlled, test, or compatibility deployments.

Default scheduling is structurally fair and work-conserving. Unused capacity is borrowable across Mesh scopes. Cleanup and release work remains available under pressure. Already admitted and higher-authority work is protected from new speculative work. No native-close timeout exists. No elapsed duration changes resource, protocol, authentication, lane, or cleanup truth.

Generic real-time enablement creates no H.264 or Opus tracks by itself. The temporary adapter requires an explicit `LegacyWebRtcMediaProfile`. Profile construction validates its fixed lane identity space and pre-provisioned lane counts. Provider attachment validates the required native resources and the adapter's fixed 2,048-fragment H.264 ceiling.

Arc 03 selects no numeric product cardinality. Connector-capable startup requires a resource provider, not an owner-authored vector of peer, Mesh, attempt, queue, or flow counts.

## 4. Reserve before allocation and retention

Production connector construction follows this order:

```text
request the connector's exact composite claim
    -> acquire a finite process lease attributed to the exact Mesh child
    -> create one cleanup owner
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection
    -> attach it to the cleanup owner
    -> install callbacks and connector state
    -> recheck attempt liveness
    -> publish the worker or start cleanup
```

Cancellation after native allocation, cancellation after result delivery, runtime shutdown, and construction failure all reach the same close owner. Raw `Transport::open_peer*` construction is limited to tests and the `transport-lab` feature.

Remote candidates use one exact attempt owner before and after remote SDP. Candidate retention consumes queue-storage and accounted-byte leases. Parsing, duplicate detection, hashing, and native application consume scheduled-work claims. Duplicate identity uses tagged, length-delimited fields so field boundaries cannot be confused by embedded delimiter bytes. Visible content accounting does not claim allocator or native retained memory. A provider refusal retires the exact attempt. An optional local policy may impose stricter cumulative ingress ceilings. A new owner exists only for a new connector attempt or an explicit successful ICE restart.

Candidate observations include visible string capacities and queue container capacity, but remain marked inexact because allocator overhead and storage inside webrtc-rs are not observable.

Each queued or applying remote candidate carries a process-local `RemoteCandidateAttemptIdentity`. A restart first retires the old identity and creates a provisional replacement. The old identity remains the recorded current attempt until commit. A local restart commits the replacement only after native `restart_ice` succeeds. A remote restart is detected when the effective ICE username fragment or password changes on the same MID, or media-line index when MID is absent. Session-level inheritance and media-level overrides are resolved before comparison. Media reordering, addition, or removal does not renew the candidate envelope when existing transport credentials remain unchanged. A remote restart commits only after the exact replacement remote description succeeds. An unchanged DTLS fingerprint is not treated as proof that ICE credentials are unchanged.

Candidates received during a provisional transaction are retained only by the provisional attempt. The old attempt cannot apply them. Structured username-fragment values and candidate-line `ufrag` extensions are parsed independently. Empty structured values are absent. Two nonempty declarations must agree exactly, and duplicate or incomplete candidate-line declarations are invalid. The first invalid binding declaration retires the exact candidate attempt before hashing or retention and returns its typed reason once. Every later submission returns the terminal attempt result before binding parsing, candidate classification, hashing, retention, duplicate accounting, diagnostic publication, or native work. A candidate carrying a replacement username fragment may arrive before its replacement SDP. It consumes the old attempt's finite ingress envelope but is not applied to the old native ICE agent. Once an exact replacement SDP arrives, only an old-queue candidate with an explicit username fragment matching the replacement credential pair may move to the provisional attempt under a fresh bounded reservation. Any declared MID or media-line index must also select that replacement binding. A location-only candidate retained by the old attempt is dropped. A location-only candidate admitted after the provisional replacement exists may remain because the replacement owner admitted it directly. Every candidate must carry at least one binding input: a nonempty MID, a media-line index, or a username fragment. A username fragment without MID or index must identify one unambiguous effective credential pair. A wholly unbound candidate is rejected. A delayed old candidate remains bounded and cannot enter the replacement native ICE agent. Local restart failure and replacement remote-description failure do not publish the provisional envelope. With no proven native rollback, the connector is retired and its cleanup owner closes the native peer.

The first invalid binding or resource-provider refusal retires the exact candidate attempt. Later submissions return the terminal attempt result without creating another diagnostic. An optional local ceiling refusal has the same terminal ownership result. Only an explicit local restart or a remote SDP with changed exact ICE credentials may create another attempt owner. The process-local identity is not serialized and is not a route, generation, ledger fact, timestamp, or timer.

## 5. Promotion, lock order, and close ordering

Attempt allocation, promotion, and retirement share one attempt-transition mutex. Connector promotion never holds connector authority while acquiring it:

1. Move the candidate into private `Promoting` state under connector authority.
2. Release connector authority.
3. Perform the attempt transition.
4. Release the attempt-transition mutex.
5. Reacquire connector authority and publish or retire the result.

Attempt retirement notifies connector retirement only after releasing its transition lock.

One `ConnectorOperationFence` orders the Arc 03 operations that can create or use connector authority. `confirm_data_channel_open` and temporary legacy real-time admission acquire that exact fence. If close commits first, neither can issue authority. Endpoint sends, real-time writes, lane operations, native track callbacks, endpoint callbacks, SDP work, candidate application, and ICE restart use the same fence on their Arc 03 entry paths.

This is a proof about the listed Arc 03 paths. It is not a claim that every application behavior in the repository has been converted to this fence.

Channel open and close use a fixed lifecycle owner outside the ordinary callback mailboxes:

```text
AwaitingOpen
    -> OpenPending
    -> OpenCommitted
    -> ClosedPending
    -> ClosedDelivered
```

Close may move an uncommitted open directly to `ClosedPending`. Open is committed only after the exact connector installs its working-channel capability and Endpoint Auth handoff. Close is exposed once, clears coalesced observations, and prevents later callback delivery. Renegotiation is a sticky coalesced obligation until it is consumed or the connector retires.

## 6. Callback producers and work-conserving scheduling

Control and endpoint data have separate typed retention paths. Every retained callback owns its accounted bytes and scheduled-work lease. Producers do not wait in an unbounded `reserve().await` backlog. Pressure returns a typed overloaded, closed, provider-refused, or wrong-owner result. No hidden producer queue exists.

Real-time events cannot enter a shared callback mailbox. Each admitted real-time flow owns its retained units and exact leases. Structurally fair work-conserving scheduling gives every admitted class and flow a bounded service opportunity without mandatory owner-selected weights.

Endpoint protocol data may arrive before channel-open promotion, but it remains in the bounded endpoint mailbox until the exact open transition commits. Close or replacement drops the uncommitted data.

The admitted native callback shape is also finite. A data-only connector accepts one application data channel and no media tracks. The temporary legacy provider accepts that same one data channel plus only the exact H.264 and Opus tracks named by its profile. Duplicate channels, unexpected channels, wrong codecs, malformed identities, and excess tracks coalesce into one connector violation and retirement. They do not create one cleanup future per violation.

## 7. Cleanup ownership and diagnostics

One `ConnectorCloseOwner` owns every private, delivered, cancelled, installed, and partially constructed native connector result. Close disables real-time delivery, commits the operation fence, retires callback identity, drains connector-owned queues, waits for earlier fenced operations, and then calls the native close owner.

One process cleanup executor runs close futures. Cleanup work is reserved as part of the connector's composite claim, so enqueueing cleanup requires no new speculative capacity and does not depend on a product-count queue ceiling. It does not create a runtime or OS thread per close.

- A successful native close releases the exact candidate and connected claims.
- A returned native-close error retains that connector's exact claims and records `Failed`.
- A cleanup future panic or executor failure invokes the exact owner's failure callback.
- Cleanup health reports leased queued jobs, active jobs, completed jobs, failed jobs, provider pressure, and executor failure.
- A caller cancellation does not cancel owner cleanup.
- There is no close timeout. A dependency that never returns remains visibly `Closing` and keeps its finite claim.

The failure callback owns a strong reference to the close owner. Dropping every external close-owner reference cannot discard the exact failed claim, its terminal diagnostic, or its process and Mesh attribution.

## 8. Real-time compatibility bounds

The codec-neutral owner separates speculative inbound quarantine from authorized outbound compatibility flows. Connector-owned bytes, storage, native objects, and work use separate domain claims. If accounting becomes unprovable, the affected provider domain is poisoned or conservatively retains its claims. This proves conservative behavior for connector-owned accounting only. It does not claim complete accounting for allocations hidden inside native WebRTC dependencies.

Each inbound provider flow retains only units whose storage and work claims were granted. Proven WebRTC and compatibility fragment or unit shape limits remain provider constraints. Provider pressure or an optional compatibility ceiling stops speculative work. There is no timer or rate window.

Generic real-time ownership does not install a codec provider or register compatibility codecs. Codec registration is lazy and occurs only when constructing a connector whose explicit temporary legacy profile requires it. An inbound transceiver without an explicit provider is stopped. The temporary legacy provider accepts only H.264 video and Opus audio with exact, in-range `video-N` or `audio-N` track identity. Lane numbers must use their canonical unsigned decimal spelling.

Complete units use deterministic `DropNewest`. Their byte lease follows the queued event and downstream copies. Dequeue alone does not release it.

Outbound compatibility acquires its flow owner before attaching or reviving a native track. Attachment failure rolls back a new owner. A failed `remove_track` leaves the lane in a non-reusable failure state that retains the exact track and flow owner. Lane suspension, resume, and finalization are explicit events. No grace timer exists.

## 9. Endpoint Auth boundary

`DataChannelOpen` proves that the exact connector has a working channel eligible for Endpoint Auth. It does not prove endpoint identity, transcript validity, bilateral application admission, reachability, or session authority.

The exact candidate becomes `ConnectedChannelCapability`, which moves into `EndpointAuthTask`. Arc 03 proves only this provenance handoff. Endpoint Auth transcript verification and `AuthenticatedChannelCapability` production belong to Arc 04.

`ConnectorRealtimeFlowCapability` is temporary compatibility authority for the existing WebRTC media adapter. It is exact to one connector and requires the provenance of that connector's Endpoint Auth task before issue. It is not the final application flow contract.

## 10. LegacyV1 boundary

Historical application routing and ordinary-member relay are compiled only with the `legacy-v1` feature. Their source lives under `legacy_v1/`. The feature exposes deprecated `LegacyV1Runtime` and `LegacyV1Network` facades plus an explicit `myownmesh serve --legacy-v1` option. Compatibility callers must name the `legacy_v1` module explicitly because the crate root does not re-export those facades. The normal V4 daemon path does not enable them.

Explicit LegacyV1 daemon mode installs one routing facade per joined Mesh. When legacy member-relay hosting is enabled, it also installs one separate `RelayService` per joined Mesh. Routed compatibility frames use the typed `__mesh_route__/v1` wire. Plain member-relay envelopes use `__mesh_relay__/v1`. Their payload remains opaque except for recognition and rejection of the exact historical routed-wrapper shape. The wire channel selects the owner, so arbitrary application payload fields never infer corrected routing behavior.

Corrected LegacyV1 is not wire-compatible with the historical routed wrapper. A corrected routing participant uses `__mesh_route__/v1`. When the corrected plain-relay owner receives the exact historical wrapper shape on `__mesh_relay__/v1`, it rejects the frame instead of forwarding it as application payload. An older node does not understand the corrected routed wire. Mixed-version routed delivery is therefore unavailable, explicit, and fail-closed. Ordinary plain-relay payloads remain opaque. Malformed corrected routed values are discarded by the typed subscription, which continues to process later valid frames.

This is structural isolation through a feature boundary, a compatibility subtree, explicit construction, deprecation, and CI that denies deprecated use in normal V4 source. It is not a hard type-level proof that no future source edit could call the compatibility facade.

The old roster-member relay advertisement is named `LegacyV1MemberRelay` in source. Its frozen wire tag remains `service:relay` for compatibility. It is not TURN, signaling, or a generic opaque relay.

The retained compatibility evidence consists of a native two-link routing implementation control plus supported deployment startup and owner-installation controls. It is not a full supported-deployment two-hop test. RTM-001 and RTM-002 remain open until downstream users migrate and the compatibility subtree is deleted in its named later arc.

## 11. Daemon and library forms

Supported construction is explicit:

- `embedded::start_connector_capable(config, resource_provider)`;
- `embedded::start_infrastructure_only(config)`;
- feature-gated deprecated `embedded::start_connector_capable_with_legacy_v1(config, resource_provider, runtime)`;
- feature-gated deprecated `embedded::start_connector_capable_with_legacy_media(config, resource_provider, media_profile)`;
- feature-gated deprecated `embedded::start_connector_capable_with_legacy_v1_and_media(config, resource_provider, runtime, media_profile)`;
- feature-gated deprecated `myownmesh serve --legacy-v1`;
- feature-gated deprecated `myownmesh serve --legacy-media`;
- feature-gated deprecated `myownmesh serve --legacy-v1 --legacy-media`.

LegacyV1 and legacy-media are independent compatibility authorities. Selecting `--legacy-media` alone installs the reviewed H.264 and Opus provider without constructing `LegacyV1Runtime`, binding `LegacyV1Network`, or enabling member-relay ownership. The combined form requires both flags. Neither feature implies the other. The command-line media sidecar requires three owner-supplied profile fields: maximum lanes per codec kind, pre-provisioned H.264 lanes, and pre-provisioned Opus lanes. No profile value is inferred. The compatibility media engine registers only H.264 profiles and Opus, never the dependency's broader default codec set.

The temporary compatibility artifact is defined for Linux x86-64, Windows x86-64, and macOS ARM64. CI compiles and runs the retained `legacy-v1` and `legacy-media` controls on those desktop platforms. The default appliance cross-builds remain separate evidence and do not imply compatibility-feature support on musl appliances.

Infrastructure-only startup requires node participation to be disabled. Later node enablement fails without changing runtime state. Normal connector-capable startup is codec-neutral and requires an installed resource provider. It does not require a static Mesh, peer, attempt, queue, or flow count.

The library forms are `Mesh::open_connector_capable`, `Mesh::open_connector_capable_with_identity`, `Mesh::open_infrastructure_only`, and `Mesh::open_infrastructure_only_with_identity`. Ambiguous ownerless network-capable open forms do not exist.

## 12. Mechanical modules

- `runtime/attempt/admission.rs`: attempt admission and promotion
- `runtime/attempt/lifetime.rs`: attempt lifetime and cancellation
- `runtime/attempt/policy.rs`: provider structural constraints, compatibility policy, and optional local ceilings
- `runtime/attempt/resource_owner.rs`: process provider, hierarchical lease attribution, and cleanup ownership
- `transport/webrtc/policy.rs`: WebRTC candidate and temporary provider policy
- `transport/webrtc/callback.rs`: callback classes, operation fence, and scheduler
- `transport/webrtc/realtime.rs`: flow queues and connector-owned byte leases
- `transport/webrtc/cleanup.rs`: native close and conservative retention
- `transport/webrtc/media.rs`: temporary H.264 and Opus adapter
- `transport/webrtc/h264.rs`: structurally bounded H.264 assembly
- `legacy_v1/`: frozen application routing and ordinary-member relay compatibility

`PeerSession` does not implement `Deref`. Production native connector creation stays behind `WebRtcConnectorWorker`.

## 13. Arc 03 completion contract

The accepted connector head proves these six statements, which the elastic correction must preserve:

1. Channel-open and channel-close transitions cannot be lost.
2. Cleanup failure retains the exact claim even when cleanup owns the final strong reference.
3. Local and remote ICE restart are transactional, exact to WebRTC ICE credentials, and cannot mix old candidate-attempt work with the replacement attempt.
4. Every pre-authentication native WebRTC callback surface has a structural bound and an explicit overload or violation result.
5. Generic real-time policy selects no codec, device purpose, media purpose, or lane meaning.
6. Temporary LegacyV1 and H.264 or Opus paths are explicit, independently selectable, tested, and unreachable from the V4 authority path without their own named compatibility feature and owner.

These statements prove one lease-backed WebRTC connector candidate produces at most one working-channel capability, cannot outlive its actual connector lifecycle, cannot lose or manufacture resource ownership, and can be handed to Endpoint Auth with exact provenance. Arc 03 may close only when the exact head additionally proves that semantic cardinality remains open, child scopes cannot multiply the process grant, and every protected connector allocation and scheduled operation retains a finite lease. These statements do not prove Endpoint Auth transcript verification or session authority.

## 14. Evidence and approval boundary

The red-team record names the required ownership and pressure controls. [`scripts/measure-v4-arc03g.ps1`](../../scripts/measure-v4-arc03g.ps1) remains useful for performance, provider-cost, fairness, regression, and opaque-allocation characterization. Measurements do not establish a universal product-object ceiling.

The historical Arc 01 inventory remains provenance for its recorded commit. It is not current evidence for this branch. [`arc-03-ownership-delta.json`](arc-03-ownership-delta.json) records the Arc 03 owner changes without rewriting the historical assignments. [`ARC-03-RESOURCE-OWNERSHIP-REPORT.md`](ARC-03-RESOURCE-OWNERSHIP-REPORT.md) records the current-to-target policy map, lease points, pressure behavior, exactness, and native residuals.

Arc 03 remains unapproved until the elastic resource controls and accepted Arc 03 controls pass formatting, workspace checks, Clippy, tests, compiler-boundary checks, native direct and TURN controls, local and remote restart controls, retained-feature controls, the supported-platform matrix, and the cross-target matrix on the exact pushed head.

Arc 03J does not claim complete hostile-ingress admission, exact native dependency memory accounting, Endpoint Auth verification, authenticated session authority, final application flow authority, final codec policy, repository-wide close fencing, or LegacyV1 removal.
