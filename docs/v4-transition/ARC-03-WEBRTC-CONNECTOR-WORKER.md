# V4 Arc 03 WebRTC connector ownership

Status: Arc 03I correction on `arc/03i-final-connector-boundary` in draft fork PR #5. Fork PR #4 was closed without merge as a superseded Arc 03G record. Arc 03I is not merge-approved. Arc 04 has not started.

## 1. Scope

Arc 03 puts the existing WebRTC connector behind explicit process, Mesh runtime, attempt, candidate, callback, cleanup, and Endpoint Auth provenance owners. It preserves the existing ICE, STUN, TURN, DTLS, direct path, native RTP, mDNS, Nostr, reconnect, and recovery implementations. H.264 and Opus remain in a temporary compatibility adapter, not in basal connector semantics.

This arc does not add route identities, durable connector records, path generations, pair permissions, authentication before pathfinding, Endpoint Auth transcript verification, authenticated session authority, final application flow policy, or final codec policy. It does not add Arc 03 responsibilities to `PeerStateData`, `NetworkCmd`, or `NetworkState`.

Endpoint payload uses an endpoint WebRTC session. TURN may be its selected ICE carrier. Signaling never carries endpoint payload.

## 2. Cardinality and authority

```text
one ProcessResourceRoot
    -> one process connector resource owner
    -> one child scope for each live Mesh runtime

one Mesh connector child scope
    -> one owner-selected candidate ceiling
    -> no implicit borrowing from another Mesh scope

one connection attempt
    -> multiple connector candidates

one WebRTC connector candidate
    -> one RTCPeerConnection and ICE agent
    -> multiple internal ICE candidates and pairs

DataChannelOpen from the exact live connector
    -> ConnectedChannelCapability
    -> EndpointAuthTask owns connected-channel provenance
```

`ConnectorCandidateCapability` represents one connector candidate, not one trickled `LocalIceCandidate`. The attempt defines its structural claim but cannot manufacture capacity. Admission updates the process aggregate and the exact Mesh child under one mutex. External code cannot construct either resource owner.

## 3. Owner-selected policy

The public connector policy has no `Default`. A connector-capable owner supplies:

- process and per-Mesh candidate ceilings;
- cumulative remote-candidate item, content-byte, duplicate, and application-work ceilings for one ICE attempt;
- control and endpoint-data mailbox capacities;
- control and endpoint-data scheduler weights;
- disabled or enabled codec-neutral real-time ownership;
- when real-time is enabled, its scheduler weight, inbound and outbound flow counts, per-flow queue count, structural unit limits, cumulative pre-promotion packet and content-byte limits, and independent inbound and outbound byte ceilings.

There is no third real-time total policy. Inbound and outbound are hard partitions with no borrowing. No native-close timeout exists. No elapsed duration changes resource, protocol, authentication, lane, or cleanup truth.

Generic real-time enablement creates no H.264 or Opus tracks by itself. The temporary adapter requires an explicit `LegacyWebRtcMediaProfile`. Profile construction validates its fixed lane identity space and pre-provisioned lane counts. Policy attachment validates outbound flow capacity and the adapter's fixed 2,048-fragment H.264 ceiling.

No production value is selected by Arc 03. The daemon requires every operational value from its owner.

## 4. Reserve before allocation and retention

Production connector construction follows this order:

```text
request exact Mesh child capacity
    -> atomically reserve process and Mesh claims
    -> create one cleanup owner
    -> start owned asynchronous construction
    -> allocate RTCPeerConnection
    -> attach it to the cleanup owner
    -> install callbacks and connector state
    -> recheck attempt liveness
    -> publish the worker or start cleanup
```

Cancellation after native allocation, cancellation after result delivery, runtime shutdown, and construction failure all reach the same close owner. Raw `Transport::open_peer*` construction is limited to tests and the `transport-lab` feature.

Remote candidates use one cumulative envelope before and after remote SDP. A unique candidate consumes one item and its candidate content bytes. The content quantity covers the candidate string, optional identifiers, and optional media-line index. Duplicate identity uses tagged, length-delimited fields so field boundaries cannot be confused by embedded delimiter bytes. The content quantity does not claim allocator or native retained memory. Duplicate and application-work counts are independent. The envelope renews only for a new connector attempt or an explicit successful ICE restart.

Candidate observations include visible string capacities and queue container capacity, but remain marked inexact because allocator overhead and storage inside webrtc-rs are not observable.

Each queued or applying remote candidate carries a process-local `RemoteCandidateAttemptIdentity`. An explicit ICE restart retires the old identity, blocks new work through it, waits for already admitted work to leave, creates a fresh identity and cumulative envelope, and keeps replacement candidates queued until replacement SDP commits. This identity is not serialized and is not a route, generation, ledger fact, timestamp, or timer.

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

## 6. Callback producer and scheduler bounds

Control and endpoint data have separate bounded mailboxes. Producers use nonblocking insertion and receive a typed overloaded, closed, policy-refused, or wrong-owner result. There is no `reserve().await` producer backlog and no connector callback queue outside those mailboxes.

Real-time events cannot enter a shared callback mailbox. Each admitted real-time flow owns its own bounded queue. Weighted scheduling gives every ready callback class and every ready flow a bounded service opportunity. The weights remain owner inputs.

Endpoint protocol data may arrive before channel-open promotion, but it remains in the bounded endpoint mailbox until the exact open transition commits. Close or replacement drops the uncommitted data.

The admitted native callback shape is also finite. A data-only connector accepts one application data channel and no media tracks. The temporary legacy provider accepts that same one data channel plus only the exact H.264 and Opus tracks named by its profile. Duplicate channels, unexpected channels, wrong codecs, malformed identities, and excess tracks coalesce into one connector violation and retirement. They do not create one cleanup future per violation.

## 7. Cleanup ownership and diagnostics

One `ConnectorCloseOwner` owns every private, delivered, cancelled, installed, and partially constructed native connector result. Close disables real-time delivery, commits the operation fence, retires callback identity, drains connector-owned queues, waits for earlier fenced operations, and then calls the native close owner.

One bounded process cleanup executor runs close futures. Its queue capacity is validated when the process connector policy is constructed and equals the process candidate ceiling. It does not create a runtime or OS thread per close.

- A successful native close releases the exact candidate and connected claims.
- A returned native-close error retains that connector's exact claims and records `Failed`.
- A cleanup future panic or executor failure invokes the exact owner's failure callback.
- Cleanup health reports queue capacity, queued jobs, active jobs, completed jobs, failed jobs, and executor failure.
- A caller cancellation does not cancel owner cleanup.
- There is no close timeout. A dependency that never returns remains visibly `Closing` and keeps its finite claim.

The failure callback owns a strong reference to the close owner. Dropping every external close-owner reference cannot discard the exact failed claim, its terminal diagnostic, or its process and Mesh attribution.

## 8. Real-time compatibility bounds

The codec-neutral owner separates speculative inbound quarantine from authorized outbound compatibility flows. Connector-owned byte and in-progress counters are split by domain. If a domain's arithmetic becomes unprovable, that domain is charged to its full ceiling and refuses later admission. This proves conservative behavior for connector-owned accounting only. It does not claim complete accounting for allocations hidden inside native WebRTC dependencies.

Each inbound provider flow is bounded by fragment bytes, fragment count, unit bytes, simultaneous units, a per-flow queue, an inbound byte ceiling, and a cumulative pre-promotion packet and content-byte envelope. Exhausting the pre-promotion envelope stops that speculative transceiver. There is no timer or rate window.

Generic real-time ownership does not install a codec provider or register compatibility codecs. Codec registration is lazy and occurs only when constructing a connector whose explicit temporary legacy profile requires it. An inbound transceiver without an explicit provider is stopped. The temporary legacy provider accepts only H.264 video and Opus audio with exact, in-range `video-N` or `audio-N` track identity. Lane numbers must use their canonical unsigned decimal spelling.

Complete units use deterministic `DropNewest`. Their byte lease follows the queued event and downstream copies. Dequeue alone does not release it.

Outbound compatibility acquires its flow owner before attaching or reviving a native track. Attachment failure rolls back a new owner. A failed `remove_track` leaves the lane in a non-reusable failure state that retains the exact track and flow owner. Lane suspension, resume, and finalization are explicit events. No grace timer exists.

## 9. Endpoint Auth boundary

`DataChannelOpen` proves that the exact connector has a working channel eligible for Endpoint Auth. It does not prove endpoint identity, transcript validity, bilateral application admission, reachability, or session authority.

The exact candidate becomes `ConnectedChannelCapability`, which moves into `EndpointAuthTask`. Arc 03 proves only this provenance handoff. Endpoint Auth transcript verification and `AuthenticatedChannelCapability` production belong to Arc 04.

`ConnectorRealtimeFlowCapability` is temporary compatibility authority for the existing WebRTC media adapter. It is exact to one connector and requires the provenance of that connector's Endpoint Auth task before issue. It is not the final application flow contract.

## 10. LegacyV1 boundary

Historical application routing and ordinary-member relay are compiled only with the `legacy-v1` feature. Their source lives under `legacy_v1/`. The feature exposes deprecated `LegacyV1Runtime` and `LegacyV1Network` facades plus an explicit `myownmesh serve --legacy-v1` option. Compatibility callers must name the `legacy_v1` module explicitly because the crate root does not re-export those facades. The normal V4 daemon path does not enable them.

Explicit LegacyV1 daemon mode installs one routing facade per joined Mesh. When legacy member-relay hosting is enabled, it also installs one separate `RelayService` per joined Mesh. Routing wrappers and plain relay envelopes share the frozen reserved wire channel, but they have different semantic owners. The routing owner ignores plain relay envelopes, and the member relay ignores routing wrappers. A malformed envelope is discarded without terminating either owner.

This is structural isolation through a feature boundary, a compatibility subtree, explicit construction, deprecation, and CI that denies deprecated use in normal V4 source. It is not a hard type-level proof that no future source edit could call the compatibility facade.

The old roster-member relay advertisement is named `LegacyV1MemberRelay` in source. Its frozen wire tag remains `service:relay` for compatibility. It is not TURN, signaling, or a generic opaque relay.

The retained compatibility path has a native two-link payload control. RTM-001 and RTM-002 remain open until downstream users migrate and the compatibility subtree is deleted in its named later arc.

## 11. Daemon and library forms

Supported construction is explicit:

- `embedded::start_connector_capable(config, policy)`;
- `embedded::start_infrastructure_only(config)`;
- feature-gated deprecated `embedded::start_connector_capable_with_legacy_v1(config, policy, runtime)`;
- feature-gated deprecated `embedded::start_connector_capable_with_legacy_media(config, policy, media_profile)`;
- feature-gated deprecated `myownmesh serve --legacy-v1`.

Infrastructure-only startup requires node participation to be disabled. Later node enablement fails without changing runtime state. Normal connector-capable startup is codec-neutral and rejects missing, zero, invalid, or inconsistent owner values before joining.

The library forms are `Mesh::open_connector_capable`, `Mesh::open_connector_capable_with_identity`, `Mesh::open_infrastructure_only`, and `Mesh::open_infrastructure_only_with_identity`. Ambiguous ownerless network-capable open forms do not exist.

## 12. Mechanical modules

- `runtime/attempt/admission.rs`: attempt admission and promotion
- `runtime/attempt/lifetime.rs`: attempt lifetime and cancellation
- `runtime/attempt/policy.rs`: owner-selected policy types and validation
- `runtime/attempt/resource_owner.rs`: process and Mesh accounting plus cleanup executor
- `transport/webrtc/policy.rs`: WebRTC candidate and temporary provider policy
- `transport/webrtc/callback.rs`: callback classes, operation fence, and scheduler
- `transport/webrtc/realtime.rs`: flow queues and connector-owned byte leases
- `transport/webrtc/cleanup.rs`: native close and conservative retention
- `transport/webrtc/media.rs`: temporary H.264 and Opus adapter
- `transport/webrtc/h264.rs`: structurally bounded H.264 assembly
- `legacy_v1/`: frozen application routing and ordinary-member relay compatibility

`PeerSession` does not implement `Deref`. Production native connector creation stays behind `WebRtcConnectorWorker`.

## 13. Arc 03I completion contract

Arc 03I may be called code-complete only when the exact pushed head proves all six statements:

1. Channel-open and channel-close transitions cannot be lost.
2. Cleanup failure retains the exact claim even when cleanup owns the final strong reference.
3. ICE restart cannot mix old candidate-attempt work with the replacement attempt.
4. Every pre-authentication native WebRTC callback surface has a structural bound and an explicit overload or violation result.
5. Generic real-time policy selects no codec, device purpose, media purpose, or lane meaning.
6. Temporary LegacyV1 and H.264 or Opus paths are explicit, frozen, tested, and unreachable from the V4 authority path without their named compatibility feature and owner.

These statements prove one bounded WebRTC connector candidate produces at most one working-channel capability, cannot outlive its actual connector lifecycle, cannot lose or manufacture resource ownership, and can be handed to Endpoint Auth with exact provenance. They do not prove Endpoint Auth transcript verification or session authority.

## 14. Evidence and approval boundary

The red-team record and [`scripts/measure-v4-arc03g.ps1`](../../scripts/measure-v4-arc03g.ps1) name the controls and measurement inputs. Measurements are observations only and do not select production policy values.

The historical Arc 01 inventory is not current evidence for this branch. Its checker reports 117 production Rust units and 2,099 declaration members against 106 and 1,792 recorded, plus obsolete module paths and markers. A later reviewed inventory refresh must assign that drift. Arc 03I does not silently rewrite those owner assignments.

Arc 03I remains unapproved until the exact pushed head passes formatting, workspace checks, Clippy, tests, compiler-boundary checks, native direct and TURN controls, retained-feature controls, the supported-platform matrix, the cross-target matrix, workload measurements, and owner review.

Arc 03I does not claim complete hostile-ingress admission, exact native dependency memory accounting, Endpoint Auth verification, authenticated session authority, final application flow authority, final codec policy, repository-wide close fencing, or LegacyV1 removal.
