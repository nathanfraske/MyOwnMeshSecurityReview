# Arc 03 resource ownership report

Status: normative target and current-to-target map for the elastic resource correction. The connector behavior at `8a2351d` remains accepted. Its static resource policy does not yet satisfy this report.

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
    -> work-conserving Mesh child scopes
    -> attempt and connector owners
    -> callback, cleanup, candidate, and real-time descendants
```

Creating a Mesh scope does not create capacity. Unused capacity is borrowable under the basal provider. Optional local policy may impose stricter isolation or cardinality ceilings without becoming basal semantics.

## 2. Limit classes

| Class | Meaning | Basal effect |
| --- | --- | --- |
| Protocol-shape bound | Canonical parser or wire validity | Invalid input is rejected |
| Provider structural limit | Actual transport, codec, kernel, hardware, or dependency constraint | Provider reports unsupported or unavailable |
| Runtime resource availability | Current memory, handles, sockets, tasks, storage, and work grant | Provider grants a lease or returns typed pressure |
| Optional local policy ceiling | Explicit administrator, Closed, cost, appliance, test, or compatibility restriction | Wrapper may refuse a claim the provider could otherwise grant |

No class may silently stand in for another.

## 3. Current-to-target static policy map

| Current Arc 03 field | Target disposition | Reason |
| --- | --- | --- |
| Process maximum connector candidates | Remove from basal construction | Connector count emerges from composite claims and process availability |
| Per-Mesh maximum connector candidates | Remove from basal construction | Mesh scopes share the process grant and use work-conserving fairness |
| Cleanup queue capacity derived from connector count | Replace with connector-reserved cleanup work | Cleanup must remain admissible under pressure |
| Remote candidate unique-item count | Replace with queue-storage, accounted-memory, and work leases; allow an optional local ceiling | An item count is not transport-independent resource truth |
| Remote candidate content bytes | Retain as a claim source, not a universal ceiling | Visible content contributes to conservative memory and queue claims |
| Duplicate candidate submissions | Replace with scheduled parsing and hash work leases; allow an optional local ceiling | Repeated work consumes work capacity, not product cardinality |
| Native candidate application work | Replace with scheduled-work and native-operation leases | Admission follows actual work capacity |
| Control callback mailbox items | Replace with per-entry bytes and scheduled-work leases | Queue growth remains owned without a universal count |
| Endpoint-data callback mailbox items | Replace with per-entry bytes and scheduled-work leases plus typed backpressure | Reliable endpoint pressure is byte and work based |
| Control and endpoint scheduler weights | Remove as mandatory inputs | Basal scheduling is structurally fair and work-conserving |
| Real-time scheduler weight | Remove as a mandatory input | Optional application or provider policy may refine fairness later |
| Maximum complete real-time unit bytes | Provider structural limit or later application flow contract | It is not a basal session cardinality |
| Inbound and outbound active-flow counts | Replace with per-flow composite leases | Flow count emerges from resource cost |
| Complete-unit queue items per flow | Replace with per-unit storage and work leases plus provider pressure semantics | Interactive flow policy is provider or application specific |
| Inbound fragment bytes | Retain only when proven as a provider or compatibility parser limit; otherwise claim actual bytes | Shape validity and resource availability are distinct |
| Fragments per unit | Retain only as a provider or compatibility structural limit | The temporary H.264 adapter has a proven fixed hard stop |
| In-progress units per flow | Replace with storage and work leases; optional local ceiling permitted | Simultaneous unit count is not basal cardinality |
| Cumulative pre-authentication RTP packets | Replace with scheduled-work leases; compatibility or local policy may add a ceiling | Time and current product media shape cannot define basal correctness |
| Cumulative pre-authentication RTP content bytes | Replace with accounted-memory and work leases | The provider controls actual live resource use |
| Inbound and outbound accounted-byte ceilings | Replace with provider byte claims and separate ownership domains | Actual byte use remains a resource dimension |
| Legacy lanes per codec kind | Retain in the temporary compatibility adapter | It is a fixed identity and provider shape, not basal MyOwnMesh |
| Pre-provisioned H.264 and Opus lanes | Retain in the temporary compatibility adapter | Explicit compatibility deployment choice |

The terminal candidate-attempt, lifecycle, cleanup, close, restart, codec-neutrality, and compatibility authority semantics remain unchanged. A provider refusal retires the exact speculative attempt where the accepted Arc 03 owner already requires terminal refusal.

## 4. Resource ownership matrix

| Resource dimension | Claim source | Lease owner | Admission point | Release point | Pressure behavior | Reclaimability | Exactness or residual | Structural limit | Optional local hook |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Accounted memory | Owned Rust values and conservative visible capacity | Exact object owner | Before protected allocation or retention | Final owned drop or explicit transfer | Typed pressure | Speculative state only when its owner contract permits | Exact for declared claim, allocator overhead residual | None basal | Byte ceiling or isolation wrapper |
| Queued bytes | Candidate, callback, endpoint, or complete-unit content | Queue entry or payload lease | Before insertion | Final consumer drop or drain | Backpressure, typed refusal, or connector failure by operation contract | Speculative entries may be dropped by contract | Exact content, container and allocator residual recorded separately | Provider queue primitive if proven | Queue or cost policy |
| Socket or handle | Socket, file, event, or provider handle request | Connector or storage owner | Before or atomically with native acquisition | Proven native close | Typed unavailable or pressure | Only through provider close semantics | OS allocation may be isolatable but not exactly observable in process | OS or provider limit | Job, cgroup, rlimit, or administrator guard |
| Native transport object | Peer connection, ICE agent, relay allocation, transceiver, track | Connector cleanup owner | Before construction | Proven native cleanup; failed cleanup retains claim | Typed unavailable; cleanup remains protected | Not reclaimable while native ownership is unresolved | Conservatively claimable with opaque dependency residual | WebRTC or provider shape | Provider isolation wrapper |
| Worker or task | Construction, connector worker, cleanup worker | Exact lifecycle owner | Before spawn | Join, cancellation completion, or terminal cleanup | Typed pressure | Speculative work may be cancelled through its owner | Task count exact; runtime internals residual | Runtime structural limits if documented | Priority or isolation policy |
| Callback or scheduled work | Candidate parse, hash, native application, callback dispatch | Exact attempt, connector, or flow owner | Before enqueue or execution | Completion, drain, or retirement | Backpressure or typed refusal | Speculative work may be refused before admitted work | Work unit exact, CPU cost observed or conservative | None basal | Work budget or cost policy |
| Storage bytes and objects | Durable fact, delayed spool, removable-media object | Store or delayed-delivery owner | Before retention | Deletion or transfer | Typed storage pressure | Policy and semantic owner determine reclamation | Provider-reported allocation; filesystem overhead residual | Filesystem or device limit | Quota or appliance policy |
| Relay or provider allocation | TURN, future opaque relay, provider-native reservation | Exact connector or relay owner | Before or atomically with provider allocation | Proven release | Typed provider unavailable or cost pressure | Provider contract only | Provider-reported, external residual explicit | Exact endpoint-pair or provider limit | Carrier cost policy |
| Parsing or CPU work | Canonical parse, candidate validation, hashing, codec assembly | Exact input or flow owner | Before protected work | Work completion | Backpressure or typed work pressure | Pending speculative work may be refused | Work permits exact; CPU cost observational unless isolated | Protocol parser shape | CPU or ingress policy |
| Opaque dependency residual | Unreported webrtc-rs, runtime, allocator, kernel, driver, or codec state | Narrow connector or process isolation owner | Before dependency use through conservative guard | Proven dependency teardown | Typed unavailable where enforceable; otherwise explicit residual | Isolation-domain termination only when permitted | Conservatively claimable, isolatable, observable only, or unobservable | Dependency-specific | Process or job isolation |

## 5. Pressure and fairness

The process provider checks the composite claim before admission. Child scopes do not receive fixed shares by default. Scheduling is work-conserving, gives each admitted class a bounded service opportunity, and permits unused capacity to be borrowed.

Cleanup and exact release work has reserved execution ownership. Already admitted and higher-authority work is protected from new unauthenticated speculative work. Resource refusal is an availability result and never an Open or Closed authorization denial.

One large claim may consume more capacity than many small claims. Tests must compare resource quantities, not object counts.

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

The implementation must prove:

- no basal `MAX_MESHES`, `MAX_PEERS`, `MAX_ATTEMPTS`, or `MAX_FLOWS`;
- one more object is admitted whenever the mock provider grants its claim;
- refusal names a resource dimension rather than an object count;
- one large claim may cost more than many small claims;
- many small peers or flows coexist while resources remain;
- more Mesh scopes do not multiply the process grant;
- exact lease release restores capacity;
- unused capacity is borrowable under the basal provider;
- an optional local ceiling can deliberately restrict a deployment;
- speculative work is reclaimed or refused before cleanup or admitted higher-authority work is starved;
- slow work retains its finite lease without time-derived expiry;
- storage-backed work consumes storage leases;
- no hidden default cardinality exists.

The accepted lifecycle, cleanup, malformed-candidate, restart, direct WebRTC, TURN-selected, compiler-boundary, and compatibility controls remain required.

## 8. Measurements

Measurements remain useful for performance characterization, provider-cost estimation, regression detection, fairness validation, opaque-allocation discovery, and choosing optional deployment policy. They do not define universal correctness or product cardinality.

For every run, retain the exact commit, platform and target, input workload, raw logs, failures, CPU and RSS observations, queue occupancy, service delay, candidate distribution, close result, and every sample. Do not infer a production ceiling from those observations.
