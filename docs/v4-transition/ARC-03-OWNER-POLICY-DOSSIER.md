# Arc 03 owner policy dossier

Status: awaiting owner workload selection and owner policy review. This dossier records inputs and raw observations. It does not select or recommend a production value.

## Decision boundary

Arc 03 can prove that every retained resource has an owner and an enforced finite field. Source code and structural tests cannot decide the operational size of those fields. The values must come from workloads the owner identifies as representative, followed by an explicit owner decision.

No Arc 03 policy type implements `Default`. The ordinary daemon, headless daemon, embedded daemon, LegacyV1 daemon, and LegacyV1 media sidecar must receive a complete policy before they can create a connector-capable runtime.

## Required production fields

The connector owner must review all of these fields:

| Scope | Field |
| --- | --- |
| Process | maximum simultaneous connector candidates |
| Mesh runtime | maximum simultaneous connector candidates within that Mesh |
| ICE attempt | unique remote candidate items |
| ICE attempt | remote candidate content bytes |
| ICE attempt | duplicate candidate submissions |
| ICE attempt | remote candidate native-application work |
| Connector | control callback mailbox items |
| Connector | endpoint-data callback mailbox items |
| Scheduler | control service weight |
| Scheduler | endpoint-data service weight |
| Generic real-time, when enabled | real-time service weight |
| Generic real-time, when enabled | maximum complete unit bytes |
| Generic real-time, when enabled | inbound flow count |
| Generic real-time, when enabled | outbound flow count |
| Generic real-time, when enabled | complete-unit queue items per flow |
| Generic real-time, when enabled | inbound fragment bytes |
| Generic real-time, when enabled | fragments per unit |
| Generic real-time, when enabled | simultaneous in-progress units per flow |
| Generic real-time, when enabled | cumulative pre-authentication RTP packets |
| Generic real-time, when enabled | cumulative pre-authentication RTP content bytes |
| Generic real-time, when enabled | inbound accounted bytes |
| Generic real-time, when enabled | outbound accounted bytes |
| Legacy media sidecar | lanes per codec kind |
| Legacy media sidecar | pre-provisioned H.264 lanes |
| Legacy media sidecar | pre-provisioned Opus lanes |

The real-time overflow rule is currently the explicit compatibility rule `DropNewest`. It is not presented as the final application flow policy.

## Required workload inputs

[`scripts/measure-v4-arc03g.ps1`](../../scripts/measure-v4-arc03g.ps1) refuses to invent workload sizes. The owner must provide:

- repetition count for every selected scenario;
- callback samples, simultaneous flows, and payload bytes for callback contention;
- saturated-flow units, latency-sensitive units, and payload bytes for flow fairness;
- simultaneous peers for the multi-peer scenario;
- simultaneous Mesh runtimes and candidates per Mesh for the multi-Mesh scenario;
- candidates per attempt for candidate bursts.

The harness also runs direct, TURN-selected, data-only, H.264, Opus, reconnect, native-close success, and native-close error scenarios. These still require an owner-selected repetition count.

## Raw evidence record

No representative workload vector has been supplied for Arc 03J, so no workload distribution is recorded here yet. Structural unit controls and exact-head CI are separate evidence and must not be presented as operational sizing evidence.

For each owner-selected run, retain:

- exact Git commit;
- platform and target triple;
- scenario and complete input vector;
- every raw test log;
- process CPU time and maximum resident set size from `/usr/bin/time -v`;
- queue occupancy and callback service delay observations;
- candidate content bytes and application-work observations;
- connector concurrency and per-Mesh distribution;
- in-progress real-time bytes and flow queue observations;
- native close duration and result;
- every sample, not only an average.

## Review outcome

Arc 03 cannot be marked production-usable until the owner records a workload vector, reviews the raw distributions, selects every required field, and identifies the deployment forms that use that policy. A selected value belongs in deployment configuration or an owner-reviewed policy source, not in this dossier and not as an inferred code default.
