# Macro-slice 2 entry ledger

Opened from the fork `main` merge commit
`c79ea09cc577bfb3953cf532b2dd555229f7e12c`. Macro-slice 1 exit review:
[4945363089](https://github.com/nathanfraske/MyOwnMeshSecurityReview/pull/6#pullrequestreview-4945363089).

This is a transition artifact, not an architecture source of truth. It records
what Macro-slice 2 inherited, the owner of each residual, and the bounded unit
currently admitted to implementation. It must be deleted at the Repository
Closure and Nodularity Gate in `TRANSITION-PLAYBOOK.md` section 7.3, which
permits no surviving evidence dossier. A residual is discharged here only by
naming the exact commit and the control that closes it. No residual may remain
open when this file is deleted; an open residual at the 7.3 gate is a stop
condition, not permission to delete the record.

## Accepted residuals

Because this ledger cannot be deleted with an open residual, every residual
recorded here is a Macro-slice 2 exit condition. That is stricter than carrying
any of them to an unspecified later owner.

**R1, R2 and R3 accepted 2026-08-16** by the operator, in the directive that
opened PR #7 and authorized the first bounded unit. Acceptance fixes the
commitment; it discharges nothing. Each residual below stays open until the
discharge record at the end of this file names the exact closing commit and
control, and an open residual at the 7.3 gate remains a stop condition rather
than permission to delete the record.

**R4 was not part of that acceptance and is not claimed to be.** It is a
pre-existing defect the first bounded unit found while proving its own
boundary, recorded here on the same terms so it cannot be lost, and awaiting the
owner's decision on whether it carries the same exit-condition commitment as the
first three.

### R1 — `STORE_LOCK` is process-local

Custody-store mutations are serialized by a process-wide mutex with no file
lock. The deployment invariant is one writable MyOwnMesh daemon per state
directory; two daemons sharing one secrets directory are outside the current
guarantee.

Owner: the Macro-slice 2 durable-store work. This is not discharged by adding a
custody-only file lock.

Status: open.

### R2 — hard process death can strand a provisional enrollment

An MFA enrollment is installed before its response is written and is
rollback-owned until `Wrote::Sent`. Armed `Drop` covers normal unwind,
cancellation, and I/O failure, not SIGKILL or power loss. A process death
between the atomic save and the write can leave a lock whose secret and
recovery codes were never delivered.

Owner: the Macro-slice 2 durable-state work. The target is durable provisional
recovery, not a retry protocol or custody transaction framework.

Status: open.

### R3 — an offline evicted Device has no durable proof delivery

Current members refuse an evicted Device and cannot re-admit it: the signed
eviction converges among current members, `log_evicted` is true, the roster
mirror removes it, and `current_policy_admits` returns false so auto-approve
cannot fire. What remains is the Device's own stand-down. That currently rides
B3's single best-effort denial frame: one attempt, followed by dropping the
exact peer when the attempt returns, with no receipt, retry, acknowledgement,
or timer by design.

Deferred control, retained under `--ignored` with its body and 20-second budget
unchanged:
`crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down`.

Owner: the typed durable-semantic Signaling Node lane together with the
Macro-slice 2 semantic proof work. The lane boundary is the first dependency,
and this is the first residual targeted after that boundary exists.

Status: open.

### R4 — driver-side pre-normalization attributes a departure to the named device

**Pre-existing. The first bounded unit discovered and documented this while
proving its own boundary; it neither introduced it nor fixed it.** Unit 1 added
the lane boundary's `from`-over-`peer_id` rule and then had to establish which
carriers that rule actually governs, which is what surfaced the gap upstream of
it.

Both network drivers normalize `SignalingMessage::Announce` and
`SignalingMessage::Leave` into their own presence and withdrawal reports before
the lane boundary sees them, and take the body-supplied `peer_id` while doing
so:

- `crates/myownmesh-signaling/src/mdns/driver.rs` — leave takes the body
  `peer_id`, though announce alongside it takes `frame.from`;
- `crates/myownmesh-signaling/src/nostr/driver.rs` — both announce and leave
  take the body `peer_id`, and neither is checked against the relay event's
  pubkey.

The match in each driver is on the message kind rather than on
directed-versus-broadcast, so a directed frame is normalized the same way.
`LocalBroker` is unaffected: it stamps the sending peer handle's registered id,
which the sender cannot choose.

**Exact reachable effect.** A hostile peer on Nostr or mDNS can publish a
departure naming a third party's Device ID. That arrives as the driver's own
`PeerLeft`, becomes a carrier withdrawal at the lane boundary, and reaches
`drop_peer` in `engine/mod.rs`, which tears down the receiving device's **live
local session** with the named third party. The victim is then rediscovered and
redialled by the ordinary announce and reconnect paths.

**Exact limit, and it is the reason this is a session-availability defect rather
than an authority one.** The effect stops there. It does not mutate the roster
or membership, does not synthesize a durable leave, does not evict, and mints no
Device authority — the signaling effect union contains no variant that could,
which is asserted by
`a_carrier_withdrawal_has_no_durable_effect_to_produce` in
`engine/signaling_lane.rs` and by
`v4_m2_u1_a_carrier_withdrawal_leaves_the_signed_membership_intact` in
`engine/mod.rs`. Both remain true with this gap open.

See also the achieved-scope subsection under the first bounded unit, which
records the same boundary from the lane's side.

Owner: later Macro-slice 2 signaling-driver work. The repair belongs in the two
drivers — attributing a normalized departure to the authenticated or routed
sender rather than to the body — because it changes what each driver reports
rather than how a lane classifies. It is not a lane-boundary change and was
deliberately excluded from Unit 1's scope.

Status: open.

## First bounded unit — typed signaling lanes

Classify signaling at the Signaling Node boundary into typed
**durable-semantic** and **ephemeral-transport** lanes, retaining bounded carrier
provenance. Classification happens before domain parsing. Application payload
cannot enter either signaling lane. Neither lane may turn carrier identity into
Device authority, and a carrier withdrawal on either lane cannot synthesize a
durable leave.

This unit creates the typed boundary only. It does not implement anti-entropy,
deliver an eviction proof, change B3, add a timer, poll, retry, terminal
acknowledgement, or start relay and durable-store work. Those semantics require
a later bounded unit after this boundary is accepted.

Required evidence follows the playbook rather than inventing a parallel gate:

- compile-time or visibility controls prove signaling cannot deliver
  application data;
- the classifier is an exhaustive match over the typed signaling input with no
  wildcard arm, so a new variant cannot compile until its lane is chosen;
- negative controls prove that a carrier-supplied identity on either lane mints
  no Device authority, and that a carrier withdrawal produces no durable leave
  or roster mutation;
- deterministic carrier controls exercise duplicate and out-of-order delivery
  through the lane boundary for the existing LocalBroker, Nostr, and mDNS
  adapters;
- measurements cover time to first hint and first candidate, while remaining
  characterization rather than correctness evidence or a capacity source.

Stop and return to owner review if the lane cannot be assigned to the Signaling
Node without changing product semantics, or if a compatibility adapter would
need permanent product behavior.

### Achieved scope of the identity and withdrawal guarantees

Recorded here because the requirement above is wider than what a lane boundary
alone can deliver, and the difference must not be discovered later from a
control that reads stronger than it is.

**Holds on every carrier.** No signaling effect grants, revokes, or records
membership: the effect union contains no such variant, so neither a
carrier-supplied `from` nor a body-supplied `peer_id` can mint Device authority,
and a carrier withdrawal cannot synthesize a durable leave or mutate the roster.
This is structural rather than asserted per carrier.

**Holds only for values that reach the boundary's directed parse.** The rule
that the routing `from` outranks a body-claimed `peer_id` governs
`parse_directed`. Offer, answer, and candidate reach it from all three carriers.
Announce and leave reach it from `LocalBroker` alone: the Nostr and mDNS drivers
normalize both variants into their own presence and withdrawal reports first,
and take the body `peer_id` while doing so — mDNS for leave, Nostr for both. So
for those two carriers a hostile departure naming a third party is still
attributed to the named device upstream of the lane boundary.

**Carrier attribution is not authenticated on a network carrier.** `LocalBroker`
stamps the sending peer handle's registered id, which the sender cannot choose.
Nostr and mDNS supply a decoded envelope field that is never checked against the
relay event's pubkey or the wire source, so preferring it over `peer_id` buys
consistency, not proof.

Correcting the driver-side pre-normalization is later signaling-driver work. It
changes what each driver reports rather than how a lane classifies, so it was
deliberately excluded from this unit and is not a discharge of any residual. It
is tracked as **R4** above, with its exact reachable effect and its limit.

## Scope ceiling

No repository-wide discovery pass, downstream consumer migration, custody-only
file-lock subsystem, generic transaction framework, route identity, route
ledger, path generation, or application-domain work is admitted by this entry.
No work in AllMyStuff, CEC Support, or another repository is part of this
slice.

Before this ledger is deleted, the canonical documents must describe the
contract that actually remains. Exact closing commits, controls, and PR records
remain the durable evidence for each discharge; this table is an index to that
evidence, not its sole copy.

## Discharge record

| Residual | Discharged at | Closing control |
| --- | --- | --- |
| R1 | — | — |
| R2 | — | — |
| R3 | — | — |
| R4 | — | — |
