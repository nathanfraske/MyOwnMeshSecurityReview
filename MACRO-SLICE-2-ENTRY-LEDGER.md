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

Because this ledger cannot be deleted with an open residual, this entry
proposes treating all three residuals as Macro-slice 2 exit conditions. That is
stricter than merely carrying the first two to an unspecified later owner. The
operator must accept or amend that commitment at this entry review before
source implementation begins.

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
