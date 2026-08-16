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

**Pre-existing. Discovered while proving the ingress boundary; neither
introduced nor, at that point, fixed by it.** Both network drivers normalized
`SignalingMessage::Announce` and `SignalingMessage::Leave` into their own
presence and withdrawal reports before the boundary saw them, taking the
body-supplied `peer_id` while doing so — mDNS for leave, Nostr for both. A
hostile peer could therefore publish a departure naming a third party's Device
ID, and it reached `drop_peer` as that third party's, tearing down the receiving
device's live local session with them.

**Addressed by the signaling + semantic-ingress boundary. The three counts are
not equals, and saying so is the point:**

1. **The report no longer names a third party on mDNS.** `mdns/driver.rs`
   attributes a normalized leave to `frame.from` — the same field its announce
   already used, and the same one its own peer table is keyed on. **Narrows the
   surface; mDNS only.** It does not help on Nostr, where the departure still
   carries the body `peer_id`.
2. **A sender's claim cannot cancel a carrier's observation.**
   `SignalingRuntime` refuses to let a `SenderClaimed` withdrawal clear a
   `CarrierObserved` presence, and delivers no withdrawal at all while another
   attach still observes the device. **Narrows the surface; it does not close
   the effect on a single carrier.** Nostr presence *and* departure are both
   `SenderClaimed`, so on a Nostr-only attach — no mDNS, nothing else observing
   the device — a hostile relay payload naming a third party still withdraws
   what a relay payload claimed, and that withdrawal **is delivered to the
   engine** as a `PeerLeft` for the named third party. This is stated plainly
   because counts 1 and 2 together do not stop it.
3. **The engine barrier: a sender-claimed withdrawal selects no session in any
   state. This is the count that holds on every carrier and closes the
   body-target effect outright.** `PeerLeft` is reachability evidence, and
   `engine/mod.rs` reads *attribution* before liveness. A `SenderClaimed`
   withdrawal is teardown-inert — it retires nothing, whatever state the named
   session is in — so the delivered Nostr withdrawal of count 2 reaches the
   engine and selects nothing. Only a `CarrierObserved` withdrawal may retire a
   session, and only one that is not live; a live session is retired by the
   authenticated `SessionControl::Depart` over that exact session, ordinary
   connector closure, or the heartbeat, and by nothing else.

   **This count was liveness-only when it was first written, and that was
   wrong.** Guarding on `authenticated && data_channel_open` alone left a
   sender-claimed departure able to retire a third party's
   authenticated-but-channel-closed session — a session in recovery, which is
   when it is least able to defend itself. Attribution, not liveness, is what
   makes the body-claimed target inert rather than merely narrowed.

**The guard window, exactly, and it now applies only to `CarrierObserved`.**
"Live" is the conjunction the engine tests: `authenticated && data_channel_open`.
A session that is authenticated but whose data channel is closed — mid-recovery,
or mid-replacement of the transport underneath it — does **not** satisfy it, and
a carrier's *own* observation naming that device can retire it. That is
deliberate and consistent: it is the same predicate
`depart_authenticated_sessions` uses to choose which sessions get an
authenticated goodbye, so the two halves of the lifecycle agree on what a live
session is, and a session with no channel has no channel for a
`SessionControl::Depart` to arrive on either. Nothing a sender writes can aim at
that window, because a sender-claimed hint never reaches the retirement at all.

**Stale-replacement safety.** The retirement takes the peer owner token, reads
liveness through that same token, and retires with `drop_peer_if_current`. A
session installed between the read and the retirement — the reconnect this hint
may well have raced — is not retired by evidence about the one it replaced.
Nothing on this path touches the roster or the member log.

**Control coverage, and the two controls prove different things.**
`a_withdrawal_is_delivered_only_when_nothing_still_observes_the_device` in
`engine/signaling_ingress.rs` proves the **multi-carrier hold**: while any attach
still observes the device, the withdrawal is not delivered at all. It says
nothing about a single-carrier attach, where the withdrawal *is* delivered.
`v4_m2_a_carrier_withdrawal_leaves_a_healthy_authenticated_session_intact` in
`engine/mod.rs` proves what happens to one that **is** delivered, in three
parts: it cannot retire a healthy authenticated session; a sender-claimed one
cannot retire an authenticated session whose channel has closed either; and a
carrier-observed one still can retire that same not-live shape — which is what
makes the control a rule about attribution rather than an arm that has stopped
dropping anything. It keeps its durable assertions throughout: the device stays
a signed member, stays rostered, and stays admissible. Neither control subsumes
the other, and only the second speaks to the Nostr-only case above.

**What remains, and it is not this residual.** On an unauthenticated carrier the
sender attribution is still a field the sender wrote — `frame.from` on mDNS,
`envelope.from` and `peer_id` on Nostr. Nothing in signaling can fix that, and
nothing in signaling needs to: what it can still buy is a cancelled dial attempt
against a device that is not yet a session — which is what a withdrawal is
allowed to mean — and, for a carrier's own observation only, the guard window
above. Endpoint authentication and policy
remain the only things that admit a device, and no signaling effect can grant,
revoke, or record membership.

**The cost of the correction, stated rather than discovered later: Nostr has no
`CarrierObserved` withdrawal path at all.** Every Nostr departure is a decoded
payload — a peer's own `leave`, or an intelligent relay reporting that a peer's
socket closed, both carrying a body-supplied device id that neither the relay nor
the event author is authenticated to. All of them are therefore `SenderClaimed`
and retire nothing. **Prompt carrier-driven session retirement is intentionally
unavailable on a relay-only network**, and exact connector closure, the
authenticated `SessionControl::Depart`, or the heartbeat timeout is the backstop.
That is slower than the relay hint used to be, and it is the price of the hint
not being aimable: a relay report was exactly as forgeable as any other payload.
The other two carriers keep a genuine observed path — mDNS browse expiry and
goodbye, and every `LocalBroker` join and drop, are `CarrierObserved` — so a LAN
peer disappearing is still noticed promptly by the carrier that was watching it.

Status: **discharged at correction commit
`7fb4708d01895269b4aff809857b9d6ffe88d6ad`.** The earlier implementation commit
`0b9b5b2c5be60f8204aa2fef4e14259e5d385611` guarded on liveness alone and was
insufficient: it left a sender-claimed departure able to retire a third party's
authenticated-but-channel-closed session. The correction commit moves
attribution ahead of liveness, makes every sender-claimed withdrawal
teardown-inert, and binds the carrier-observed liveness decision and retirement
to one exact `PeerOwnerToken`. The controls named in the table below are committed
at that exact correction head.

## The Macro-slice 2 signaling and semantic-ingress boundary

Macro-slice 2 lands as **one atomic PR**, not as a sequence of separately
reviewed units. What follows is the boundary that PR establishes; the earlier
"first bounded unit" framing described a review gate this slice does not have.

`engine/signaling_ingress.rs` is the Signaling Node's ephemeral-transport
ingress: the only place a carrier observation is admitted, and the only place it
becomes an engine domain value. Admission happens before domain parsing, bounded
carrier provenance is retained, and the admission is an exhaustive match with no
wildcard arm, so a new carrier variant cannot compile until someone states what
it is — and a variant carrying a durable signed fact has no kind to choose.

**There is no durable-semantic ingress, and none is pretended.** No carrier
variant carries a durable signed fact, so an uninhabited durable arm would have
been a tag whose other value nothing can hold. The distinction `ARCHITECTURE.md`
§4 draws is carried by the type this module produces.

`SignalingRuntime` is the owner on the signaling side. It owns exactly three
things: an opaque process-local `CarrierInstance` minted per attach,
cross-carrier de-duplication, and availability — which attaches currently
observe a device, and on what attribution. It owns no roster decision, no
endpoint identity, and no application delivery.

The semantic-ingress half is the Peer Session lifecycle owner: an authenticated
`SessionControl::Depart` sent over the exact live session, consumed only under
that session's owner, with no target Device ID because the session defines its
endpoints. A carrier withdrawal is reachability evidence and cannot retire a
healthy authenticated session; `announce_leave` may still emit the carrier hint,
but it carries no teardown authority and the fixed departure wait is gone.

Excluded, and still excluded: anti-entropy, proof delivery, B3 changes, timers,
polls, retries, terminal acknowledgements, relay and durable-store work, route
identities, route ledgers, path generations, persistence, application payload in
signaling, downstream migration, and any generic framework.

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
| R4 | `7fb4708d01895269b4aff809857b9d6ffe88d6ad` (supersedes `0b9b5b2c5be60f8204aa2fef4e14259e5d385611`) | `a_withdrawal_is_delivered_only_when_nothing_still_observes_the_device` (multi-carrier hold), `v4_m2_a_carrier_withdrawal_leaves_a_healthy_authenticated_session_intact` (delivered sender-claimed withdrawal retires nothing in any state; carrier-observed still retires a not-live session) |
