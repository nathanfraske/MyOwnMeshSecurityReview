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

**R4 was not part of that acceptance and is not claimed to be.** The operator
accepted R1, R2 and R3 on 2026-08-16, and that acceptance was never extended
backwards to cover R4. R4 is a pre-existing defect the first bounded unit found
while proving its own boundary; it was recorded here under the same non-deletion
mechanic so it could not be lost, but on this record's authority rather than the
operator's. **That distinction is preserved for provenance and nothing below
softens it.**

What has changed is the implementation, not the acceptance. R4 was discharged at
`0237f9e02df3ab21131c5612c1b231050c860cc4`, so the open question — whether it
carried the same exit-condition commitment as the first three — no longer has to
be answered by anyone: there is no unresolved R4 choice left at the 7.3 gate. A
discharge is evidence that the defect is closed, and it is not a ratification of
R4 by the operator.

### R1 — durable semantic owner/store

The durable semantic owner is the single writer for one semantic slot. Its
cross-process lease is held for the owner lifetime, its snapshot combines the
canonical fact graph, projection commitment, provisional custody, and proof
records, and publication is atomic. A live replacement cannot open the slot;
after a hard-dead owner the kernel-owned lease is released and the next owner
can reopen and continue from the last complete snapshot.

The closing implementation is the durable-store sequence `f2a0f31` (store),
`d6dd84d` (semantic facts and provisional custody), `1a8285b` (durable proof
outbox), and hardening in `f29207d`, `eaba95b`, and `57ca3c5`, integrated at
`55bafe5`.

Closing controls are
`semantic::store::child_process_contention_and_hard_death_release_the_writer`,
`semantic::store::lifetime_owner_blocks_second_open_then_reopens_for_append`,
`semantic::store::lifetime_owner_preserves_deterministic_graph_and_proof_union`,
`durable_semantic_restart::closed_network_restart_restores_the_committed_semantic_graph`,
and
`durable_semantic_restart::shutdown_fences_stale_state_before_same_slot_reopen_and_append`.
These cover live-owner exclusion, hard-death reopen, graph/custody/proof union,
restart reconstruction, and stale-owner shutdown fencing.

Owner: the Macro-slice 2 durable-store work.

Status: discharged at `55bafe5`.

### R2 — hard process death can strand a provisional enrollment

An MFA enrollment is a client-owned `Prepare` -> material delivery -> exact
`Commit` transaction. `Prepare` creates provisional material; delivery,
including `Wrote::Sent`, does not commit the enrollment. Only an explicit
`Commit` for the exact transaction settles it. `Query`, `Redeliver`, and
`Abort` recover an uncertain delivery, with `Abort` releasing only the exact
matching provisional record. A process death between the atomic save and
delivery can still leave material whose secret and recovery codes were never
delivered.

Owner: the Macro-slice 2 durable-state work. The target is durable provisional
recovery, not a retry protocol or custody transaction framework.

The package-level regression control
`crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment`
now drives both sides of the boundary with a real child process and pipe
barriers: a prepared enrollment is hard-stopped before its acknowledgement,
while a delivered enrollment is acknowledged before the child keeps it. The
production custody record carries its exact process incarnation and OS owner
lease, startup reclaims only lease-free provisional records before exposing the
control socket, and the client-owned transaction retains exact provisional
custody until explicit `Commit` or exact `Abort`. Recovery probes the exact persisted-secret
lease for every provisional record; process-nonce equality is diagnostic, not
liveness. These controls are the shipped CLI transaction boundary and its exact
recovery controls; their exact-head evidence is recorded below.

Closing controls are the package-level child hard-death control above,
`custody::tests::v4_r2_hard_death_recovery_preserves_prepared_transaction`,
`custody::tests::v4_r2_committed_handoff_survives_restart_recovery`,
`custody::tests::v4_r2_current_nonce_without_owner_lease_is_recovered`, and
`control::handoff::tests::v4_r2_mfa_sent_write_aborted_before_settle_stays_prepared`.
Together they exercise prepared versus delivered material, explicit commit,
query/redelivery/abort recovery, restart custody, kernel-lease orphan truth,
and preservation of a sent-but-unsettled response as `Prepared` across task
cancellation until explicit settlement. The exact shipped CLI controls are
`crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment`
and
`crates/myownmesh/src/control/handoff.rs::tests::v4_r2_mfa_sent_write_aborted_before_settle_stays_prepared`;
the integration discriminator and external evidence are recorded below.

The shipped CLI unit controls are
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_enroll_displays_and_flushes_material_before_commit`,
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_lost_commit_ack_queries_exact_committed_transaction`,
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_prepared_query_retries_one_exact_commit`,
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_ambiguous_retry_queries_once_after_second_ambiguous_commit`,
`crates/myownmesh/src/cli/ctl.rs::tests::malformed_material_never_reaches_commit`,
and
`crates/myownmesh/src/cli/ctl.rs::tests::mfa_transaction_subcommands_preserve_exact_wire_mapping`.
The exact integration discriminator is
`crates/myownmesh/tests/ctl_mfa_transaction_r2.rs::shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact`.

Status: discharged at integration head `6d71567`; hosted CI `33229628657`
completed all six jobs green and Turing's exact-head source audit is PASS.

### R3 — an offline evicted Device receives a durable proof delivery

Current members still refuse an evicted Device and cannot re-admit it: the
signed eviction converges among current members, `log_evicted` is true, the
roster mirror removes it, and `current_policy_admits` returns false, so
auto-approve cannot fire. The Device's own stand-down is now a typed durable
proof publication. The sender persists an exact `Pending` record before any
carrier send, whose fact IDs are the canonical selected-head causal closure;
materialization is not admission and cannot itself emit the proof.

The receiver admits only the exact context, target, delivery ID, and complete
fact closure. Admission updates the semantic graph and projection, then emits
one matching typed `ProofAck`; the sender settles only that exact record and
keeps the `Settled` terminal tombstone across a second reopen. A reconnect
rebinds the record to the current authenticated owner/binding, while a stale
E0 is superseded before the canonical E1 replay. Generic W0/W2 carrier
attempts refuse without consuming the demand; the separately funded W1
sidecar owns D and an exact W1 settlement retires only W1, preserving W0/W2
and the provider baseline.

The closed-network reconnect control remains
`crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down`.
The durable proof lane and its transport-lab controls are the implementation
boundary, not a retry timer or a best-effort denial protocol.

The exact R3 controls are
`crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_pending_proof_is_persisted_before_send_and_replayed_after_restart`,
`crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_stale_e0_is_superseded_before_e1_reconnect_replay`,
and
`crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down`.

Owner: the typed durable-semantic Signaling Node lane together with the
Macro-slice 2 semantic proof work.

Status: discharged at integration head `6d71567`; hosted CI `33229628657`
completed all six jobs green and Turing's exact-head source audit is PASS.

### AuthorityLineage - bounded persistent closure record

**Status: FROZEN at integration head `6d71567`.** Hosted CI
`33229628657` completed all six jobs green and Turing's exact-head typed source
audit is PASS. These controls do not amend the R1 discharge or turn an
unresolved HOLD into an acceptance.

This is a separate, bounded semantic record accompanying the R3 implementation
boundary; it does not create another residual or widen the transport lane.
`FactBody::AuthorityLineageResolution` is the only persistent cross-cell
selector for a multi-head AuthorityUse lineage. Ordinary
`FactBody::Resolution` remains a same-cell selector (including Role cells) and
cannot select cross-cell authority heads. A distinct-author Membership payload
Resolution remains payload-local and cannot join Role lineage. Self-authored
Closed Membership retains its author AuthorityUse edge and must fork with a
concurrent Role revoke; an OpenParticipation Resolution remains payload-local
and adds no persistent subject lineage. An unresolved fork stays fail-closed
and its losing RoleGrant remains inactive. The exact integration-head commit,
hosted run, and typed-audit evidence are `6d71567`, `33229628657`, and Turing's
source PASS, respectively.

Within the AuthorityLineage boundary, `FactGraph::selected_authority_branch`
chooses the unique causally maximal matching typed selector in the sole
current-head ancestry, independently of FactId or parent traversal order. Zero
matching selectors or multiple incomparable maximal selectors fail closed;
redundant ancestor parents cannot revive an older selector.

Both stale-selector controls choose a bounded deterministic valid redundant-
support T2 and assert `R.id > T2.id`. Canonical sorted parents plus the old
`Vec::pop` traversal would visit `R` to the older T0 first, while the fixed
selector chooses the newer maximal T2.

The closure is evidenced by
`authority_lineage_selection_survives_cross_cell_forks_and_rejects_losers`,
`membership_resolution_does_not_select_authority_lineage_branch`,
`finite_authority_fork_requires_complete_resolution_before_regrant`,
`cross_cell_resolution_cannot_select_a_role_authority_fork`,
`cross_cell_payload_resolution_preserves_authority_fork_in_any_arrival_order`,
`payload_resolution_does_not_join_a_transitive_role_fork`,
`second_order_payload_resolution_cannot_join_the_role_authority_fork`,
`second_order_payload_fork_converges_without_authority_join`,
`open_participation_payload_fork_stays_in_its_ordinary_cell`, and the
`720`-permutation projection control
`finite_authority_fork_projection_converges_for_every_arrival_permutation`,
`self_authored_membership_keeps_a_role_authority_fork_explicit`,
`self_authored_membership_resolution_cannot_select_the_role_loser`, and
`self_authored_membership_resolution_is_order_independent_after_role_regrant`,
`stale_selector_follows_newer_typed_role_resolution`, and
`stale_selector_arrival_converges_with_distinct_owner_and_redundant_ancestor`
(12 schedules).
Together they persist exact role-cell authority selection, reject payload
resolution as an AuthorityUse selector while retaining only local witnesses,
require complete typed resolution before regrant, preserve the self-authored
Membership authority edge, keep the loser inactive, reject stale selectors,
and prove the 12-schedule stale-selector, 120-permutation, and 720-permutation
controls.

The exact shipped typed-selector controls are
`crates/myownmesh-core/tests/semantic_fact_controls.rs::authority_use_fork_requires_explicit_typed_selection_across_arrival_orders`,
`crates/myownmesh-core/tests/semantic_projection_controls.rs::authority_lineage_selection_round_trips_and_regrant_is_future_only`,
`crates/myownmesh-core/tests/semantic_projection_controls.rs::stale_selector_arrival_converges_with_distinct_owner_and_redundant_ancestor`,
and
`crates/myownmesh-core/src/semantic/causal.rs::FactGraph::selected_authority_branch`.

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

1. **The report no longer names a third party on mDNS, and mDNS is no longer
   trusted to name one at all.** `mdns/driver.rs` attributes a normalized leave
   to `frame.from` — the same field its announce already used, and the same one
   its own peer table is keyed on. **Narrows the surface; mDNS only.** It does
   not help on Nostr, where the departure still carries the body `peer_id`.

   The exact-head review found the deeper error: browse resolve, expiry and
   goodbye were labelled `CarrierObserved`, but the device id in every one of
   them is parsed from the advertisement TXT record, which any LAN participant
   may write with any value. An attacker could advertise a victim's Device ID
   and then withdraw it. **All mDNS presence and withdrawal is now
   `SenderClaimed`**, which leaves the in-process `LocalBroker` as the only
   producer of `CarrierObserved` anywhere in the system. A driver leaves that
   state by gaining an authenticated binding between what it observed and the
   device key, not by observing more carefully.
2. **Attribution travels with the report, unchanged, to the one place that
   reads it.** `SignalingRuntime` retains nothing and decides nothing about a
   withdrawal: an earlier revision held one back while some other attach still
   observed the device, and that availability map was deleted rather than
   repaired (see the boundary section). **Narrows nothing on its own; it
   preserves the evidence.** A hostile Nostr payload naming a third party is
   delivered to the engine as a `PeerLeft` for that third party, on every
   network shape, single-carrier or not. Nothing before the engine stops it, and
   nothing before the engine is asked to — which is why count 3 is the one that
   closes the effect.
3. **The engine barrier: a sender-claimed withdrawal selects no session in any
   state. This is the count that holds on every carrier and closes the
   body-target effect outright.** `PeerLeft` is reachability evidence, and
   `engine/mod.rs` reads *attribution* before liveness. A `SenderClaimed`
   withdrawal is teardown-inert — it retires nothing, whatever state the named
   session is in — so the delivered Nostr withdrawal of count 2 reaches the
   engine and selects nothing. Only a `CarrierObserved` withdrawal may retire
   anything, and only an attempt that never became a session: **the predicate is
   the promoted `SessionCapability` itself**, not the transport booleans
   underneath one. A promoted session is retired by an exact channel failure or
   the authenticated `SessionControl::Depart` over that very session, and by
   nothing else.

   **This count was liveness-only when it was first written, and that was
   wrong.** Guarding on `authenticated && data_channel_open` alone left a
   sender-claimed departure able to retire a third party's
   authenticated-but-channel-closed session — a session in recovery, which is
   when it is least able to defend itself. Attribution, not liveness, is what
   makes the body-claimed target inert rather than merely narrowed.

**The guard window is closed, not narrowed.** An earlier revision defined "live"
as `authenticated && data_channel_open`, which left a real window: a session
whose channel had closed while recovery or replacement was in progress failed the
conjunction and could be retired by a carrier's own observation. That state
belongs to the Peer Session and connector-recovery owners, so the predicate on
both sides of the lifecycle is now `PeerConnection::holds_promoted_session` —
graceful departure may only depart a session that exists, and a carrier
withdrawal may not retire one. A closed channel no longer changes either answer.

**Stale-replacement safety, on both sides.** The withdrawal arm takes the peer
owner token, reads promotion through that same token, and retires with
`drop_peer_if_current`. Graceful departure now does the same: it selects
`PeerRegistry::owners_snapshot()` and never re-resolves a Device ID again, so a
replacement installed before the send, during the awaited send, or after it is
neither sent a goodbye meant for its predecessor nor torn down in its place.
Nothing on either path touches the roster or the member log.

**Control coverage, and the two controls prove different things.** Every
withdrawal now reaches the engine — the runtime's availability map, which used to
hold one back while another attach still observed the device, was removed rather
than repaired — so what the engine's arm does with a delivered withdrawal is the
whole rule. `v4_m2_a_carrier_withdrawal_selects_only_an_unpromoted_attempt` in
`engine/mod.rs` proves it over the in-process carrier, the only one that can
produce a carrier-observed report at all: a sender-claimed departure selects
nothing however healthy the transport looks, and a carrier-observed withdrawal
does cancel an unpromoted attempt — which makes it a rule about attribution
rather than an arm that has stopped dropping anything.
`v4_m2_a_third_party_lan_claim_creates_no_session_and_moves_nothing_durable`
proves the network carrier's shape, where both directions are claimed: a LAN
participant may write any device id into a TXT record, and neither the announce
naming a stranger nor the withdrawal naming a victim yields a promoted session or
changes the roster version, roster size, transition log or member log — compared
before and after, not enumerated. A claimed announce *may* leave an unpromoted
attempt behind it, because an announce paces a dial; that is the cost of a
connection that will not authenticate, and it is not an admission.

**The promoted half cannot be proven without a connector, and is not
counterfeited.** Only a real connector mints a `SessionCapability`, so
`v4_m2_a_carrier_withdrawal_cannot_retire_a_promoted_session` lives behind
`transport-lab` with the rest of the promotion controls. It is `#[ignore]`d,
because it opens a native WebRTC object, so **the ordinary `transport-lab` CI job
compiles it and does not run it**; no scheduled job executes it. Its only
execution to date is the explicit manager run `ef44f52a`. **Neither the
default-feature job nor the ordinary `transport-lab` job covers the
promoted-session side of this boundary**, which is disclosed here rather than
left to be discovered, and "CI runs it" is not claimed. The alternative — a fixture writing a promotion field the
product cannot produce — would assert against a session that does not exist. The
default-feature control keeps its durable assertions throughout: the device stays
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
**mDNS has no `CarrierObserved` path either, and this correction removed the
last one it had.** Browse resolve, expiry and goodbye all take the device id from
an advertisement's TXT record, so the daemon observing a record appear or vanish
establishes that *a record* moved, not whose device it names. The in-process
`LocalBroker` is the only producer of `CarrierObserved` anywhere in the system,
because it is the only one that stamps the registered id of the handle that sent
rather than reading an id out of something a sender wrote. On every network
carrier, prompt carrier-driven retirement is therefore unavailable by design, and
exact connector closure, the authenticated `SessionControl::Depart`, or the
heartbeat timeout is the backstop.

Status: **discharged at
`0237f9e02df3ab21131c5612c1b231050c860cc4`** — "Complete signaling and semantic
ingress ownership", parent `ee8f5b98622ddbfe2c4307294113f9ddd2c73d8e`, 15 source
and test files at +1713/-870, adding `engine/semantic_ingress.rs`. This ledger is
deliberately not in that commit, so the evidence does not contain its own claim.

**Two prior discharges are superseded, and both are kept here rather than
overwritten**, because a residual that was closed twice on insufficient evidence
is worth being able to read back.
`0b9b5b2c5be60f8204aa2fef4e14259e5d385611` guarded on liveness alone, so a
sender-claimed departure could retire a third party's
authenticated-but-channel-closed session — a session in recovery, which is
exactly when it is least able to defend itself.
`7fb4708d01895269b4aff809857b9d6ffe88d6ad` moved attribution ahead of liveness
and bound the decision to one exact `PeerOwnerToken`, which closed the aimable
half but left two holes the exact-head review of `ee8f5b9` found: the mDNS driver
still labelled a sender-chosen TXT Device ID `CarrierObserved`, so an attacker
could advertise a victim's id and then withdraw it; and the retirement predicate
was still the transport booleans rather than the promoted session. Neither
survives in `0237f9e0…` — every mDNS report is `SenderClaimed` there, and the
predicate is a promoted `SessionCapability` — and the three controls named in the
discharge record below are present in that commit and are what close it.

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

**There is no durable-semantic *signaling* variant, and none is pretended.** No
carrier variant carries a durable signed fact, so an uninhabited durable arm on
the signaling union would have been a tag whose other value nothing can hold.

The durable half lives where the sender is known. `engine/semantic_ingress.rs`
is the Semantic Node's ingress: the seven existing authenticated-session durable
messages (`NetworkState`, `NetworkStatePropose`, `NetworkStateAck`,
`NetworkStateSplit`, `RosterSummary`, `RosterRequest`, `RosterEntries`) enter one
closed typed `DurableSemanticIngress`, and a separate reducer applies them under
the exact `PeerOwnerToken` the session belongs to. The type wraps a private enum,
so the only way to obtain one is the module's `admit`, and `admit` is total over
`MeshMessage` with no wildcard — a new durable message is a compile error until
it is classified. Its outcome is a two-variant `SemanticAdmission`, not a
`Result`: "not a durable fact" is the ordinary case rather than an error, and a
`Result` would have put a whole `MeshMessage` in an `Err` on the way past every
non-durable live frame. Boxing that would have bought an allocation per frame in
front of the entire inbound path; the enum moves the frame and allocates nothing. The two ownerships are therefore disjoint by construction:
unauthenticated carrier ingress carries no durable fact and has no kind that
could, and durable ingress is reachable only from a promoted session.

`SignalingRuntime` is the owner on the signaling side. It owns exactly two
things: an opaque process-local `CarrierInstance` minted per attach, and
cross-carrier de-duplication whose every retained key is funded by the finite
provider rather than capped by a constant. **It retains no untrusted record.** An
earlier revision kept a per-device availability map keyed by attacker-chosen
device ids and bounded by an invented constant; it was removed rather than
repaired, which closes the flood that evicted real peers and the stale-attach
suppression together, and leaves a detaching carrier with nothing to clean up.

A key is committed only where the engine's mailbox actually **accepted** the
value. The send reports three outcomes — accepted, dropped, engine gone — rather
than a keep-pumping boolean, because a boolean conflates "the driver carries on"
with "the engine has it": under that reading a first offer refused by local
pressure still left its key behind, and the retransmission meant to rescue the
attempt was swallowed as a duplicate of something nobody received. That is the
defect `a_refused_offer_leaves_no_dedup_history_and_its_retransmission_lands`
exists to catch, and it caught it.

The Peer Session lifecycle owner is unchanged: an authenticated
`SessionControl::Depart` sent over the exact live session, consumed only under
that session's owner, with no target Device ID because the session defines its
endpoints. A carrier withdrawal is reachability evidence and cannot retire a
promoted session; `announce_leave` may still emit the carrier hint, but it
carries no teardown authority and the fixed departure wait is gone.

**Both driver queues are gone rather than sized, in both directions.**

*Inbound.* A driver used to push decoded reports into an unbounded channel that a
bridge pump drained, and that stretch was unaccounted memory an unauthenticated
carrier filled at its own rate. Drivers now take a
`myownmesh_signaling::InboundSink` — an opaque closure — and carry each report
through the engine's funded admission on their own task. Local pressure is lossy
and never a teardown signal; only a gone consumer stops a driver.

*Outbound.* The mirror defect, and the one a single whole-queue lease did not
close. The bridge used to translate each engine event into the driver's type and
push that translation into a second unbounded channel, with one standing
`SIGNALING_DRIVER_QUEUE_CLAIM` acquired for "the queue". That named the subsystem
without bounding it: the translations are the allocations, the depth is how many
exist at once, and one claim says nothing about that number however long it is
held. Drivers now take a `myownmesh_signaling::OutboundSource` and **pull**; the
translation is built at the moment the driver asks for one, from the engine's
own per-driver funded mailbox, which already admitted the pre-translation value.
Nothing is ever queued in a translated form, so there is no queue lease —
`SIGNALING_DRIVER_QUEUE_CLAIM`, `acquire_driver_queue_owner`, `OwnedQueue`,
`start_with_queue_owner` and `join_with_queue_owner` are all deleted rather than
kept as vestigial accounting for a queue that no longer exists.

Both seams are opaque callbacks or traits over plain values, so the signaling
crate still learns no resource vocabulary and still works standalone.

Excluded, and still excluded: anti-entropy, proof delivery, B3 changes, timers,
polls, retries, terminal acknowledgements, relay and durable-store work, route
identities, route ledgers, path generations, persistence, application payload in
signaling, downstream migration, and any generic framework.

### Named residuals inside this boundary

Both the engine→driver and driver→engine seams are queueless now: a driver pulls
its outbound values through an `OutboundSource` and offers its inbound reports to
an `InboundSink`, so nothing is retained in a translated form on either side.

Three unbounded queues remain **on the production bridge path or upstream of
it**, and they are named rather than quietly sized:

- **mDNS discovery events** (`mdns/discovery/embedded.rs`,
  `mdns/discovery/system.rs`). These are **upstream of admission and on the
  carrier→engine path**: a LAN participant's multicast lands here before the
  driver has decided anything, so this is a real bound the driver still lacks.
  It is left open because bounding it belongs to the driver's own work model —
  the system backend's queue is the `mdns-sd` dependency's, which the review
  allows to remain a named residual, and the embedded backend's is the same
  buffer under our own control. Naming it as internal would have been the
  comfortable answer and the wrong one.
- **The mDNS resolve queue** (`mdns/driver.rs`), fed from the discovery events
  above and drained by the exchange dialler. Same position, same reason.
- **`server.rs`'s per-connection outbound queue.** The self-hosted relay is a
  separate deployment with no `NetworkState` and no provider to answer to; it is
  not on this node's carrier→engine path at all.

The count is those three and no more. It deliberately excludes the adapters a
caller may opt into — `LocalBroker::join`, `InboundSink::from_unbounded`,
`UnboundedSource` — which do build unbounded channels, but only for a standalone
embedder or a control that asked for one, and never on the production bridge
path: `attach_local`, `attach_nostr` and `attach_mdns` construct none of them.
That is the point of naming them in the signaling crate's public surface rather
than hiding a buffer inside a driver — the choice appears in the source of
whoever made it.

## Exact resource matrix for the remaining carrier/server state

This matrix is an accounting boundary, not a claim that every allocation in a
carrier library is already provider-metered. A row names the retaining state,
its producer and consumer, the exact admission/refusal point, and the owner
that releases it. Provider dimensions are named only where a provider seam
exists; backend-owned queues and a separately deployed relay are explicitly
marked **no provider** rather than assigned guessed byte prices.

| State class | Producer | Consumer | Provider scope / dimensions | Admission / refusal | Queued / executing / terminal / shutdown owners | Pressure control | Provider baseline |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **mDNS discovery / resolve:** backend `DiscoveryEvent`; resolved `PeerEntry` and `key_to_peer`; directed `OwnedSignal<String>` | `Discovery::start` backend; `run_browse` TXT/SRV resolution; engine `OutboundSource` | `run_browse` parser and peer maps; engine `InboundSink<MdnsInbound>`; per-connection writer | Backend discovery queue is **no provider** and remains the named upstream residual. `Shared.peers` is structurally capped, but `key_to_peer` has no independent cap/provider lease and is also a named residual. Directed lines retain their engine owner; any attached provider charge is made before engine-mailbox admission | `wire::parse_advert`, room/version/address validation, `MAX_DISCOVERED_PEERS`, and sink acceptance. Invalid/full records drop; a full/closed directed queue drops its owned line | Backend owns discovery events; `Shared.peers`/`key_to_peer` own resolved state; writer owns queued `OwnedSignal`. `MdnsDriverHandle::stop` cancels, unregisters/shuts down discovery, aborts tasks, and drops maps/owners | `MAX_DISCOVERED_PEERS = 1024`; per-connection `OUTBOUND_QUEUE_CAP = 128`; bounded frame line. Dependency-owned discovery depth and uncapped backend-key mapping remain HOLD items | No signaling-side provider delta. Attached engine ownership returns to its pre-arrival baseline after invalid/full/drop and stop |
| **Nostr replay / parsing:** inbound WebSocket frame and decoded `Value`/`NostrEvent`; exact directed attempt, session, relay-entry, and correlation records | Relay socket read; `DeliveryStore::admit`; `open_session` | `handle_inbound_frame` and `InboundSink<NostrInbound>`; `run_relay_session`; `DeliveryStore` retry/reconnect state | Attached `DeliveryProvider` scope is one attempt, one relay session, and one `(attempt, session)` entry. `DeliveryRetention` independently names encoded-event, attempt key/entry, relay entry, session identity/entry, and residual claims across `AccountedMemoryBytes`, `QueuedBytes`, `StorageObject`, and `OpaqueDependencyResidual` | 256-KiB frame cap, JSON/envelope/kind/tag checks, and sink acceptance precede retention. Provider refusal precedes map insertion/frame encoding; one refused relay is not an attempt terminal while another relay lives | Socket task parses/writes; exact attempt owns source/correlation; each relay session owns session/relay-entry leases. Accepted, typed refusal, replacement, ACK, cancellation, and shutdown settle exact owners; driver stop cancels sessions and store | No pre-parse dedup ring or unbounded refusal queue; provider admission is per attempt/session/relay and reconnect rebinds exact current identity | Attached provider `in_use` returns to pre-admission baseline after refusal, ACK, replacement, or shutdown. Standalone compatibility mode is explicitly unmetered |
| **Relay per-connection I/O / replay:** server `ConnEntry`, bounded outbound queue, subscriptions, stored replay deque, per-REQ replay vector | `HubInner::handle_event` fan-out; `HubInner::handle_req` stored-plus-live replay; client frames | Per-connection writer; `serve_conn`; `handle_req` sends replay and `EOSE` | Self-hosted `server.rs` is a separate deployment with **no MyOwnMesh `FiniteResourceProvider` scope**. Its limits are server policy/OS accounting, not mesh dimensions | Bounded `try_send`; rate/filter/subscription/message limits reject or drop. Replay dedupes and truncates to `MAX_REPLAY_PER_REQ`; storage admits only replayable events under its cap | `HubInner` owns connection/subscription/presence state; writer owns queued frames; connection owns replay output until send. Unregister and hub shutdown release exact state | `MAX_STORED_EVENTS = 8192`, 15-minute retention, `MAX_REPLAY_PER_REQ = 500`, queue 128, and per-connection limits | No mesh-provider baseline is claimed; baseline is configured store/presence plus empty per-connection queue after pruning |
| **Server registration / shutdown:** listener accept, `conns`, `ip_counts`, presence ownership, IDs, shutdown watch | Listener accepts socket; `HubInner::register` creates `ConnEntry` | `serve_conn` reader/writer; `HubInner::unregister` removes exact connection and current presence ownership | **No provider:** relay has no semantic mesh slot or attached finite resource scope. OS listener/socket/runtime allocations are outside mesh dimensions | `max_connections_per_ip` refusal sends bounded NOTICE then closes; shutdown, failed upgrade, or closed socket never enters `conns`; successful registration is the sole record admission | `HubInner` owns registration/IP/presence maps; `serve_conn` owns socket; writer owns queue; unregister is terminal cleanup; shutdown watch ends readers and writers | Default `max_connections_per_ip = 64`, plus message/rate/subscription/filter ceilings and OS listener admission | No mesh-provider delta is promised. Server baseline is zero connections, empty IP/presence maps, no writer queues after shutdown; deployment-level OS accounting remains HOLD |

**R1 and HOLD are preserved.** R1 remains discharged at `55bafe5`; this
matrix does not reopen it. The mDNS backend queue and self-hosted-relay
no-provider allocations remain HOLD until their owning dependency or
deployment supplies a typed, independently verified accounting boundary. The
Nostr client row is provider-owned only when an attached `DeliveryProvider`
is supplied; its standalone unmetered provider is not evidence of finite
production capacity.

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
| R1 | `55bafe5` (closing subset: `f2a0f31`, `d6dd84d`, `1a8285b`, `f29207d`, `eaba95b`, `57ca3c5`) | `semantic::store::child_process_contention_and_hard_death_release_the_writer`, `semantic::store::lifetime_owner_blocks_second_open_then_reopens_for_append`, `semantic::store::lifetime_owner_preserves_deterministic_graph_and_proof_union`, `durable_semantic_restart::closed_network_restart_restores_the_committed_semantic_graph`, `durable_semantic_restart::shutdown_fences_stale_state_before_same_slot_reopen_and_append` |
| R2 | `6d71567` (hosted CI `33229628657`; Turing source PASS) | `crates/myownmesh/tests/custody_recovery_r2.rs::v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment`, `crates/myownmesh-core/src/custody.rs::v4_r2_hard_death_recovery_preserves_prepared_transaction`, `crates/myownmesh-core/src/custody.rs::v4_r2_committed_handoff_survives_restart_recovery`, `crates/myownmesh-core/src/custody.rs::v4_r2_current_nonce_without_owner_lease_is_recovered`, `crates/myownmesh/src/control/handoff.rs::tests::v4_r2_mfa_sent_write_aborted_before_settle_stays_prepared` |
| R3 | `6d71567` (hosted CI `33229628657`; Turing source PASS) | `crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_pending_proof_is_persisted_before_send_and_replayed_after_restart`, `crates/myownmesh-core/tests/durable_proof_delivery_r3.rs::r3_stale_e0_is_superseded_before_e1_reconnect_replay`, `crates/myownmesh-core/src/engine/mod.rs::v4_b2_speculative_proof_ack_is_bound_to_exact_w1`, `crates/myownmesh-core/tests/closed_network_governance.rs::evicted_offline_device_learns_on_reconnect_and_stands_down` |
| R4 | `0237f9e02df3ab21131c5612c1b231050c860cc4` (supersedes `7fb4708d01895269b4aff809857b9d6ffe88d6ad`, which supersedes `0b9b5b2c5be60f8204aa2fef4e14259e5d385611`) | `v4_m2_a_carrier_withdrawal_selects_only_an_unpromoted_attempt` (default feature), `v4_m2_a_third_party_lan_claim_creates_no_session_and_moves_nothing_durable` (default feature), `v4_m2_a_carrier_withdrawal_cannot_retire_a_promoted_session` (`transport-lab`) |
