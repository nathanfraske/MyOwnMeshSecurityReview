# Arc 04 endpoint authentication red team

Status: the current evidence record for Macro-slice 1, covering the
endpoint-authentication boundary on `arc/04-endpoint-auth`. It owns the control
inventory, the residuals, and the evidence statements.

Under controlling review 4892207368 this is the **one** current evidence record.
The per-arc red-team essays it used to cross-refer to (Arc 02 authority spine,
Arc 03 connector worker) are deleted along with the rest of the micro-slice
scaffolding; [`MESH-ATTACK-VECTORS.md`](MESH-ATTACK-VECTORS.md) remains as the
architecture-level threat catalog. Source-shape guard claims are also gone: the
boundary is now carried by Rust visibility, private constructors, ordinary type
checking, and the two compile-fail probe harnesses, so this record no longer
asserts anything about the spelling of Rust source.

**Execution evidence lives in exactly one place here: section 6.** Everything
outside it is a source read, a boundary statement, or a moved historical note,
and source presence is never exact-head execution evidence. A review identifier
is provenance only: it names the instruction an integration followed, never a
run. Every run identifier in section 6 is anchored to the exact head it was
produced at and may not be re-attached to a newer one — a green run does not
cover a control added, renamed, or changed after that head. An incomplete run is
recorded as incomplete and never as a pass. Passing this record does not
authorize merge.

## 1. Canonical names and owners

Read from the working tree. These are the names the fundamental documents are
expected to match; a document naming something else is stale, not a second
design.

| Concern | Current owner and name |
|---|---|
| Peer `hello` contribution intake | `EndpointAuthTask::accept_peer_hello`, answering `AcceptedPeerHello::{FirstBinding, ExactDuplicate}` |
| Peer `auth_response` proof intake | `EndpointAuthTask::accept_peer_proof`, answering `PeerProofAcceptance::{Promoted, AlreadyPromoted}` |
| Sole issuer of the authenticated channel | `EndpointAuthTask::accept_peer_proof`, the only transition that constructs `PeerProofAcceptance::Promoted`; `AuthenticatedChannelCapability::from_verified_exchange` mints the `EndpointAuthPermit` internally, and `PeerConnection` owns the capability. There is no `EndpointAuthTask::authenticate` |
| Terminal failure vocabulary | `EndpointAuthError` — `NoBoundTranscript`, `NotMutual`, `ContributionNotFresh`, `SignatureInvalid`, `ChannelNotCurrent`, `ConflictingPeerContribution`; returned only by the two intake operations, every variant terminal for the attempt |
| Setup refusal vocabulary | `EndpointAuthSetupError` — `MissingIdentityField`, `MissingContribution`, `ContributionWrongWidth`, `ContributionMalformed`, `IncompatibleProfile`; fires before or beside an attempt and terminalizes nothing. No conversion exists in either direction |
| Closed profile derivation | `EndpointAuthProfile::V1Ed25519Dtls`, derived in `endpoint_auth::context` from the connector's closed `EndpointAuthBindingProfile`, never supplied by the engine or a peer |
| Compatibility precondition | `endpoint_auth::negotiate_profile`, gating on `Feature::ENDPOINT_AUTH_V1`; absence is `EndpointAuthSetupError::IncompatibleProfile` before any proof work, and the handler's own drop of the exact current peer is what fails the connection closed |
| Signed transcript commitment | `endpoint_auth::transcript::{transcript_bytes, transcript_for_context}`, domain-tagged and length-prefixed, role-canonical by `transcript::role_of` |
| Channel binding term | `connector::EndpointAuthBinding::webrtc_certificate_fingerprints`, supplied by the connector worker's `endpoint_auth_binding()` |
| Binding-supplier refusal cleanup | the engine `TransportEvent::DataChannelOpen` arm: `worker.refuse_data_channel_open()` then `drop_peer_if_current` |
| Registry admission witnesses | `engine::state::{AdmittedSessionOperation, AdmittedApplicationOperation, AdmittedInboundApplicationOperation, AdmittedInboundDispatch, AdmittedRenegotiation}`, minted inside the registry mutation fence |
| Local RPC withdrawal identity | `rpc::PendingOpId` over the private zero-sized `PendingOpMarker`, compared by `Arc::ptr_eq` |
| Arc 04 compiler-boundary harness | `scripts/check-v4-arc04-compiler-boundaries.py` |

`endpoint_auth_v1` is an advertisement, not a negotiation input. There is one
closed profile and no second inhabitant, so the advertisement decides only
whether an attempt begins. It can never select a weaker profile, and its
absence fails closed with a typed refusal before any transcript is assembled or
any signature is produced or verified.

`PendingOpId` is a process-local ownership token — a local capability for
naming one filed pending entry again. It is **not** network authority, not
durable, not a route or session authority, not a credential, and not a
generation counter. It is never serialized, never sent, never derived from
anything a peer supplies, and no inbound path reads it.

## 2. Harness ownership

Arc 04 has its own compiler-boundary harness,
[`scripts/check-v4-arc04-compiler-boundaries.py`](../scripts/check-v4-arc04-compiler-boundaries.py).
It reuses the Arc 03 record's hard-won harness invariants — root-derived vendor
patches, generated-manifest self-check, rustflag-normalized probe environment,
copied lockfile, shared isolated target, `--offline`, and exact
code/fragment/primary-line cause matching — and adds its own probes over the
endpoint-authentication boundary. It carries no evidence from the Arc 03 runs
recorded in that record.

The live two-connector controls are owned by `endpoint_auth::native_link`,
gated on `transport-lab` alone, and run in a `transport-lab`-only CI job. That
ownership is what let the pre-V4 compatibility subtree be deleted later without
taking the evidence with it; the status note below records the move while that
subtree still existed, and carries a bracketed marker saying so.

## 3. Status notes

The Arc 04B-4, 04E, 04F, and 04G notes below were written into the Arc 03
connector record while Arc 04 was in flight and are moved here unaltered, so
each keeps saying exactly what it said at the point it was written. Where a
later note corrects an earlier one, it says so in its own words and the earlier
text is left standing. The one editorial marker added by this move is bracketed
and labelled as such. The Arc 04H note at the end is new and was written here.

### Status note at Arc 04B-4

Recorded while correcting two claims in the Arc 03 record that had gone stale.
The Arc 03-owned half of that note — the probe-count staleness correction —
stays in the Arc 03 record, because it is about the Arc 03 script. The Arc 04
half is this:

- **Ownership of the basal native fingerprint control.** Arc 03 left the live
  substituted-fingerprint control inside `legacy_v1`, where it needed the
  deprecated compatibility feature to compile at all. Under Arc 04 it is basal
  V4 behaviour and no longer lives there: the reusable two-connector fixture and
  its controls are owned by `endpoint_auth::native_link`, gated on
  `transport-lab` alone, and CI runs them in a `transport-lab`-only job so
  deleting the pre-V4 subtree cannot delete the evidence. The pre-V4 *routing*
  controls stay in `legacy_v1`, which is unchanged. [Editorial marker, added
  after the fact: that subtree, its feature, and its routing controls have since
  been deleted outright, which is the deletion this note was written to survive.
  The `endpoint_auth::native_link` controls it moved the fingerprint evidence
  into are unaffected, which is the whole point of having moved them.]

### Status note at Arc 04E

Added rather than edited in place, for the same reason as the note above: the
run records must keep saying what those runs actually reported. Nothing in this
subsection has been executed. No run identifier is cited for any claim here,
because none exists — these are working-tree source facts, read from the tree,
and they are not evidence that anything passes.

- **The inbound application path is now fenced by a witness, not a boolean.**
  The path previously answered admission with an `Option<bool>` that outlived
  the fence which produced it, after which the affected peer-directed dispatch
  arms re-resolved the peer *by device id*. A replacement installed during the
  await could therefore answer that lookup and receive those peer-scoped
  effects, the liveness touch, the counters, and the delivery. Durable
  identity-keyed governance is deliberately outside the witness and is not
  covered by this change or by the controls below.

  Admission now yields a move-only witness that names one exact installation and
  carries the parsed frame with it, so there is nothing left to re-resolve;
  after replacement the witness names nothing. The synchronous effect runs
  *inside* the registry mutation fence rather than after a currency answer — the
  helper delegates to `PeerRegistry::with_current`, which holds the lock across
  the whole closure, so replacement orders strictly before or after the entire
  effect and there is no instant at which "still current" has been established
  but the effect has not yet run. Reliable stream state moves under the same
  fence. The witness types are crate-internal and remain externally unreachable
  — `engine::state` is `pub(crate)` and both are `pub(super)`. The
  module-privacy probe is paired with the harness's positive control, which
  names the public Arc 04 surface that must still compile, so the probe cannot
  go green merely because a witness was renamed or deleted.

  The RPC arm is the one place where the fenced authority is weaker than it may
  read: it claims authorization atomicity, not cancellation. A replacement
  landing before the mint refuses the authority and the handler never runs; a
  replacement landing after the mint does **not** cancel it, and the handler
  runs to completion. What the capture buys there is that the run is owner-bound,
  so its replies fail closed against a superseded installation rather than being
  delivered to whoever holds the device id by then.
- **The missing-binding path is now the real one.** The absent-component
  controls previously could only be stated against a hand-built context. They
  are now driven through the production engine open arm on a live link, using a
  fixture that opens a genuine offerer/answerer pair and stops at the left
  connector's own native open callback without consuming it, so the arm under
  test is the thing that promotes. The positive twin runs first: if stated
  components cannot open and start a handshake at all, "absent component fails
  closed" would pass for the wrong reason.
- **A conflicting contribution is a typed terminal cause, and the first cause
  wins.** Ordinary teardown reaches the same terminal path a refusal does — a
  refused proof removes the peer, and peer removal retires the task — so without
  an explicit first-cause rule the recorded cause of a refusal would depend on
  scheduling. The controls pin both halves: a conflict keeps its own cause
  through later retirement, and later frames on a conflicted task report the
  conflict rather than whichever lifecycle event arrived next.
- **The signer shares the process identity instead of copying a private key.**
  The endpoint-auth task is now built with `LocalIdentitySigner::for_identity`
  over an `Arc<Identity>`, replacing a construction that cloned the signing key
  out of the identity. This narrows how many copies of the private key exist; it
  is not a claim about key storage, zeroization, or memory hygiene, none of
  which this change addresses and none of which has a control here.
- **Current control totals, counted by reading the working tree.** The Arc 04
  compiler harness carries 19 cause-matched rejection probes and one positive
  public-surface control, and the script prints its own total rather than a
  hardcoded number, so quote the script's output and not this sentence. The
  `arc04-endpoint-auth` CI job names 33 exact controls: 23 run without
  `--ignored`, and 10 are live two-connector controls run with `--ignored` in the
  `transport-lab`-only step. Every one is wrapped in the same triple non-vacuity
  parse — exactly one test selected, that exact name reported ok, and a summary
  of one passed with nothing failed and nothing ignored — because `cargo test`
  exits 0 when a filter matches nothing. None of these totals has been verified
  by execution at any head, and none should be quoted as a passing result.
- **The non-exporter residual is unchanged and still accepted.** The DTLS
  certificate fingerprint pair is not an RFC 5705 exporter and is not
  session-unique: two channels between one device pair reusing the same
  certificates carry the same value. Nothing in Arc 04E narrows this. It remains
  accepted on the stated grounds — the pair defeats a terminating signaling-path
  man-in-the-middle, and separation of one channel from another is carried by
  the per-attempt contributions and by connector-incarnation ownership — and is
  documented as a protocol property in
  [`docs/PROTOCOL.md`](../docs/PROTOCOL.md#handshake-signature). It is a named
  residual, not a closed question.

### Status note at Arc 04F

**Nothing in this subsection has been executed.** No harness run, no `cargo`
build, check, test or clippy run, and no CI run stands behind any statement
below. Every claim here is a source read or a count taken from the working
tree. No run identifier is cited for any of it, and none should be inferred.
Operator review `4890068348` is cited as directive provenance only — it is the
instruction this integration followed, and it is not execution evidence for
anything.

- **Binding provenance, stated exactly.** Both components of the channel
  binding are read from the connector's own live native session after that
  session exists: the local one from the `a=fingerprint:` of the *applied local
  description*, the remote one from the `a=fingerprint:` of the *applied remote
  description*. What ties the remote component to the peer actually on the wire
  is the native DTLS stack, which verifies the certificate presented during the
  handshake against the fingerprint in the SDP it received. MyOwnMesh does not
  read or validate the certificate. It reads an already-applied, already-
  enforced SDP attribute. This is **not** an RFC 5705 exporter and **not** a raw
  certificate or public-key read, and the earlier language in this record should
  be read subject to that correction.
- **One terminal lifecycle transition.** The endpoint-auth task now has exactly
  one way to end, and it runs with the exchange guard in hand — it is the sole
  writer of both the terminal state and the lock-free `retired` observation
  cache. Retirement takes the lock first and marks nothing before it, closing
  the window in which a task could report itself retired while an operation
  already inside the critical section was still free to sign a transcript or
  move the handoff out. A proof arriving before anything is bound is now
  terminal rather than merely refused. Successful promotion is deliberately not
  a terminal ending, because the duplicate-`auth_response` guard depends on
  telling `Promoted` from `Terminal`.
- **RPC responses are bound to a device and a class.** A request id is a routing
  key and never an authority. Before this, the three inbound settle arms took
  the admitted dispatch witness and discarded it, reaching the pending map with
  nothing but the id the frame itself carried, so any authenticated peer that
  learned or guessed another peer's in-flight id could resolve that caller's
  reply, inject chunks into its stream, or end the stream early. Each pending
  operation now additionally names the one canonical device that may settle it
  and the one response class it accepts, and the source is taken from the
  admitted owner token. The binding is to the device rather than the
  installation, deliberately: the same device returning over a freshly
  authenticated replacement connector completes a still-pending call, a
  different device never does. Request ids are never reused to displace an
  in-flight operation — a colliding draw retries, and an exhausted draw fails
  locally before anything is sent. *[Editorial marker added when this note was
  moved: that last sentence was superseded at Arc 04G. The current shape is one
  draw and one claim, with no redraw, no retry and no attempt counter — see the
  G1 correction below, which is where the change is recorded.]*
- **Reconciliation, recorded explicitly.** `rpc::PendingEntry` is left `pub`,
  exactly as it already was. An intermediate revision narrowed it to
  `pub(crate)`; that was reverted here as unnecessary public API removal. The
  authority boundary is the `pending` map being private together with the three
  bound operations that are the only way to reach it, and naming `PendingEntry`
  gets a caller no closer to an entry. No external rejection probe was added for
  it, and nothing constrains its visibility beyond ordinary Rust privacy.
- **Public API compatibility, disclosed rather than buried.** `RpcError` gains a
  new variant, `RequestIdUnavailable`, reporting the explicit local failure when
  no unused request id could be drawn. `RpcError` is publicly re-exported and is
  not `#[non_exhaustive]`, so this is a breaking change for any downstream
  exhaustive `match` on it. That is a known and accepted consequence of naming
  the failure rather than displacing a pending owner; adding `#[non_exhaustive]`
  was considered and deliberately deferred out of this slice.
- **A refused open now cleans up as well as refusing.** When no binding can be
  formed, the connector is fenced first — exactly one native close is started,
  synchronously, since there is no watchdog behind it and a close not started
  there would never start — and only then is the peer removed, and only if it is
  still the exact entry the open was admitted for. A replacement installed for
  the same device while the binding was being read is left untouched. Retiring
  alone, as before, left a live native channel and an addressable peer entry
  that nothing could prove anything about.
- **Current control totals, counted by reading the working tree.** The Arc 04
  compiler harness carries 19 cause-matched rejection probes and one positive
  public-surface control; the script prints its own total, so quote that and not
  this sentence. The `arc04-endpoint-auth` CI job names 48 exact controls: 37
  without `--ignored`, and 11 live two-connector controls with `--ignored` in the
  `transport-lab`-only step. Every one is wrapped in the same triple non-vacuity
  parse. None of these totals has been verified by execution at any head.
- **Two control-only seams now exist inside security-critical code**, and both
  are gated: the lifecycle rendezvous that can park a thread inside the exchange
  critical section, and the native-close hold point that can park a real
  cleanup. Neither can exist in a production build: both are `#[cfg(test)]`, so
  the compiler removes them from any non-test build rather than a guard
  asserting their spelling.

### Status note at Arc 04G

**Nothing in this subsection has been executed.** No harness run, no `cargo`
build, check, test or clippy run, and no CI run stands behind any statement
below. Every claim here is a source read or a count taken from the working
tree. No run identifier is cited for any of it, and none should be inferred.
Operator review `4890447056` on PR #6 is cited as directive provenance only —
it is the instruction this integration followed, and it is not execution
evidence for anything. The Arc 04F note above is left exactly as it stands;
where this note corrects it, it says so.

**Neither of the two findings this slice acts on was an exploitable
vulnerability**, and neither is written up here as one. One was a documented
exactness property the code did not actually have, reachable only behind a
negligibly unlikely local event no peer can induce; the other was a type
telling an untruth about a live attempt's state, behind behaviour that was
already fail-closed. Both are worth closing, and neither should be read as a
defeated attack.

- **G1: local withdrawal is exact, and the earlier claim of exactness was an
  overclaim.** Arc 04F bound the *inbound* settle to a canonical device and a
  response class, and that binding is unchanged and still correct: a frame
  cannot know a process-local identity and must not have to. What Arc 04F then
  reused for the *local* withdrawal after a failed send was that same
  device-and-class predicate, described in the source as abandoning "its own
  operation and never a newer occupant of the same key". That description was
  not true of the code. The predicate names a *class* of operations, so if the
  withdrawing call's own entry had already left the map — settled by a response
  that raced the failing send — and the id had since been redrawn by a fresh
  call to the same device in the same class, every coordinate matched the
  newcomer and the stale withdrawal removed a live operation, stranding its
  caller on a reply nothing could deliver. Reaching it requires the same 96-bit
  random id to be drawn twice — negligibly unlikely, not impossible — which is
  why this is a latent exactness gap and a documentation overclaim rather than a
  vulnerability: no peer behaviour induces the collision, and the race that
  would exercise it needs the collision first. It is nonetheless handled
  exactly rather than argued away, on the same grounds the collision refusal
  itself is. The withdrawal is now conditional on a private, process-local identity
  — a zero-sized private marker behind an `Arc`, compared with `Arc::ptr_eq`,
  deliberately not `PartialEq` because a derived comparison on a zero-sized
  pointee makes every identity equal to every other. It is never serialized,
  never sent, never derived from anything a peer supplies, and no inbound path
  reads it. It is not an authority, a credential, or a generation counter.
- **G1, correcting the Arc 04F note above.** That note ends its RPC paragraph
  with "a colliding draw retries, and an exhausted draw fails locally before
  anything is sent". That is no longer the shape and the sentence should be read
  subject to this correction: there is now exactly one draw and one claim, with
  no redraw, no retry and no attempt counter. `REQUEST_ID_ATTEMPTS` is gone.
  "Never displace" was total either way; the bounded loop only read as a policy
  that would eventually take the id, when the honest answer is that it will not
  try. `RpcError::RequestIdUnavailable` keeps its name and its place in the
  public enum — the Arc 04F disclosure about that breaking change stands
  unaltered — but its documented meaning narrows from "no unused id in N draws"
  to "the one id this call drew was already owned".
- **G2: a second promotion is a typed outcome, not a borrowed terminal cause.**
  A retransmitted `auth_response` reaching an already-promoted attempt used to
  be reported as `EndpointAuthError::ChannelNotCurrent`. The attempt behind it
  is alive — bound, promoted, still its connector's, still answering a
  retransmitted `hello` from its cache and still vouching for what it issued —
  so that made an intact task claim a terminal cause it never took, and it left
  `EndpointAuthError` carrying two senses at once: "the attempt is over" and
  "this call had nothing to do". Promotion now answers a closed
  `PeerProofAcceptance` with exactly two variants, `Promoted(capability)` and a
  payload-free `AlreadyPromoted`, and every `Err` from that path is a cause the
  attempt recorded through the single locked terminal transition. **This is a
  correctness-of-type repair, not a closed hole.** The engine's duplicate guard
  corroborated an installed, current authenticated channel before treating a
  duplicate as benign, and dropped the peer otherwise; it still does, against
  the same two conditions. No peer was authenticated without that corroboration
  before this change, and none is now.
- **G2: what the duplicate outcome does not say, stated where callers read
  it.** `AlreadyPromoted` is a lifecycle fact and nothing more. It does not say
  the replayed signature verified — the attempt's state is read under the lock
  before any verification, and a promoted attempt has no handoff left to
  promote in any case, so those bytes are never examined and any bytes at all
  produce it. It does not say the capability was installed: promotion issues the
  one capability to whoever won it, and a winner can move the channel out and
  then fail to install it. The handler therefore keeps corroborating
  installation and current-attempt ownership and fails closed without both, and
  the duplicate variant carries no payload, so a second caller cannot be handed
  — or lent — the capability the promoting caller already holds.
- **What the two new guard families count, and what they cannot.** Both
  properties are counts, not paths, so no control can stand in for them. On the
  G1 side: the identity type stays private and opaque, gains no derived or
  hand-written equality and no `Serialize`, is decided only by `Arc::ptr_eq`;
  both records carry it under their own names; there is exactly one call site
  that draws a request id and no loop, attempt counter or generation in either
  registration; the withdrawal reads the identity and none of the binding
  coordinates; and the three inbound bound operations read none of the identity.
  On the G2 side: the outcome enum is closed at exactly those two variants and
  stays `pub(crate)`; the controls-only `into_promoted` stays `#[cfg(test)]`;
  the promoted arm returns the non-error; every `return Err` in the promotion
  path is either a cause already recorded or one recorded through `terminalize`,
  and no variant is constructed bare; and the engine matches both outcomes by
  name, requires both corroborations together, fails closed without them, and
  special-cases no error variant as benign. What none of this proves is that any
  of it compiles or runs: these are text shapes read out of the working tree.
- **Current control totals, counted by reading the working tree.** The Arc 04
  compiler harness still carries 19 cause-matched rejection probes and one
  positive public-surface control; no probe was added or removed by this slice,
  and the script prints its own total, so quote that and not this sentence. The
  `arc04-endpoint-auth` CI job now names 54 exact controls, up from 48: 43
  without `--ignored`, and the same 11 live two-connector controls with
  `--ignored`. The six added are two for G1 and four for G2, each wrapped in the
  same triple non-vacuity parse, and each block ordered positives first. Five
  are new; the sixth,
  `v4_arc04_duplicate_auth_response_after_promotion_is_idempotent`, is a
  pre-existing control named in CI for the first time because the new
  fail-closed control needs it — without a case in which this handler does *not*
  drop, "already promoted with nothing installed drops" would pass just as well
  for a handler that dropped every duplicate it ever saw.
- **One existing control was renamed, and the rename is disclosed rather than
  absorbed into the count.**
  `v4_arc04_duplicate_auth_response_after_promotion_is_refused` at head `8b325f6`
  is now `v4_arc04g_second_promotion_is_benign_and_leaves_the_attempt_promoted`.
  The old name asserted the behaviour this slice changed: a second promotion is
  no longer refused, so keeping it would have left the control register
  describing a refusal that no longer happens. The old name was not named in CI
  at `8b325f6` — the workflow there matches it nowhere — so no CI entry was
  displaced, repointed, or left dangling by the rename, and nothing that was
  being checked stopped being checked. The new name is named in CI, added by
  this slice as the first control of the G2 block. It is counted once, as one of
  the six additions above, and not twice. No other control was renamed.
- **`insert_local_request` is gated to controls, and the compiler enforces
  it.** Every caller it has is a control — two in `rpc::tests`, six in
  `engine::tests` — and no production path files through it, because a
  production caller needs the identity back to withdraw its own failed send and
  this wrapper drops it. That is enforced by ordinary compilation rather than by
  a guard: under the workspace `-D warnings` gate an ungated crate-internal fn
  with no non-test caller is `dead_code`, so a normal lib build refuses it, and
  the `#[cfg(test)]` containment is what makes the build pass. This is a hygiene
  and surface-narrowing property, not a defeated attack.

  None of these totals has been verified by execution at any head.

### Status note at Arc 04H

**Nothing in this subsection has been executed.** Every claim is a source read
from the working tree. No run identifier is cited, and none should be inferred.
The notes above are left exactly as they stand; where this note supersedes a
name in them, it says so.

- **The refusal vocabulary was split, and the split is why some names above are
  historical.** `EndpointAuthError` is now closed to *task lifecycle
  transitions* and is returned only by `accept_peer_hello` and
  `accept_peer_proof`; every variant means the attempt was terminalized. The
  causes that describe an unusable *input* moved to a separate
  `EndpointAuthSetupError` — `MissingIdentityField`, `MissingContribution`,
  `ContributionWrongWidth`, `ContributionMalformed`, `IncompatibleProfile` —
  which fires before or beside an attempt and
  terminalizes nothing. The width variant is named for its predicate: the
  decoded draw is compared against the exact full width, so a value that is
  wrong in either direction is refused. There is deliberately no conversion in
  either direction between the two types:
  a setup refusal widened into a terminal cause would let a parse failure claim
  a lifecycle transition it never made, and a terminal cause narrowed into a
  setup refusal would lose the retirement it actually performed. Sharing one
  enum meant a caller holding an `Err` could not tell "a task died" from "a
  string did not parse", and the compiler could not tell it either.
- **`IncompatibleProfile` is a setup refusal, not a terminal one.** The
  advertisement gate runs on the inbound Hello before the attempt is reached, so
  nothing has been terminalized when it fires. What closes the connection is the
  handler's own fail-closed drop of the exact current peer. Any earlier text
  calling it a terminal cause should be read subject to this correction.
- **A proof arriving before anything is bound has its own named cause.** It is
  `EndpointAuthError::NoBoundTranscript`, and it is terminal: there is no
  transcript for the frame to be a proof *of*, so it cannot become valid later.
  The Arc 04F note above records this transition as "a proof arriving before
  anything is bound is now terminal rather than merely refused"; the name for it
  is `NoBoundTranscript`.
- **`RuntimeMismatch` is gone.** It was unreachable on the issuer path — see the
  residual below for what carries exactness in its place. Its control was
  replaced by `v4_arc04_capability_context_and_runtime_are_exact_and_not_caller_supplied`.
- **The fundamental documents were reconciled against these names.**
  `crates/myownmesh-core/src/endpoint_auth/BOUNDARY.md`,
  `TRANSITION-PLAYBOOK.md`, `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`, and
  `docs/PROTOCOL.md` now name `accept_peer_hello`/`accept_peer_proof`,
  `PeerProofAcceptance`, the two refusal vocabularies, the closed derived
  profile, the `endpoint_auth_v1` advertisement as a fail-closed compatibility
  precondition, the signed transcript commitment, and the `DataChannelOpen`
  binding-supplier refusal-and-cleanup path. No run identifier, CI job status, or
  review identifier was placed in any of them; that evidence belongs here and in
  the pull request.
- **The native-close control now rendezvous through stored state.** The old
  control observed a call counter incremented before the returned close future
  was polled, then released `Notify::notify_waiters`, which stores no permit. A
  release in that gap was lost and the suite hung. The test-only
  `TestNativeCloseGate` now stores both its entry count and its open permit in
  `watch` channels. The repaired
  `v4_arc04_promoted_capability_retains_the_connected_claim_until_native_close`
  control waits on the gate's own entry, bounds every observation, proves one
  close and one retained claim while held, publishes a stored release, awaits
  completion under a deadline, and proves the claim returned once. This is a
  test-harness repair; no production timer, close path, or transport policy was
  changed.
- **Current recurrence inventory, counted from the working tree only.** The Arc
  04 compiler harness now carries 20 cause-matched rejection probes plus one
  positive public-surface control: the added probe proves the crate-private
  setup-error type cannot be matched downstream. Its source-shape checks pin
  the two exact closed error domains, their producing/transition signatures,
  the absence of conversions, exact-owner fail-closed handling, the exhaustive
  terminal census, and the stored-permit close seam. The Arc 04 CI job names 59
  unique exact controls: 48 ordinary and the same 11 `--ignored` native
  controls. The five additions are the four `v4_arc04h_*` setup/terminal
  controls and the repaired native-close retention control. Every one remains
  inside the exact one-test/non-vacuity parser. These are source counts, not a
  passing result; nothing in this subsection has been executed.

## 4. Named residuals

- **The channel binding is not session-unique.** The selected term is a DTLS
  certificate fingerprint pair. It is not an RFC 5705 exporter and does not
  cover the key exchange; two channels between the same device pair reusing the
  same certificates carry an identical binding. What it does prove is retained:
  an interceptor terminating DTLS on each leg presents its own certificate, so
  the fingerprints disagree and the signature fails. Replay separation across
  channels is carried by the two per-attempt CSPRNG contributions and by exact
  connector-incarnation ownership, not by the binding. Ownership invalidates
  already-issued tasks and capabilities on channel replacement; it does not make
  an otherwise-valid signature invalid.
- **A true exporter is deferred.** RFC 5705 export is implemented in
  `webrtc-dtls` but unreachable, since `DTLSConn.state` and
  `RTCDtlsTransport::conn()` are both crate-private, so reaching it would mean
  vendoring a third dependency while vendored-tree integrity is still an open
  gate.
- **The permit is not an independent admission.** `EndpointAuthPermit` is
  derived from the runtime of the `ConnectedChannelCapability` the task already
  owns, so what it attests is existing connected-channel ownership rather than a
  fresh pre-authentication admission decision. A real pre-authentication
  admission remains unimplemented and the permit must not be cited as evidence
  of one.
- **There is no runtime-mismatch cause on the issuer path, and one could not
  fire there.** The permit is minted from the connected capability's own
  runtime, because the engine holds no independent `RuntimeIncarnation` to
  compare it against. Exactness on install is carried instead by the retained
  binding record compared in `EndpointAuthTask::issued` and by
  connector-incarnation ownership. Two conjuncts of that record — binding
  profile and provenance — each have one variant today, so no control can
  falsify them until a second closed variant exists; that is a stated limit, not
  a passing control.
- **The RPC fence claims authorization atomicity, not cancellation.** A
  replacement landing after the mint does not cancel a running handler; the run
  is owner-bound, so its replies fail closed against a superseded installation.

## 5. Corrections applied at Arc 04H

- **The unproved size claim was removed.**
  `crates/myownmesh-core/src/endpoint_auth/task.rs` documented
  `PeerProofAcceptance::Promoted` as "the larger part of this enum by two orders
  of magnitude". No measurement stood behind that ratio. The boxing decision was
  never in question — only the quantified claim. The current text reads "the
  substantially larger of the two variants", which is what the shape supports,
  and no numeric ratio is asserted anywhere. Confirmed by reading the file; the
  edit itself belongs to the H1 slice, not to the documentation slice.
- **`PendingOpId` is described as what it is.** A process-local ownership token —
  a local capability for naming one filed pending entry again — and never network
  authority, durable state, route authority, or session authority. Any earlier
  wording that read it as an authority is superseded.
- **Stale retry-loop wording is fenced.** The Arc 04F note's sentence "a
  colliding draw retries, and an exhausted draw fails locally before anything is
  sent" is left standing as the dated record it is, with an inline editorial
  marker pointing at the G1 correction. The current shape — one draw, one claim,
  no retry — is what `docs/PROTOCOL.md` states, and no fundamental document
  carries the superseded wording.

## 6. Exact-head evidence ledger

**Historical, and anchored to exact heads.** Every entry below is stated as of
the head it names and does not attach to a newer one. A green run at a named
head is not evidence for any control added, renamed, or changed after that head,
and no entry here may be quoted as current status. The wording is moved from the
Arc 04G pull-request material rather than restated from memory; nothing has been
inferred, generalized, or upgraded in the move.

### Arc 04G, exact pushed head `7527d287224c93459f4c308cab39c197cab860ed`

- **Hosted CI, push event — run `31297776642`.** Completed successfully at that
  exact head: all seven jobs passed on their first attempt across Linux,
  Windows, macOS, aarch64-musl, and riscv64-musl. The Arc 04 job produced 54
  exact named `ok` lines and 54 exact one-test result lines, matching 43
  ordinary plus 11 `--ignored` controls. The Arc 03 compatibility job reproduced
  the 1 positive / 22 rejection / 4 authority-set / 5 real-time-flow boundary
  tally and passed the TURN endpoint-authentication control. No hosted retry is
  used as evidence.
- **Hosted CI, pull_request event — run `31297778613`.** Recorded by the Arc 04G
  integration as the companion seven-job green run at the same exact head. This
  record carries no per-job detail for it; the detailed job-level wording above
  belongs to `31297776642` and must not be transferred to this entry.
- **Independent local verification — complete for the gates it reached,
  incomplete overall. This is not a pass.** `HEAD`,
  `origin/arc/04-endpoint-auth`, and the PR head all equalled that exact head,
  and all cargo and boundary work ran serially under the sole build lock.
  Formatting, both boundary harnesses, the `-D warnings` library check,
  all-target Clippy, and the `transport-lab` library suite passed; that suite
  reported 606 passed, 0 failed, 35 ignored. The next feature-matrix gate did
  **not** complete: after compiling cleanly it reported 614 passed, 0 failed, 36
  ignored, then hung in the pre-existing control
  `v4_arc04_promoted_capability_retains_the_connected_claim_until_native_close`.
  That control's unchanged test seam observes a synchronous call counter before
  the returned future registers `Notify::notified()` and then uses
  `notify_waiters()`, which stores no permit, so under this run's scheduling the
  wake was lost. The process stayed at 0 CPU delta and 0 log growth over a
  controlled 45-second sample. The same close-port implementation and gate
  ordering are identical at the Arc 04F parent `8b325f6`; Arc 04G changed only
  the mechanical extraction of the promoted capability in that test. The run was
  stopped fail-fast and **not retried**, so the local 54-control replay and the
  workspace test gate were never run and no result may be claimed for them.
  Teardown left zero builders, removed only the verifier's lock after ownership
  confirmation, and reproduced the pre-run 416-file fingerprint exactly.

### Predecessor heads, preserved rather than flattened

- Run `31290492367` remains valid evidence for the Arc 04F head `8b325f6`. It is
  **not** Arc 04G evidence and was never presented as such.
- Arc 04E run `31281112185` and its failed predecessor `31236618911` remain in
  the history and were not flattened. Neither is evidence for any later head.
- The three superseded harness runs `31051812846`, `31054735382`, and
  `31054732818` belong to the Arc 03 record, remain non-evidential for every
  boundary there, and are non-evidential here for the same reason: they are Arc
  03 runs.

### Accepted advisories carried at Arc 04G

Recorded as limits, not as defects closed: the local Windows full-workspace gate
is exactly as stated above and hosted runs carry the cross-platform completion
evidence; `PendingOpId` identity relies on `Arc` allocating an `ArcInner` even
for a zero-sized marker, which is structurally sound and worth keeping explicit;
the proof guard reads adjacent files directly rather than by parameter, a
harness-style issue and not an authority gap; the guard's additional textual
`&&` check is weaker in isolation but does not weaken the combined property; the
F1 `LifecycleBarrier` remains test-only without a local deadline, so a future
rendezvous regression would fail by job timeout rather than quickly; and no
`cargo doc` gate was prescribed or run, so documentation links were spot-checked
rather than exhaustively rendered.

## 7. Completion gate

Arc 04 is production-*reachable*, not complete. The completion gate still
requires the signaling-MITM, no-payload-before-auth, cross-channel replay, and
DTLS binding controls to be run and cited at an exact pushed head. Given the
non-session-unique residual above, the cross-channel replay control is the one
that actually carries the guarantee, so it must be run and cited rather than
assumed.

Reject any claim that Arc 04 endpoint-authentication verification, authenticated
session authority, or final application flow authority is established before
exact-head evidence exists. Reject any citation of an Arc 03 run toward an Arc 04
control, and any citation of a control total in this record as a passing result.
