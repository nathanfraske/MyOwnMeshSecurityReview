# Wire protocol

Every frame on the WebRTC data channel between two MyOwnMesh peers is
a JSON object tagged by a `kind` discriminator. The source of truth
for these types is `crates/myownmesh-core/src/protocol/`.

```
PROTOCOL_VERSION  = 1
SIGN_DOMAIN_TAG   = "myownmesh-mesh-auth-v1:"
TRYSTERO_APP_ID   = "myownmesh-cloud-mesh-v1"
```

A receiver that sees an unknown `kind` silently drops the frame. New
optional message kinds are gated per-peer via the `features` matrix
on the `hello` frame so a sender doesn't waste cycles on a peer that
doesn't speak them.

## Frame envelope

```jsonc
{
  "kind": "<discriminator>",
  // ...kind-specific fields
}
```

Each variant below lists its discriminator and the fields it carries.
All field names are snake_case.

---

## Handshake

### `hello`
First frame on a fresh data channel from each side.

| Field | Type | Notes |
|---|---|---|
| `protocol` | u32 | Wire-protocol version. v1 today. |
| `device_id` | string | Bare-pubkey Device ID (base32-lowercase, 52 chars). |
| `label` | string | Self-reported human label. Cosmetic. |
| `nonce` | string | Random 32-byte challenge, base32-lowercase. |
| `verification_code` | string | 6-char `[a-z0-9]`. Read aloud over voice. |
| `capabilities` | object? | `CapabilityAdvert` — see below. Optional. |
| `max_connections` | u32? | Hint to the topology selector. |
| `features` | string[] | Capability ids the sender claims. Must include `endpoint_auth_v1` — see below. |
| `app_version` | string? | Cosmetic. |

**The endpoint-authentication profile is advertised, and it is a hard
precondition rather than an optional-frame gate.** A `hello` whose
`features` list does not contain the exact id `endpoint_auth_v1` is
refused with a typed incompatible-auth-profile failure, and that refusal
happens *before* any proof work: before the peer's contribution is
parsed, before it is bound to the attempt, before any transcript is
assembled, and before any signature is produced or verified. Nothing is
signed for a peer that cannot be authenticated.

There is exactly one closed profile and no way to select another, so
this is advertisement, not negotiation: a peer states that it speaks the
one profile, it does not choose among several. There is no fallback, no
downgrade path, no free-form profile string, and no third outcome — the
selection either resolves to the single closed profile or fails closed.
A peer that omits the id is dropped with an explicit diagnostic naming
the required id, rather than being allowed to proceed to a signature
check and surface as a generic bad-identity failure.

The other side signs the Arc 04 endpoint-auth transcript (see
[Handshake signature](#handshake-signature)) with their ed25519 secret
key and returns the signature in `auth_response`. `nonce` is that
endpoint's per-attempt contribution: a fresh 32-byte CSPRNG draw,
base32-lowercase, accepted only in that exact canonical encoding. Both
sides send one, and both are bound into the signed transcript.

### `auth_response`
Proves possession of the secret key matching `hello.device_id`, over the
exact endpoint-auth transcript for this attempt — not over a bare nonce.

| Field | Type | Notes |
|---|---|---|
| `signature` | string | Base32-lowercase ed25519 signature over the Arc 04 endpoint-auth transcript (`ENDPOINT_AUTH_DOMAIN_TAG`, length-prefixed, role-canonical — see [Handshake signature](#handshake-signature)). Not the legacy `SIGN_DOMAIN_TAG` payload. |

A peer's contribution binds an attempt exactly once, and an
`auth_response` that arrives before anything is bound is terminal rather
than merely refused. A second `auth_response` reaching an
already-promoted attempt is a distinct non-error outcome and is never
reported as a failure cause. Both rules are stated in full under
[Handshake signature](#handshake-signature).

### `approve`
Sent once the local side has cleared the peer (either auto-approved
from the roster, or the user clicked "approve"). Empty payload. Both
sides must observe each other's `approve` before the connection
transitions to ACTIVE.

### `deny`
Sent when the local side rejects the peer. Carries an optional reason
string. The peer should not reconnect until the user approves again.

| Field | Type | Notes |
|---|---|---|
| `reason` | string? | Optional human-readable explanation. |

---

## Keepalive

### `ping` / `pong`
| Field | Type | Notes |
|---|---|---|
| `t` | i64 | Sender's monotonic timestamp (ms). Echoed back unchanged so the sender can compute RTT against its own clock. |

`ping` cadence: `HEARTBEAT_INTERVAL_MS = 30_000`. Silent peers past
`HEARTBEAT_TIMEOUT_MS + WAKE_DETECTION_THRESHOLD_MS` (~75 s) escalate
to Tier 4 re-handshake.

---

## Topology

### `shelve`
"I'm not going to send you application traffic for now — keep the
data channel open as a heartbeat path."

| Field | Type | Notes |
|---|---|---|
| `reason` | string? | Surfaced in the Activity log. Optional. |

### `unshelve`
Reverses `shelve`. Empty payload. The receiving side may now expect
app traffic again.

Each side tracks `local_shelved` (we sent shelve) and `remote_shelved`
(they sent it) independently. A connection is effectively shelved
when either flag is set.

---

## Capabilities

### `capabilities_update`
Push an updated `CapabilityAdvert` to peers. Receivers replace their
cached copy wholesale.

| Field | Type | Notes |
|---|---|---|
| `capabilities` | `CapabilityAdvert` | New advertisement. |

### `CapabilityAdvert` shape
| Field | Type | Notes |
|---|---|---|
| `tags` | string[] | Embedder-defined capability tags. |
| `app_version` | string? | |
| `max_connections` | u32? | |
| `extra` | json | Embedder-defined structured advertisement. |

---

## RPC

### `rpc_request`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | Caller-generated, unique within in-flight map. |
| `method` | string | Embedder-defined dispatch key. |
| `payload` | json | Opaque to the mesh. |
| `streaming` | bool | When true, expect `rpc_stream_chunk`+`rpc_stream_end` rather than `rpc_response`. |

### `rpc_response`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | Echoes the request id. |
| `ok` | json? | Result payload on success. Mutually exclusive with `error`. |
| `error` | string? | Error message on failure. |

### `rpc_stream_chunk`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | |
| `seq` | u64 | Monotonic sequence number. WebRTC preserves order, so this is informational. |
| `payload` | json | One chunk of the streamed response. |

### `rpc_stream_end`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | |
| `error` | string? | Set when the stream terminated abnormally. |

---

## Application channels

### `channel`
Carries embedder payloads on a named typed channel. The mesh treats
the payload opaquely; embedders define their own serialization via
`Channel<T>`.

| Field | Type | Notes |
|---|---|---|
| `channel` | string | The channel name; same on both sides. |
| `payload` | json | The serialized application body. |

---

## Handshake sequence

```
Side A                                              Side B
  │                                                  │
  ├── hello {device_id, nonce, code, ...} ─────────▶ │
  │ ◀───────── hello {device_id, nonce, code, ...} ─┤
  │                                                  │
  │ verifies B's claimed device_id against pubkey ─▶ │
  │ ◀────────── auth_response {signature(payload)} ─┤
  ├── auth_response {signature(payload)} ─────────▶ │
  │                                                  │
  │   each side either:                              │
  │     a) finds peer in roster → auto-approve       │
  │     b) prompts user with verification_code       │
  │                                                  │
  ├── approve ───────────────────────────────────▶  │
  │ ◀──────────────────────────────────── approve ──┤
  │                                                  │
  │            ACTIVE — app traffic flows            │
  │ ◀──── ping / pong / channel / rpc_* / shelve ──▶│
```

### Handshake signature

The exact byte-shape of the domain-tagged transcript that both sides
sign. Every field is length-prefixed `len:value`, and each of the two
sides derives byte-identical input because every paired field is
ordered by role, not by which endpoint is local:

```
ENDPOINT_AUTH_DOMAIN_TAG
  + f(mesh_context)              # canonical network id
  + f(crypto_profile)            # fixed selection, "ed25519-dtls-v1"
  + f(signer_role)               # "initiator" | "responder"
  + f(initiator_device_id) + f(responder_device_id)
  + f(initiator_contribution) + f(responder_contribution)
  + f(initiator_fingerprint) + f(responder_fingerprint)
```

where `f(x) = len(x) + ":" + x`, `ENDPOINT_AUTH_DOMAIN_TAG =
"myownmesh-endpoint-auth-v1:"`, roles are derived from the device pair
rather than chosen, and the fingerprints are the DTLS certificate
fingerprints of **both** endpoints. Length prefixes — rather than `|`
separators — make the encoding injective, so no field value can shift a
later field boundary and make two distinct tuples sign identical bytes.
Device IDs are the canonical base32-lowercase pubkey portion (display
suffixes stripped). Each side verifies its own half as well as the
peer's, so a proof is mutual rather than one-directional.

This is a hard cutover. The legacy
`SIGN_DOMAIN_TAG + nonce + "|" + my_device_id + "|" + their_device_id`
payload (`crate::signing::handshake_payload`) is retained as a helper
for other callers but is neither produced nor accepted on the live
`hello`/`auth_response` path, and there is no feature-negotiated
fallback: domain separation means an older peer fails authentication
rather than negotiating down, so a downgrade is not attacker-selectable.

The cutover is also *diagnosable* rather than silent. Because the
profile is advertised on `hello` (see [`hello`](#hello)), a peer running
the old format is refused explicitly, by name, before any proof work —
instead of being told only that a signature did not verify, which reads
identically to a wrong key or a tampered transcript. The signed
transcript still binds the selected closed profile, so the
advertisement decides only whether an attempt begins; it can never
widen or replace what the transcript commits to.

**Where the two fingerprints come from.** Both are read from the
connector's own live native session, after that session exists, and
never from a peer-supplied protocol field:

- the **local** component is the `a=fingerprint:` line of this
  endpoint's *applied local description* — the certificate this side
  presents on the DTLS channel;
- the **remote** component is the `a=fingerprint:` line of the
  *applied remote description* — the certificate the peer said it
  would present.

What ties the remote component to the peer that is actually on the
wire is the **native DTLS stack, not MyOwnMesh**: WebRTC verifies the
certificate presented during the DTLS handshake against the
`a=fingerprint:` in the SDP it received, and the connection does not
come up if they disagree. MyOwnMesh neither reads nor validates the
certificate itself. It reads an already-applied, already-enforced SDP
attribute and commits to it.

Stated plainly, because both of these are easy to over-read: this is
**not** an RFC 5705 exporter, and it is **not** a raw certificate or a
public-key read. It is a fingerprint string taken from applied SDP.

The pair is also not session-unique — two channels between one device
pair reusing the same certificates carry the same value. It defeats a
terminating signaling-path man-in-the-middle, which must present its
own certificate on each leg; separation of one channel from another is
carried by the per-attempt contributions and by connector-incarnation
ownership. This is a named, accepted residual rather than a closed
question, and nothing below narrows it.

Both fingerprints are required. If either the local or the remote
component is absent, the channel is **not** authenticated with a
partial transcript and is **not** allowed through unauthenticated: the
open path fails closed before an attempt begins. A transcript is only
ever signed over a fingerprint pair both endpoints actually stated, so
an absent component can never be silently encoded as an empty field
that two peers might agree on.

Failing closed there is a *cleanup* obligation as well as a refusal.
The channel that cannot be bound is fenced — exactly one native close
is started, synchronously, because nothing else will start it later —
and only then is the peer entry removed, and only if it is still the
exact entry this open was admitted for. A replacement installed for
the same device while the binding was being read is left untouched:
the refusal is about one channel, not about the device. No task is
built, no `hello` is sent, no proof is computed, and no profile is
negotiated. The refusal states nothing about certificates.

A peer's contribution binds an attempt exactly once. A retransmitted
`hello` carrying the *same* contribution is answered from the cached
proof — no second draw, no second signature — and none of its other
fields are adopted, so a late frame cannot rewrite the label,
verification code, advertised features, or capabilities of an attempt
that is already bound. A `hello` carrying a *different* contribution is
not a retransmission; it is a typed terminal conflict that retires the
attempt.

An `auth_response` that arrives before anything is bound is terminal,
not merely refused. There is no transcript for it to be a proof *of* —
this endpoint has drawn its half and no peer half exists — so the
frame cannot become valid later, and leaving the attempt live would
hold a channel claim open for a peer that has already violated the one
ordering the exchange has.

**Two refusal domains, and a receiver must not confuse them.** Refusing
an *input* and terminating an *attempt* are separate outcomes with
separate closed types, and there is no conversion between them in either
direction.

- **Setup refusals** (`EndpointAuthSetupError`) say the input was
  unusable and nothing was harmed: an empty mesh or Device identifier,
  an absent contribution, a contribution whose decoded value is not
  exactly the full draw width, a contribution not in canonical
  lowercase BASE32-nopad, or a `hello` that does not advertise
  `endpoint_auth_v1`. These fire *before or beside* an attempt — the
  advertisement gate in particular runs on the inbound `hello` before
  the attempt is reached — so no attempt has been terminalized when one
  of them fires.
- **Terminal failures** (`EndpointAuthError`) say this attempt is over.
  They come only from the two intake transitions, and there are exactly
  six: no bound transcript, non-mutual Device pair, unfresh
  contributions, invalid signature, channel no longer current, and a
  conflicting peer contribution. Each means the attempt is retired,
  belongs to no connector, and vouches for nothing.

The receiver's behaviour on the wire is the same for both domains: it
drops the exact current peer, keyed on the installation the frame was
admitted for, so a replacement is never dropped for its predecessor's
refusal. What differs is what the outcome *claims*. Sharing one
vocabulary would have let "a string did not parse" read as "a task
died".

`AlreadyPromoted` is the one non-terminal proof outcome and is in
neither domain: it is not a failure, and it is described in full below.

Terminal causes are **first-cause**: an attempt that has already failed
keeps the error that actually refused it. This matters because ordinary
teardown reaches the same terminal path a refusal does — a refused
proof removes the peer, and peer removal retires the task — so without
the rule, the recorded cause of a refusal would depend on scheduling and
a signature failure could be reported as an ordinary channel
replacement.

An attempt has exactly one way to end, and it ends under the same lock
every operation takes. Retirement acquires that lock first and marks
nothing before it, so there is no interval in which the attempt reports
itself dead while an operation already inside the critical section is
still free to sign a transcript or hand the channel over. A retirement
racing a `hello` or an `auth_response` therefore either reaches the
state first — and that operation refuses before signing or promoting
anything — or it waits, and the operation it lost to has completed
before the retirement is observable at all. Successful promotion is
deliberately *not* one of these terminal endings: a promoted attempt
still belongs to its connector, still answers a retransmitted `hello`
from its cache, and still vouches for what it issued.

A second `auth_response` reaching an already-promoted attempt is
therefore not a failure at all. It is a distinct non-error outcome, and
it is deliberately not expressed as one of the failure causes, so that
a refusal always means *this attempt is over* and never means "this
frame had nothing to do". A receiver never has to consult its own state
to work out which of the two senses a refusal carried.

That outcome states exactly one thing: this attempt had already moved
its channel out. It does **not** say the replayed signature verified —
the attempt's state is read before any verification, and a promoted
attempt has no channel left to promote in any case, so those bytes are
never examined and any bytes at all produce the same outcome. It also
does **not** say the authenticated channel was ever installed:
promotion hands the authenticated capability to whichever caller won
the promotion, and what that caller then did with it is outside the
attempt. The receiver therefore corroborates, against its own state,
that an authenticated channel really is installed for this exact
attempt, and drops the peer when it cannot. A promotion that moved the
channel out and then failed to install what it was handed must not be
indistinguishable from one that completed, or it would leave a peer
alive and unauthenticated.

### RPC response binding

A `request_id` is a routing key. It is **not** an authority, and on its
own it settles nothing.

Every in-flight local call additionally records the one canonical
device that may answer it and the one response class it will accept.
An inbound `rpc_response`, `rpc_stream_chunk`, or `rpc_stream_end` is
matched against both, and the source is taken from the identity the
transport authenticated for that frame — never from the frame's own
contents, so a sender cannot nominate its own authority. A frame
failing either test performs no action at all: nothing is removed,
nothing is mutated, and the rightful caller's operation is left exactly
as it was. Concretely, one peer cannot resolve another peer's pending
call, inject chunks into another peer's stream, or end one early; a
single response cannot settle a stream, and a stream end cannot settle
a single-response call.

The binding is to the **device**, not to the connector installation. A
peer that drops and re-authenticates mid-call returns on a fresh
connector under the same canonical device id, and that is a legitimate
completion of a still-pending operation, so it is allowed. A different
device is never allowed. This deliberately differs from an inbound
`rpc_request`, which binds to the exact installation because it
authorizes running a local handler rather than resolving a call the
local caller is already waiting on.

Request ids are drawn locally and are never reused to displace an
in-flight operation. A call draws exactly one id and claims it in a
single step. If that id is already owned the call fails locally and is
never sent, rather than overwriting: displacing the owner would strand
that caller on a reply that can never arrive and hand its answer to the
wrong receiver. There is no redraw, no retry and no attempt counter.
The collision is handled explicitly rather than assumed away: at 96
bits of entropy per draw it is negligibly unlikely, not impossible, so
it gets a named local failure and the call is not sent. What a bounded
redraw bought was nothing — "never displace" is total either way — and
what it cost was clarity, because a loop reads as a policy that will
eventually take the id when the honest answer is that it will not try.

Withdrawal is by identity, not by binding. When an outbound send fails,
the call withdraws its own pending entry, and the entry it removes is
the *exact* one it filed — named by a process-local identity that is
never serialized, never sent, never derived from anything a peer
supplies, and never consulted by any inbound path. The device-and-class
binding above is the right test for an inbound frame, which cannot know
an identity and must not have to, and the wrong test here: it describes
a *class* of operations rather than one. A withdrawal that ran late —
after its own entry had already been settled by a response that raced
the failing send, and after the id had been redrawn by a fresh call to
the same device in the same class — would match that newcomer on every
coordinate and remove a live operation, leaving its caller waiting on a
reply no inbound frame could reach.

---

## Forward-compatibility rules

1. **Unknown `kind`**: receiver silently drops the frame. New
   message kinds added in future revisions don't break older peers.

2. **Unknown fields**: serde deserialization ignores extra fields by
   default. Embedders can add fields to `CapabilityAdvert.extra` without
   protocol-level coordination.

3. **Optional fields with sensible defaults**: a v1 receiver missing
   an optional field treats it as the default (`None`, empty list,
   etc.).

4. **`features` gate optional message kinds**: senders consult the
   peer's advertised `features` list before sending an optional frame.
   Older peers that don't advertise a feature don't receive it.

   **`endpoint_auth_v1` is the one exception and is not
   forward-compatible by design.** It is a required precondition, not an
   optional-frame gate: a peer that does not advertise it is refused,
   not merely sent less. Absence fails closed with a typed refusal
   before any proof work rather than degrading to anything weaker, which
   is exactly what makes the Arc 04 cutover hard. Treat it as a
   compatibility break against pre-Arc-04 peers, and never as a feature
   a sender can route around.

5. **Bump `PROTOCOL_VERSION` only when an existing message's shape
   changes incompatibly.** Additive changes don't bump.

---

## Signaling envelope (Nostr)

Out-of-band signaling splits across two Nostr event kinds by message
class:

- **Presence / announce** travels as a NIP-01 *stored* regular event,
  **kind `1077`** (stored range 1000–9999). Stored so a late joiner's
  `REQ since=now-300s` is replayed by the relay with everyone's recent
  announces — without that, discovery degenerates into a star around
  whichever existing peer happens to re-announce inside the new
  joiner's window.
- **Connection negotiation** — offer / answer / ICE candidate / leave —
  travels as an *ephemeral* event, **kind `21077`** (ephemeral range
  20000–29999), which relays forward live but never persist. Negotiation
  is point-in-time and must not be replayed onto a future session, so it
  is deliberately ephemeral.

The driver subscribes to both kinds, and the receive path enforces the
split: an announce is honoured only on `1077`, an
offer/answer/candidate/leave only on `21077` (so a stale directed
message replayed from history is dropped). Constants
`SIGNALING_EVENT_KIND = 1077` and `SIGNALING_EPHEMERAL_KIND = 21077`
live in `crates/myownmesh-signaling/src/nostr/event.rs`.

The event content is a JSON envelope:

```jsonc
{
  "from": "<sender device_id>",
  "to":   "<recipient device_id, or null for broadcast>",
  "kind": "offer" | "answer" | "candidate" | "leave" | "announce",
  ...kind-specific fields
}
```

Room tag: `["r", "<room_handle>"]` where the handle is
`SHA-256(app_id || ":" || network_id)` — deterministic across
runtimes so two peers using the same `(app_id, network_id)` land in
the same Nostr room.

Periodic announce cadence: one publish on startup, one safety-net
re-publish at +30 s, then every 2 min (`ANNOUNCE_BACKOFF_MS` +
`ANNOUNCE_STEADY_MS` in `crates/myownmesh-signaling/src/upstream.rs`).
Discovery doesn't rely on the periodic cadence — it relies on the
relay's storage of our last announce plus engine-side reactive
reflection on every inbound announce (`engine::handle_signaling_inbound`).
The periodic publish is only there to refresh storage inside the
relay's retention window.

Full Nostr-driver behavior — relay selection, subscription replay
on reconnect, transition-only logging — is documented in
`crates/myownmesh-signaling/src/upstream.rs`.
