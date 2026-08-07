# Endpoint Auth Task boundary

## Purpose

Own fresh mutual Device authentication for one exact connected channel. Arc 03 moves the connected-channel capability into this owner and binds its installation to the exact connector incarnation. Arc 04 added the verified transcript and the authenticated-channel transition.

## Owned state

The Arc 03 task owns connected-channel provenance. Its handoff records the exact process-local connector incarnation and cleanup owner. Arc 04 added the fresh transcript, ordered endpoint roles, exact mesh-context binding, the selected channel-binding terms (both endpoints' DTLS certificate fingerprints, which are not session-unique — see Residual), and the authenticated result. It added **no** independent resource admission: the permit attests the connected-channel ownership this task already holds. Exactness of channel identity is carried by the composition of per-attempt contribution freshness and process-local connector-incarnation ownership, not by the binding terms.

## Inputs

- one `ConnectedChannelCapability`;
- one `EndpointAuthPermit` per attempt. **It is not backed by a separate Arc 04 resource admission.** The landed constructor derives it from the runtime of the `ConnectedChannelCapability` the task already owns, so what it actually attests is existing connected-channel ownership, not a fresh admission decision. A real pre-authentication admission remains unimplemented; the permit must not be cited as evidence of one;
- fresh contributions from both endpoints in Arc 04;
- exact local and remote Device IDs, mesh context, and the selected channel binding in Arc 04 — the DTLS certificate fingerprints of **both** endpoints, in role-canonical order. Not an exporter; see Residual.

## Residual: the channel binding is not session-unique

The selected binding term is a DTLS **certificate fingerprint** pair. A certificate fingerprint identifies the certificate, not the session: reusing a certificate across connections yields the same fingerprint, and it does not cover the key exchange. It is therefore **not an RFC 5705 exporter**, and two channels between the same device pair reusing the same certificates carry an identical binding.

What the binding does prove is real and is retained: an interceptor terminating DTLS on each leg must present its own certificate, so the fingerprints disagree and the signature fails. That defeats the terminating signaling man-in-the-middle.

What it does not carry is replay separation across channels. **That is carried by the two per-attempt CSPRNG contributions and by exact connector-incarnation ownership, not by the binding.** If either weakens, the property is lost. Ownership invalidates already-issued tasks and capabilities on channel replacement; it does not make an otherwise-valid signature invalid.

A true exporter is deferred: RFC 5705 export is implemented in `webrtc-dtls` but unreachable, since `DTLSConn.state` and `RTCDtlsTransport::conn()` are both crate-private, so reaching it would mean vendoring a third dependency while vendored-tree integrity is still an open gate.

## Outputs

- `AuthenticatedChannelCapability` on complete verification;
- bounded authentication observations or a typed failure.

## Dependencies

This task depends on the connected-channel capability and the selected cryptographic profile. It does not depend on application payload, Open or Closed policy decisions, or durable projection.

## Resources

Endpoint-authentication work remains pre-authentication work. The connected transport claim stays owned until native close succeeds. Arc 02 defines the authentication permit type, but Arc 03 does not create a production issuer, admit authentication resources, verify the Arc 04 transcript, or infer a limit.

**Enforcement.** The capability is gated on, not merely stored. `PeerConnection::is_application_admitted` requires a live `AuthenticatedChannelCapability` **and** the existing approval policy, and every production application, reliable, and real-time admission gate routes through it. Reading `PeerStateData::authenticated` directly is not sufficient: that bool records policy history, survives channel replacement, and is deliberately left set by `retire_connector` — so a gate consulting it alone would keep admitting traffic after the authority artifact was dropped. Protocol admission traffic (Hello, AuthResponse, Approve, Deny) stays outside the gate, since it is what establishes the capability.

**Implementation status.** Arc 04 has landed the production issuer: `EndpointAuthTask::authenticate` is the sole path that mints an `EndpointAuthPermit` and an `AuthenticatedChannelCapability`, and `PeerConnection` owns the capability, dropping it whenever the connector is retired or replaced. This makes the arc *reachable*; it does not mark the arc complete. The completion gate still requires the signaling-MITM, no-payload-before-auth, cross-channel replay, and DTLS binding controls to be run and cited — and given the residual above, the replay control is the one that actually carries the guarantee.

`EndpointAuthError::RuntimeMismatch` is **not** a production control on the issuer path: the permit is minted from the connected capability's own runtime, because the engine holds no independent `RuntimeIncarnation` to compare against. It guards only the move-only `EndpointAuthAttempt::begin` constructor.

## Restart behavior

Possession of the permit or authenticated-channel capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. The transcript, permit, and capability are memory-only and disappear on process restart. Stored IDs or an old transcript cannot reconstruct them.

## Forbidden responsibilities

This task does not decide mesh policy, mint `SessionCapability`, authorize an application, choose a route, mutate durable facts, or treat a working channel as authenticated without the complete fresh proof.

## Compatibility adapter

`LegacyAuthenticatedChannel<T>` can hold a legacy object only beside an already-issued capability. It cannot create authentication or expose the raw object outside this owner. Arc 05 deletes it when Session Broker consumes the typed channel directly.
