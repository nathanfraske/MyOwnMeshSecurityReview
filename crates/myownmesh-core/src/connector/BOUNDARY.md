# Connector worker boundary

## Purpose

Own native connector work and turn one admitted candidate into a live connected channel. Arc 03 places the existing WebRTC runtime behind this owner without changing its transport protocol.

## Owned state

`WebRtcConnectorWorker` holds connector-native attempt state, one live channel, its callback incarnation, pending remote candidates, cleanup state, and optional connector-native flow state.

## Inputs

- one `ConnectorCandidateCapability` consumed by the connector;
- typed candidate updates and connector callbacks;
- bounded cancellation and observation requests.

## Outputs

- `ConnectedChannelCapability` after the channel is proven to work;
- connector observations, failure, or cleanup completion.

The connector issues no separate real-time authority. Real-time work is authorized by the promoted session that owns the flow set, which the engine mints under its registry fence; the connector only carries units for flows that session already opened.

## Dependencies

The connector depends on the attempt capability and its connector-specific transport implementation. It does not depend on application codecs, durable semantic projection, Open or Closed policy, or application authorization.

## Resources

Connector work remains covered by the child reservation owned by the consumed candidate. Promotion explicitly transfers the opening claim to a connected claim. The connected claim moves into Endpoint Auth Task, while the connector cleanup owner retains release responsibility through successful native close. A returned close error or cleanup-start failure retains only that connector's exact claim. A native close that does not return remains `Closing` and retains its finite claim. No timer changes that state. Aggregate accounting corruption remains process-fatal because the total can no longer be proved. Arc 03 observes known WebRTC ownership sites, but complete dependency resources remain outside the structural claim.

## Restart behavior

Possession of a connected-channel capability grants the authority represented by that type. Its process-local connector incarnation grants no authority. The incarnation only prevents a handoff from being installed against another connector, including a replacement in the same runtime. Connected-channel capabilities and native channel objects are memory-only and disappear on process restart. Public labels and stored diagnostics cannot recreate them.

## Forbidden responsibilities

This worker does not mint session authority, decide mesh authorization, authenticate a Device, parse application payload meaning, mutate durable facts, or forward application data through signaling. The compatibility real-time capability names no codec, media kind, or application lane meaning. A final real-time capability must be session-bound, principal-bound, policy-guarded, and independently resource-reserved.

## Compatibility adapter

`LegacyConnectedChannel<T>` keeps the current native channel object beside an already-created capability. It cannot create authority from the legacy value.

Arc 04 endpoint authentication now consumes the connected channel directly: the connector's `EndpointAuthHandoff` carries capability, connector incarnation, and close owner together, `EndpointAuthHandoff::into_generic` narrows it to the transport-neutral `ConnectedChannelHandoff`, and `EndpointAuthTask::begin` takes that whole value — so the close-owner retention travels with the promotion. `LegacyConnectedChannel<T>` was **not** deleted by that change and still exists; its removal remains Arc 05's.
