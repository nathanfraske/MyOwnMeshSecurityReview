# Relay Node boundary

## Purpose

Own exact bounded opaque relay allocations. The production runtime admits a
provider-backed `RelayAllocationPermit` only after the engine binds the exact
closed-member witnesses and owner-selected finite profile.

## Owned state

The target owner holds exact allocation endpoints, both directional bounded
queues and buffers, allocation lifetime, and relay-local observations. Endpoint
key material remains outside this boundary.

## Inputs

- one exact allocation request tied to live attempt or session authority;
- exact permitted destination and endpoints;
- one `RelayAllocationPermit` from resource admission;
- typed payload-blind carrier bytes.

## Outputs

- one exact opaque relay allocation or typed failure;
- bounded allocation, bandwidth, buffer, and lifetime observations.

## Dependencies

Relay Node depends on typed attempt or session ports and the selected relay profile. It does not depend on application parsing, signaling service identity, durable governance mutation, or arbitrary next-hop selection.

## Resources

Pre-authentication handshakes and post-authentication relay data use separate
reviewed resource families. The permit reserves the retained relay allocation;
the immutable profile supplies every allocation, queue, lifetime, bandwidth,
control, and shutdown bound.

## Restart behavior

Possession of an allocation permit grants only the exact provider-backed
allocation represented by that type. Session witnesses prevent use against a
replacement endpoint. The permit remains owned through shutdown grace and is
released exactly once by settlement. Allocations disappear on process restart;
public destinations, route labels, and stored records cannot recreate them.

## Forbidden responsibilities

This node does not authenticate endpoints, mint sessions, parse application payload, fan out to ordinary mesh members, authorize a destination from a public label, or treat relay identity as peer identity.
