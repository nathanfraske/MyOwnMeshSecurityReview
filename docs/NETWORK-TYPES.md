# Network types and V4 authority

## V4 contract

The implemented V4 authority model is a canonical `FactGraph` of verified
`SignedFact` records, persisted by `DurableSemanticStore`. A fact is identified
by its content-derived `FactId`; its domain, mesh context, author, parents, and
explicit authority uses are verified before durable semantic admission. The
graph, not a roster file or quorum count, is the authority source.

The ordinary governance bodies are typed `RoleGrant { target, role }`,
`RoleRevoke { target }`, and `Evict { target }`. Their typed authoring requests
are exactly `NetworkCmd::ProposeRoleGrant`, `NetworkCmd::ProposeRoleRevoke`,
and `NetworkCmd::ProposeEvict`; a command is an authoring request, never an
authority bypass. `MembershipAdmit` and `OpenParticipation` are separate fact
bodies with separate cells. Same-cell `Resolution { cell, cited_heads,
selected_head }` is distinct from cross-cell `AuthorityLineageResolution`,
which carries its complete cited lineage.

`NetworkKind` is local configuration/profile shape (`open`, `closed`, or
`silent`), matched to verified bootstrap state; it is not a free-standing
authority fact. Topology and transport context are outside ordinary semantic
facts, and roster/member views are projections for UI and routing hints, not
authoritative state. There is no V4 quorum table, transition-log rewrite rule,
or split-network authority path.

The bounded exception for a closed-member relay is an explicit three-party
opaque endpoint session. A and B, then B and C, independently discover,
authenticate, and promote their exact legs. The endpoints establish the
route-bound `Open` / `Offer` / `Accept` sequence; A and C seal and open
plaintext, while B forwards only opaque ciphertext under exact route,
current-owner, and allocation-generation witnesses. The relay has no key
material. Its pending allocations, packet bytes, queues, retention, and
cleanup are finite under the configured `closed_relay` profile. A refusal
preserves pending handshake custody, and terminal tombstones make duplicate
or delayed predecessor `Close` controls harmless to successor generations.
Shutdown wakes bounded waiters, settles every relay custody class, and joins
owned tasks before completion.

## Removed legacy model

The former roster/two-log `NetworkState` model, including its quorum,
transition, split, persistence, and `network_state_*` wire authority, is
excluded from the V4 contract. It must not be reintroduced as an executable
architecture or used as an authority source. See the canonical
authority ownership rules in [`ARCHITECTURE-OWNERSHIP.md`](../ARCHITECTURE-OWNERSHIP.md)
and the migration disposition in
[`CURRENT-TO-TARGET-MIGRATION-MATRIX.md`](../CURRENT-TO-TARGET-MIGRATION-MATRIX.md).
