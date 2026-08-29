# V4 release-closure resource matrix

Status: evidence handoff for review `5058637044`, bound to source integration
commit `b719e48c0669a97cd5cf2413d7c73c486abed2a0`, tree
`067c4ce8b34f5869fe9412b17c79b3b086c91dd2`, parent
`7983f12587962806b153dae66d4cf18608bfa56b`. Serialized local evidence below
was captured against source-equivalent precommit bytes with the manifest, not
as exact-head reruns: fmt `d7e26845`; default check `7698b679`; transport
check `26926d73`; Clippy `f707a503`; default tests `5438d6bc`; transport tests
`37cf80a2`; scanner 8/8 `27b42f24`; workflow/manifest `325914b4`;
no-default release build `ce790598`; binary scan `91d3df7b`. Hosted CI
`33279629298` is in progress; field, firewall, packaging, and detached-
performance evidence remain pending.
PR #7 remains OPEN, draft, unmerged, and on HOLD.

"Finite" below identifies a source bound, not a capacity promise or SLO. A
downstream core admission does not retroactively fund or bound bytes allocated
inside an upstream carrier library.

## Ownership matrix

| Profile / boundary | Raw input | First funded or finite admission | Maximum retained unit / count | Queue / execution owner | Refusal | Terminal owner | Shutdown / join / baseline | Controls and evidence | Disposition |
|---|---|---|---|---|---|---|---|---|---|
| Unix control socket | Peer credentials, then framed request bytes | Listener and client both verify peer euid before reading or writing request bytes; bounded framing and funded dispatch follow | One bounded frame and exact funded request/reply/task custody | Authenticated connection task and funded reply owner | Euid mismatch, malformed/oversize frame, or provider refusal closes the exact connection/request | Reply terminal, or durable MFA state below | Stop accept, close socket, join connection tasks, require provider baseline | Same/foreign-euid controls; shared malformed/oversize/refusal controls; Unix unread-response MFA recovery | Advertised on Unix; execution and exact-head evidence pending |
| Windows control pipe | Named-pipe connection and framed request | Protected current-user DACL on the server; client verifies connected server SID before request bytes; shared bounded framing follows | One bounded frame and exact funded request/reply/task state; opaque OS buffers excluded | Pipe connection task and shared dispatch | ACL/SID mismatch, malformed/oversize frame, or provider refusal | Reply terminal and pipe task | Stop accept, close pipes, join tasks, require funded baseline | DACL/SID positive and mismatch controls plus shared framing/dispatch controls | Advertised on Windows; does not prove Unix euid or Unix crash choreography |
| Durable MFA Prepare | Prepare, exact Query/Redeliver, then exact Commit or Abort | Prepare durably creates or recovers one Prepared record before returning material | One Prepared record per exact network slot plus bounded secret/recovery hashes and one response copy | Custody store owns Prepared; response carries a redeliverable view | Conflicting Prepare, wrong/stale settlement, and Disable while Prepared refuse | Exact Commit makes Committed; exact Abort makes Absent | Prepared survives response loss and restart; transient response custody returns to baseline | Unread-first-response recovery, exact redelivery, explicit Commit/Abort, stale-successor and Disable-refusal controls | Advertised durable transaction. Strict `GovernanceMfaEnroll` and MFA `ProvisionalHandoff` ownership are deleted |
| LocalBroker | In-process `SignalingMessage` | Lab broker plus normal core admission | One owned fan-out copy per destination and exact funded emission | LocalBroker and lab carrier/attempt owners | Missing destination or derived pressure refuses the exact emission | Routed copy and lab attempt terminal | Drop handles, join lab forwarder, settle attempts, baseline | Local-carrier route/refusal and outbound-owner controls | `transport-lab` only; not an advertised production carrier or field proof |
| Core raw carrier adapter | Normalized carrier observation/raw frame | Exact AccountedMemoryBytes, ParsingOrCpuWork, and OpaqueDependencyResidual claim before core parse | One admitted raw observation/frame and exact carrier/attempt owner | Signaling runtime, carrier guard, engine attempt/session owner | Overflow/provider pressure returns typed Unavailable before parse/mailbox/reducer | Exact carrier/attempt/session terminal | Cancel recovery cohorts, settle carrier instances, join drivers, baseline | Raw-observation refusal/recovery and Nostr frame-provider accounting controls | Advertised core boundary; pre-core allocations remain carrier-owned |
| mDNS discovery callback | Browse/add/remove identities, TXT, addresses | Bounded callback strings/TXT/address counts and bounded queue permit before copies | Source caps on queue, names, TXT, addresses, aliases | Discovery backend task and alias owner | Invalid/oversize/full-queue input is refused or coalesced without orphan work | Discovery event/alias terminal | Stop producers, clear aliases, join pump/native workers | Callback bounds, alias/rebind/final-leave, queue and shutdown controls | Advertised bounded pre-core discovery; Cargo/audit/field pending |
| mDNS resolve | Coalesced service instance | Finite `ResolveOwnership` before resolve execution; checked generation is never reused after exhaustion | At most `MAX_RESOLVE_OWNERS`, one pending follow-up per active instance | Exact resolve lease, queue, native worker | Duplicate coalesces; cap/exhaustion/stale generation refuses | Exact resolve generation through finish/drop/cancel | Stop intake, invalidate owners, drain native workers in rounds, baseline | Coalescing, cap, cancel/drop, stale replacement, exhaustion and shutdown controls | Advertised bounded pre-core resolve; execution pending |
| mDNS TCP exchange | Accepted/connected stream and line/frame | Connection semaphore before split/allocation; pre-extension frame bound | `MAX_ACTIVE_CONNECTIONS`, bounded frame and bounded per-connection queues | Connection lease, reader/writer tasks, queued `OwnedSignal` | Slot/frame/queue pressure and stale generation close/refuse exact work | Connection slot and queued-line owner | Exact replacement/final alias signals stop; await top-level and connection tasks | Active-cap release, generation exhaustion, bounded line, alias replacement and stop/join controls | Advertised bounded mDNS exchange; Cargo/system backend/field pending |
| Nostr client | Primary/fallback WebSocket frames and messages | WebSocket config caps frame and message at 256 KiB before assembly; provider claim precedes JSON parse | 256 KiB frame/message plus finite delivery/session/attempt entries | Owned primary/fallback/outbound/announcer tasks and delivery store | Oversize/invalid input, closed store, or provider refusal creates no retained parse | Exact relay delivery, session, attempt, and parse owner | Close store, cancel attempts, await all owned tasks, baseline | Config/parser bounds, binary validity, inbound funding, closed-store-before-reserve, reconnect/delivery controls | Advertised bounded Nostr client; no production unmetered provider or public driver `start` |
| Self-host relay | TCP accept, handshake, WS frame/message, subscriptions, filters, events, presence | Finite nonzero Limits before bind; connection admission before handshake; bounded outbound channel | Finite connection, per-IP, handshake, frame/message, subscription/filter, event rate, stored event, presence membership, and outbound dimensions | Listener, connection/writer tasks, hub maps and bounded outbound sender | Exact over-cap/invalid input is refused; checked connection IDs do not wrap | Exact connection, store/presence entry, and outbound task | `stop_and_wait` closes intake and awaits listener, heartbeat, connection and writer tasks | Every-limit validation, admission/handshake/frame, checked-ID, presence cap/release, relay delivery/leave controls | Advertised finite relay; no public signal-only server stop or unbounded sender |
| Release build | Frozen source and declared platform/profile | Shipped daemon builds use `--no-default-features`; only explicit target features may be enabled | One declared binary/archive per workflow path; CI storage is external | Platform build/package job | Missing build or forbidden transport-lab marker fails | Exact artifact upload record | Job cleanup and exact-head artifact inventory | Static workflow/manifest check plus native release daemon build/scan; hosted target matrix pending | Advertised only after exact-head hosted evidence |
| Daemon/portable scan | Raw binary or ZIP/TAR.GZ stream | Scanner reads bounded chunks and requires every declared exact regular-file member to be present and nonempty | 64 KiB chunk plus marker overlap; archive member sizes remain archive/toolchain owned | Scanner stream/member owner | Missing artifact/member, duplicate expected member, non-regular or empty member, unsupported archive, or forbidden marker fails | Exact scan result | Close streams and retain exact artifact/run identity | Cross-chunk marker self-control and workflow/manifest invocation census; actual artifacts pending | Covers daemon and portable GUI archives. Current scanner does not independently prove checksums or signatures |
| Tauri GUI installer | Opaque platform installer emitted by Tauri tooling | Tauri/platform packaging job; it does not enter the portable archive scanner | Exact installer artifacts declared by the workflow | Tauri/platform toolchain and publisher | Build/package failure blocks that artifact | Installer publication record | Hosted job cleanup and artifact inventory | Platform build evidence pending | Separate opaque GUI-only artifact; excluded from daemon/portable scanner and updater-portable claims |

## Evidence still required

Each advertised row must ultimately bind an exact frozen SHA, configuration,
platform/toolchain, raw logs, terminal state, before/after resource baseline,
and run or artifact identifier. Refusal, cancellation, response loss,
disconnect, shutdown, and join paths must release transient custody. Pre-core
carrier bounds and joins need their own proof; a green core baseline cannot
discharge them.

The Unix MFA gate is durable state-machine evidence: Prepare persists before
response, an unread first response leaves Prepared intact, ordinary Prepare
redelivers identical material, and an exact Commit completes enrollment (or an
exact Abort removes it). There is no MFA `ProvisionalHandoff` choreography or
response-write rollback in current source.

## HOLD and non-goals

- HOLD remains until operator acceptance of frozen source, serialized Cargo,
  independent verification and audit, hosted exact-head CI, real-machine field
  qualification, firewall cleanup evidence where applicable, packaging, and
  detached performance characterization.
- This matrix creates no performance threshold, capacity/SLO, retry framework,
  package installation, firewall exception, public listener, or new manifest.
- It does not call LocalBroker a production carrier, treat carrier identity as
  governance authority, add application payload to signaling, or relabel OS,
  resolver, carrier-library, Tauri, or CI storage as core-provider funded.
- Durable MFA recovery is local custody recovery, not remote account recovery.
- Hosted CI `33279629298` remains in progress; field, firewall, packaging, and
  detached-performance qualification remain pending for review `5058637044`.
