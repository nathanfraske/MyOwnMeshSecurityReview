# Arc 03 WebRTC connector ownership red team

Status: Arc 03H executable review record. Fork PR #4 remains draft, unmerged, and held at `f180373c732c0a42a1f50c51f184d5ce88615d20`. Passing this record does not authorize merge or select a production resource value.

## 1. Isolation and exact-head commands

Run socket-bearing checks only inside Ubuntu 24.04 WSL. Do not run Windows test binaries. This keeps the controls away from live Windows MyOwnMesh processes and avoids per-binary Windows Firewall prompts.

```powershell
$repo = (Resolve-Path "C:\Users\Admin\MyOwnMesh Security Audit\MyOwnMeshV4Transition").Path
$target = "/tmp/mom-arc03h-red-team"

wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target /root/.cargo/bin/cargo fmt --all -- --check
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target /root/.cargo/bin/cargo check --workspace --all-targets -j 16
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target /root/.cargo/bin/cargo clippy --workspace --all-targets -j 16 -- -D warnings
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target /root/.cargo/bin/cargo test --workspace --no-fail-fast -j 16 -- --test-threads=1
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target /root/.cargo/bin/cargo test -p myownmesh-core --features legacy-v1,legacy-media,transport-lab --no-fail-fast -j 16 -- --test-threads=1
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target /root/.cargo/bin/cargo test -p myownmesh --features legacy-v1,legacy-media --no-fail-fast -j 16 -- --test-threads=1
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target RUSTFLAGS="-D warnings -D deprecated" /root/.cargo/bin/cargo check -p myownmesh-core --lib
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target RUSTFLAGS="-D warnings -D deprecated" /root/.cargo/bin/cargo check -p myownmesh --lib
wsl.exe -d Ubuntu-24.04 --cd $repo env CARGO_TARGET_DIR=$target PATH=/root/.cargo/bin:/usr/bin:/bin python3 scripts/check-v4-arc03-compiler-boundaries.py
```

After retaining the logs, remove only this target:

```powershell
wsl.exe -d Ubuntu-24.04 -- rm -rf /tmp/mom-arc03h-red-team
```

## 2. RT-03-01: manufacture connector capacity

Attack: construct a worker, process owner, Mesh child, or candidate capability without the process and exact-Mesh reservation.

Required result: external code cannot construct those authorities. One process aggregate and one exact child update atomically. Conflicting process policy and exhausted child capacity fail closed.

Controls:

- `v4_arc03d_process_root_shares_one_connector_limit_across_mesh_runtimes`
- `v4_arc03e_mesh_ceiling_isolates_children_inside_the_process_cap`
- `v4_arc03e_concurrent_children_never_oversubscribe_either_ceiling`
- cause-matched compiler rejections for private resource and worker constructors

## 3. RT-03-02: cancel native construction

Attack: cancel after native allocation, after delivery, during caller runtime shutdown, or after a construction failure.

Required result: one close owner owns every partial or delivered result. Successful close releases the claim. A returned close error retains the exact claim. Caller cancellation cannot cancel cleanup ownership.

Controls:

- `v4_arc03_cancelled_construction_closes_partial_native_peer`
- `v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim`
- `v4_arc03_cancelled_delivered_result_closes_native_peer_before_release`
- `v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed`
- `v4_arc03_background_construction_failure_closes_partial_native_peer`

## 4. RT-03-03: race close against authority promotion

Attack: commit close immediately before channel-open promotion or temporary legacy real-time admission.

Required result: both transitions acquire the same operation fence. If close wins the fence, no `ConnectedChannelCapability`, Endpoint Auth handoff, or real-time capability is created.

Controls:

- `v4_arc03h_close_wins_before_open_promotion` in WSL
- `v4_arc03h_close_wins_before_legacy_realtime_admission` in WSL
- `v4_arc03g_close_fence_rejects_endpoint_send_realtime_write_and_lane_open` in WSL

Residual: this proves the enumerated Arc 03 connector paths. It is not repository-wide proof that every application behavior uses this fence.

## 5. RT-03-04: hide producers behind a full callback mailbox

Attack: fill a callback mailbox, then submit one or many later callbacks while the receiver is stalled.

Required result: insertion returns a typed overload without awaiting capacity. No producer future accumulates behind `reserve().await`, and no second callback queue exists.

Controls:

- `v4_arc03h_full_mailbox_does_not_hide_a_producer_before_close`
- `v4_arc03h_callback_producer_flood_cannot_queue_behind_full_mailbox`
- source rejection of callback `reserve().await`

## 6. RT-03-05: reorder channel-open and endpoint protocol data

Attack: place the scheduler cursor on endpoint data while `DataChannelOpen` and the first handshake message are both queued. Replace or retire the connector before open commits.

Required result: endpoint protocol data remains in its bounded mailbox until exact open promotion. Retirement drops it and releases its observation.

Controls:

- `v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor`
- `v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol`
- `v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation`

## 7. RT-03-06: flood remote candidates before and after SDP

Attack: submit unique and duplicate candidates on both sides of remote SDP, delay application, cancel application, and continue until application-work capacity is exhausted.

Required result: one ICE-attempt envelope bounds unique items, candidate content bytes, duplicates, and native application work. Application does not reset the envelope. Only a new attempt or successful explicit ICE restart renews it.

Controls:

- `v4_arc03g_candidate_queue_deduplicates_before_retention_and_enforces_both_bounds`
- `v4_arc03h_candidate_digest_is_structurally_unambiguous`
- `v4_arc03h_candidate_content_bytes_cover_every_candidate_content_field`
- `v4_arc03h_candidate_attempt_envelope_survives_delayed_apply_and_cancellation`
- `v4_arc03h_post_sdp_candidates_share_one_cumulative_attempt_envelope`
- `v4_arc03h_new_attempt_gets_a_fresh_candidate_envelope`

The content-byte limit is not an exact retained-memory limit. Candidate retained-memory observations must remain inexact.

## 8. RT-03-07: start codec work from generic real-time enablement

Attack: enable codec-neutral real-time ownership with no provider, or present a track callback anyway.

Required result: no compatibility tracks are provisioned. An inbound transceiver without a provider is stopped. H.264 and Opus processing starts only from the explicit temporary provider.

Controls:

- `v4_arc03g_generic_realtime_policy_does_not_request_media_tracks`
- `v4_arc03h_generic_realtime_without_provider_allocates_no_codec_tracks` in WSL
- `v4_arc03f_data_only_connector_allocates_no_realtime_tracks` in WSL

Residual: the no-provider native control proves the current WebRTC construction and callback path. It is not a claim that arbitrary future provider code cannot be added.

## 9. RT-03-08: confuse codec or lane identity

Attack: send VP8 as video, H.264 as audio, malformed track names, wrong prefixes, or out-of-range lane numbers.

Required result: the temporary provider accepts only H.264 `video-N` and Opus `audio-N` tracks within the reviewed profile ceiling. Lane numbers use canonical unsigned decimal spelling. Invalid tracks are stopped, not mapped to lane zero.

Controls:

- `v4_arc03h_legacy_provider_rejects_wrong_codec_and_malformed_track`
- `v4_arc03h_legacy_lane_ceiling_matches_the_fixed_provider`
- `v4_arc03h_legacy_h264_fragment_policy_cannot_exceed_adapter_hard_stop`

## 10. RT-03-09: sustain pre-promotion RTP work

Attack: send valid-looking RTP indefinitely before connector promotion.

Required result: one cumulative packet and content-byte envelope bounds the speculative track. Exhaustion stops the transceiver. There is no timer, token window, or rate reset.

Controls:

- `v4_arc03h_sustained_pre_auth_rtp_exhausts_a_finite_cumulative_envelope`
- source rejection of real-time useful-lifetime and expiry inputs

## 11. RT-03-10: corrupt cross-domain real-time accounting

Attack: underflow or overflow the inbound or outbound connector-owned byte and unit counters.

Required result: the damaged domain is charged to its full ceiling and refuses later admission. Independent domain counters prevent an unproven shared total from creating capacity. The other domain remains governed by its own ceiling.

Controls:

- `v4_arc03_realtime_accounting_corruption_fails_closed`
- `v4_arc03f_inbound_and_outbound_flow_slots_cannot_starve_each_other`

Residual: native WebRTC allocations outside connector-owned leases are not included in this proof.

## 12. RT-03-11: retain unbounded real-time units

Attack: send oversized fragments, too many fragments, many incomplete units, a silent incomplete unit, reordered units, and full complete-unit queues.

Required result: every connector-retained unit has structural per-flow and byte bounds. Complete queues use deterministic `DropNewest`. A silent partial unit keeps only its finite admitted claim until a concrete owner event releases it.

Controls:

- `v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention`
- `v4_arc03f_realtime_fragment_count_is_structurally_bounded`
- `v4_arc03f_in_progress_unit_limit_is_enforced_per_flow`
- `v4_arc03f_silent_partial_unit_retains_only_its_finite_claim_until_owner_drop`
- `v4_arc03f_complete_realtime_unit_has_no_wall_clock_expiry`

## 13. RT-03-12: reuse a lane after native track removal fails

Attack: inject `remove_track` failure, then reopen or write the same lane.

Required result: the lane becomes non-reusable and retains the exact track and outbound flow owner. A reuse attempt is rejected before another flow owner is allocated, and no duplicate track can attach.

Controls:

- `v4_arc03h_failed_remove_track_retains_exact_lane_owner_and_blocks_reuse` in WSL
- `v4_arc03f_track_attach_failure_rolls_back_outbound_flow_owner` in WSL

## 14. RT-03-13: turn time into media lifecycle truth

Attack: stop sending on a lane and wait for an elapsed grace period to remove it.

Required result: elapsed time changes nothing. Suspend, resume, and finalize are explicit events. A suspended lane retains only its finite profile-bound allocation.

Controls:

- `pinned_lane_suspends_until_explicit_finalization`
- transient lane suspend, resume, and explicit finalization controls
- source rejection of the removed legacy media grace timer

## 15. RT-03-14: crash or exhaust the cleanup executor

Attack: panic a cleanup future, terminate the executor, fill its queue, poison its state, or shut down the caller runtime.

Required result: policy construction validates queue capacity. A failed job calls the exact owner's failure path. Health reports the bounded queue and terminal failure. No timeout reclaims an unproven result.

Controls:

- `v4_arc03h_cleanup_queue_capacity_is_validated_at_policy_construction`
- `v4_arc03h_cleanup_future_panic_marks_exact_owner_failed`
- `v4_arc03h_cleanup_executor_failure_refuses_job_and_fails_exact_owner`
- `v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown`
- `v4_arc03_terminal_cleanup_failure_cannot_be_overwritten_by_start`

## 16. RT-03-15: release real-time bytes while payloads survive

Attack: dequeue a complete event, copy it to downstream receivers, and drop the first copy.

Required result: one lease follows the payload. Capacity releases only when the final owned copy drops.

Controls:

- `v4_arc03f_realtime_bytes_follow_payload_clones_through_downstream_queues`
- `v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim`
- `v4_arc03_cancelled_realtime_output_work_releases_its_claim`
- `v4_arc03_realtime_flow_retirement_drains_its_owned_queue`

## 17. RT-03-16: bypass Endpoint Auth provenance

Attack: replay `DataChannelOpen`, use a task or compatibility capability from another connector, or treat worker possession as application admission.

Required result: the exact live candidate produces one `ConnectedChannelCapability`. It moves into the exact `EndpointAuthTask`. Cross-connector use fails. Arc 03 does not claim transcript verification or authenticated session authority.

Controls:

- `v4_arc03_data_channel_open_requires_live_exact_candidate`
- `v4_arc03_cross_connector_endpoint_auth_and_realtime_capabilities_are_rejected`
- `v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability`
- compiler checks for exact capability-consuming operations

## 18. RT-03-17: turn relay selection into authority

Attack: use a TURN-selected pair as endpoint identity, Endpoint Auth, application admission, or real-time admission.

Required result: TURN remains an ICE carrier for the same endpoint session. Positive and negative controls cross the same Endpoint Auth boundary as a direct path.

Controls:

- `loopback_handshake_opens_data_channel`
- `v4_arc03_relay_selection_is_not_authentication_or_session_admission`
- `turn_selected_session_authenticates_endpoints_before_bidirectional_data` in WSL

## 19. RT-03-18: reach LegacyV1 from normal V4 source

Attack: call application routing or ordinary-member relay from the normal V4 connector, Endpoint Auth task, or daemon path.

Required result: compatibility source stays under `legacy_v1/`, behind the `legacy-v1` feature and deprecated explicit construction. The crate root does not re-export the compatibility facades. Normal V4 source compiles with deprecated use denied. The source name `LegacyV1MemberRelay` cannot be confused with TURN or signaling.

Controls:

- `v4_arc03h_legacy_v1_daemon_option_is_explicit`
- `legacy_v1_runtime_explicitly_enables_one_daemon_channel_relay`
- `v4_arc03h_legacy_v1_delivers_one_payload_across_two_native_hops` in WSL
- default-feature `-D deprecated` checks for `myownmesh-core` and `myownmesh`

Residual: this is a maintained compatibility boundary, not a hard theorem that future source edits cannot cross it. RTM-001 and RTM-002 remain open until deletion.

## 20. RT-03-19: lose the temporary media deployment path

Attack: enable generic real-time policy and assume the old H.264 and Opus adapter appears, or allow ordinary startup to infer a media profile.

Required result: normal startup remains codec-neutral. The temporary feature-gated embedder form requires an explicit reviewed profile and attaches it to the connector policy.

Controls:

- `v4_arc03h_legacy_media_profile_uses_the_supported_deployment_form`
- feature-specific build and test job in `.github/workflows/ci.yml`

## 21. RT-03-20: start without connector policy

Attack: start a participating daemon without a connector policy, turn infrastructure-only startup into participation, or infer missing operational values.

Required result: connector-capable and infrastructure-only constructors are distinct. Infrastructure-only startup requires participation disabled. Missing, zero, invalid, or inconsistent connector policy fails before network-capable startup.

Controls:

- `infrastructure_start_requires_node_participation_disabled`
- `ownerless_mesh_rejects_network_join_with_typed_policy_error`
- `infrastructure_runtime_rejects_later_node_enable_without_mutation`
- `data_only_connector_policy_requires_no_realtime_values`
- compiler rejection for ambiguous Mesh open

## 22. Measurement and approval boundary

[`scripts/measure-v4-arc03g.ps1`](../scripts/measure-v4-arc03g.ps1) records raw queue occupancy, service delay, candidate content size, in-progress bytes, connector concurrency, close duration, process CPU, and retained-memory observations for direct, TURN, data-only, H.264, Opus, flow contention, reconnect, multi-peer, multi-Mesh, close-success, close-error, and candidate-burst scenarios. Each workload shape and repeat count is an explicit owner input. The harness proposes no default or production policy value.

Before review, the exact pushed head must pass formatting, workspace checks, Clippy, tests, doctests, compiler-boundary checks, native direct and TURN controls, retained-feature controls, and the unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl matrix.

Reject claims of complete hostile-ingress admission, exact native dependency memory accounting, Endpoint Auth verification, authenticated session authority, final application flow authority, final codec policy, repository-wide close fencing, hard type-level LegacyV1 exclusion, LegacyV1 removal, or supported-platform preservation before exact-head evidence exists.
