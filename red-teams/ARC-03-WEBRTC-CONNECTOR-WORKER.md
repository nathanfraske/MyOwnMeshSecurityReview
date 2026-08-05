# Arc 03 WebRTC connector ownership red team

Status: Arc 03 executable review record for draft fork PR #5 on
`arc/03i-final-connector-boundary`. The accepted Arc 03 connector controls and
the elastic resource controls below remain required. Source presence is not
exact-head execution evidence. Passing this record does not authorize merge or
select an optional local policy value.

Under review `4865297956` at `378dd82`, this record separates basal properties
required of any installed provider port from the concrete arbitration policy of
the shipped `FiniteResourceProvider`. Every previously listed control remains
required. The separation changes only what a passing control is allowed to
claim.

## 1. Isolation and exact-head commands

Run socket-bearing checks only inside Ubuntu 24.04 WSL. Do not run Windows test binaries. This keeps the controls away from live Windows MyOwnMesh processes and avoids per-binary Windows Firewall prompts.

```powershell
$repo = (Resolve-Path "C:\Users\Admin\MyOwnMesh Security Audit\MyOwnMeshV4Transition").Path
$target = "/root/.cache/codex/mom-arc03-red-team"

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
wsl.exe -d Ubuntu-24.04 -- rm -rf /root/.cache/codex/mom-arc03-red-team
```

## 2. RT-03-01: manufacture connector resource authority

Attack: construct a worker, provider, Mesh child, lease, or candidate capability without the process provider and exact claim.

Required result: external code cannot construct those authorities. Every admitted candidate holds a finite process-backed lease attributed to its exact Mesh scope. Creating more Mesh scopes cannot multiply the process grant. Admission continues for another object whenever its claim is granted and fails with a named resource class when it is not. These are basal properties of any provider installed behind `ResourceProviderPort`. Where a control below exercises the exact borrowing or turn behavior of the shipped `FiniteResourceProvider`, it is concrete-policy evidence under section 22 rather than a universal provider requirement.

Controls:

- no basal `MAX_MESHES`, `MAX_PEERS`, `MAX_ATTEMPTS`, or `MAX_FLOWS` control
- provider-granted additional admission and named-dimension refusal controls
- unequal-claim and many-small-claim controls
- non-multiplying Mesh scope and exact-release restoration controls
- work-conserving borrowing controls, which are concrete policy of the shipped provider under section 22, and optional local ceiling controls
- cause-matched compiler rejections for private resource and worker constructors
- `foreign_port_authority_cannot_release_or_reuse_a_live_reservation`
- `one_finite_provider_cannot_back_two_distinct_authority_roots`
- `provider_rejects_an_unknown_scope_even_with_port_authority`
- `releasing_a_scope_with_a_live_reservation_poisons_later_admission`
- `accounting_mutex_poison_becomes_an_explicit_provider_invariant`

## 3. RT-03-02: cancel native construction

Attack: cancel after native allocation, race close before the native port attaches, cancel after delivery, shut down the caller runtime, or fail construction.

Required result: one close owner owns every partial or delivered result. Successful close releases the claim. A returned close error retains the exact claim. Caller cancellation cannot cancel cleanup ownership.

Controls:

- `v4_arc03_native_constructor_without_close_port_retains_exact_claim`
- `v4_arc03_close_before_native_attach_closes_late_port_and_releases_claim`
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

## 4A. RT-03-03A: lose open or close behind callback saturation

Attack: fill the control and endpoint mailboxes, queue open and close together, place endpoint data ahead of open in the scheduler, and emit callback observations after close.

Required result: open and close use their fixed lifecycle owner instead of an ordinary mailbox. Close may supersede an uncommitted open. A close recorded while the connector is authoritative survives the retirement it causes and is exposed once. A close inserted only after retirement is discarded. No event after close reaches Endpoint Auth or application dispatch. Renegotiation remains a sticky coalesced obligation, while ICE and peer-connection state retain only the latest observation.

Controls:

- `v4_arc03i_close_supersedes_prequeued_endpoint_data_without_hidden_producers`
- `v4_arc03i_open_and_close_do_not_depend_on_control_mailbox_capacity`
- `v4_arc03i_close_supersedes_an_uncommitted_open_exactly_once`
- `v4_arc03_recorded_close_survives_connector_retirement_to_engine_delivery`
- `v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing`
- `v4_arc03i_candidate_and_gathering_overload_retires_the_connector`
- `v4_arc03i_renegotiation_and_state_observations_are_coalesced`

## 5. RT-03-04: hide producers behind a full callback mailbox

Attack: fill a callback mailbox, then submit one or many later callbacks while the receiver is stalled.

Required result: every retained callback carries queued-byte and scheduled-work leases. Insertion returns typed pressure without an unbounded producer wait. No producer future accumulates behind `reserve().await`, and no second callback queue exists.

Controls:

- `v4_arc03i_close_supersedes_prequeued_endpoint_data_without_hidden_producers`
- `v4_arc03h_callback_producer_flood_cannot_queue_behind_full_mailbox`
- `producer_overload_is_typed_and_creates_no_hidden_work`
- source rejection of callback `reserve().await`

The native callback surface has a separate structural bound. Native ICE conversion first acquires structural work and a named opaque dependency residual. The pinned dependency allocates the callback wrapper before MyOwnMesh runs and exposes no allocation plan for `to_json`, so wrapper and formatting allocations are not exact byte claims. MyOwnMesh measures returned String content and capacities and transitions the lease before any asynchronous retention. A refusal drops the result and retires the connector. Data-only mode admits one application data channel and no media tracks. The temporary legacy profile admits one application data channel and only its finite, exact H.264 and Opus track set. The first shape violation retires the connector, and later violations coalesce into that one action.

Additional controls:

- `v4_arc03i_native_data_channel_shape_is_fixed_and_violation_work_is_coalesced`
- `v4_arc03i_legacy_track_shape_bounds_duplicates_codecs_and_track_count`
- `v4_arc03i_first_structural_violation_retires_once`
- `executing_callback_accounts_converted_payload_before_async_retention`

## 6. RT-03-05: reorder channel-open and endpoint protocol data

Attack: place the scheduler cursor on endpoint data while `DataChannelOpen` and the first handshake message are both queued. Replace or retire the connector before open commits.

Required result: endpoint protocol data remains in its lease-backed retention path until exact open promotion. Retirement drops it and releases its claim.

Controls:

- `v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor`
- `v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol`
- `v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation`

## 7. RT-03-06: flood remote candidates before and after SDP

Attack: submit unique and duplicate candidates on both sides of remote SDP, delay application, cancel application, and continue until the provider refuses candidate storage or application work.

Required result: one ICE-attempt owner holds every candidate storage, byte, parsing, hashing, and native-work lease. The first provider or optional local-policy refusal retires the exact attempt. Later submissions return the terminal result before hashing or logging unique candidate content. Application does not reset the owner.

A local restart creates a provisional attempt, retires the old attempt, waits for admitted old work, and commits only after native restart succeeds. Native failure does not publish the replacement and retires the connector when rollback is not proven. A remote restart is detected from changed effective ICE credentials on an existing MID, or media-line index when MID is absent. Media reordering or addition cannot manufacture a fresh candidate envelope. The replacement stays provisional until the exact remote description commits. The DTLS fingerprint does not stand in for ICE credentials. Both mutation paths arm a process-local drop guard before their first suspension. Dropping either future retires the exact affected attempt and starts the existing close owner, so cancellation cannot strand provisional or in-flight state.

A replacement candidate may arrive before the replacement SDP. It must consume finite ingress capacity without reaching the old native ICE agent, then move only when it explicitly declares the replacement username fragment and any declared media location matches the replacement binding. A location-only candidate owned by the old attempt is dropped. A location-only candidate admitted after the provisional replacement exists remains owned by that replacement. Delayed old-attempt work cannot mutate the replacement. Concurrent local restart and remote-description transactions fail closed instead of creating two candidate owners.

V4 remote SDP must enter the connector as raw input. An allocation-free pass computes its media-section, credential-record, and String shape. The input, parsing work, conservative input-bounded parser storage, and named hash-table, allocator, and native-description residuals must be leased before either the credential parser or the native SDP constructor allocates output. The measured credential owner is shared across preparation and commit and transfers to the close owner before native application. Every retained owner charges its close-registry Arc pointer, owner struct, reference counters, storage object, and allocator residuals. Native success releases only its scheduled-work unit. Dependency-queued description work keeps successful renegotiation owners charged until connector close. Cancellation, native error, commit mismatch, or failed native close cannot release that residual or leave reusable candidate state.

Attack: omit MID, media-line index, and username fragment, provide conflicting MID and index values, reuse one username fragment for different effective credential pairs, conflict the structured username fragment with the candidate-line `ufrag`, repeat the line extension, omit its value, or continue sending malformed bindings after the first refusal.

Required result: every accepted candidate has a binding to the active SDP. MID and index select one exact binding. A username-fragment-only candidate identifies one unambiguous credential pair. Structured and line declarations agree exactly. Empty structured values cannot hide the line declaration, and duplicate or incomplete line declarations are invalid. The first invalid binding returns one typed reason and retires the exact attempt. Later submissions reach the inactive-attempt check before binding parsing, candidate classification, hashing, retention, duplicate accounting, diagnostic publication, or native work. Queue length, digest cardinality, resource counters, and diagnostic cardinality remain unchanged after the one terminal result. No generation, route identity, timestamp, timer, or new rate counter is added.

Controls:

- `v4_arc03g_candidate_queue_deduplicates_before_retention_and_enforces_both_bounds`
- `v4_arc03h_candidate_digest_is_structurally_unambiguous`
- `v4_arc03h_candidate_content_bytes_cover_every_candidate_content_field`
- `v4_arc03_candidate_queue_reserves_actual_string_capacity_before_node_insertion`
- `v4_arc03h_candidate_attempt_envelope_survives_delayed_apply_and_cancellation`
- `v4_arc03h_post_sdp_candidates_share_one_cumulative_attempt_envelope`
- `v4_arc03h_new_attempt_gets_a_fresh_candidate_envelope`
- `v4_arc03i_candidate_digest_distinguishes_absent_and_maximum_mline_index`
- `v4_arc03j_local_ice_restart_is_provisional_until_explicit_commit`
- `v4_arc03_local_restart_overlap_charge_releases_on_commit_and_failure`
- `v4_arc03_dropped_ice_transaction_fences_attempt_and_starts_exact_close_owner`
- `v4_arc03_dropped_remote_description_cannot_leave_reusable_inflight_state`
- `v4_arc03j_local_restart_failure_discards_replacement_without_rollback`
- `v4_arc03j_native_local_ice_restart_commits_exact_replacement` in WSL
- `v4_arc03j_native_local_ice_restart_failure_retires_connector` in WSL
- `v4_arc03j_remote_same_fingerprint_credential_change_is_transactional`
- `v4_arc03j_media_renegotiation_cannot_mint_a_candidate_attempt`
- `v4_arc03j_terminal_candidate_exhaustion_stops_later_hash_and_work_admission`
- `v4_arc03j_sdp_ice_credentials_apply_session_inheritance_and_media_overrides`
- `v4_arc03_remote_sdp_credentials_share_one_exact_retention_lease`
- `v4_arc03_remote_sdp_residual_survives_failed_native_close`
- `v4_arc03j_remote_candidates_require_an_exact_or_unambiguous_binding`
- `v4_arc03j_candidate_username_fragment_declarations_must_agree`
- `v4_arc03j_invalid_candidate_bindings_terminally_retire_the_attempt`
- `v4_arc03j_remote_restart_migrates_only_explicit_replacement_candidates`
- `v4_arc03j_restart_transactions_reject_ambiguous_interleavings`
- `v4_arc03j_corrupt_restart_migration_leaves_no_viable_attempt`
- vendored `test_add_remote_candidate_return_proves_internal_insertion`
- vendored `test_disabled_mdns_candidate_is_not_reported_as_applied`

The content-byte limit is not an exact retained-memory limit. The production
queue separately reserves the Rust wrapper and actual retained String slack
before node insertion. Allocator metadata and dependency-native retention remain
explicit residuals.

## 8. RT-03-07: start codec work from generic real-time enablement

Attack: enable codec-neutral real-time ownership with no provider, or present a track callback anyway.

Required result: no compatibility codecs or tracks are provisioned. An inbound transceiver without a provider is stopped. Codec registration and H.264 or Opus processing start only from the explicit temporary provider.

Controls:

- `v4_arc03_generic_realtime_policy_does_not_request_media_tracks`
- `v4_arc03h_data_only_and_generic_realtime_without_provider_allocate_no_codec_tracks` in WSL

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

Required result: every retained packet byte and scheduled work unit owns a finite lease. Provider pressure or an explicit compatibility or local ceiling stops the speculative transceiver. There is no timer, token window, or rate reset.

Controls:

- `v4_arc03h_sustained_pre_auth_rtp_exhausts_a_finite_cumulative_envelope`
- source rejection of real-time useful-lifetime and expiry inputs

## 11. RT-03-10: corrupt cross-domain real-time accounting

Attack: underflow or overflow the inbound or outbound connector-owned byte and unit counters.

Required result: a damaged connector-local counter becomes explicitly inexact and cannot create capacity. With an optional local ceiling, that domain is conservatively charged to its full ceiling and refuses later local admission. Without a local ceiling, the finite provider remains authoritative and live leases remain charged. Independent ownership prevents one damaged domain from fabricating capacity in another.

Controls:

- `v4_arc03_realtime_accounting_corruption_fails_closed`
- `v4_arc03f_inbound_and_outbound_flow_slots_cannot_starve_each_other`

Residual: native WebRTC allocations outside connector-owned leases are not included in this proof.

## 12. RT-03-11: retain unbounded real-time units

Attack: send oversized fragments, too many fragments, many incomplete units, a silent incomplete unit, reordered units, and full complete-unit queues.

Required result: every connector-retained unit has a finite storage and work lease. Proven provider or compatibility shape limits remain distinct. The temporary compatibility queue uses deterministic `DropNewest`. A silent partial unit keeps only its finite admitted claim until a concrete owner event releases it.

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

Required result: connector admission reserves cleanup execution ownership. New speculative pressure cannot prevent cleanup from being scheduled. A failed job calls the exact owner's failure path. Health reports leased queued and active work plus terminal failure. No timeout reclaims an unproven result.

Controls:

- `v4_arc03_cleanup_queue_cannot_outgrow_pre_reserved_connector_claims`
- `v4_arc03_cleanup_submission_consumes_one_exact_reservation_capability`
- `v4_arc03h_cleanup_future_panic_marks_exact_owner_failed`
- `v4_arc03h_cleanup_executor_failure_refuses_job_and_fails_exact_owner`
- `v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown`
- `v4_arc03_terminal_cleanup_failure_cannot_be_overwritten_by_start`
- `v4_arc03i_cleanup_panic_retains_claim_after_last_external_owner_drops`
- `v4_arc03i_executor_termination_retains_active_job_without_external_owner`

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

Required result: TURN remains an ICE carrier for the same endpoint session. Positive and negative controls preserve the retained endpoint-authentication and application-admission boundary used by a direct path. Arc 04 transcript verification is not claimed.

Controls:

- `loopback_handshake_opens_data_channel`
- `v4_arc03_relay_selection_is_not_authentication_or_session_admission`
- `turn_selected_session_authenticates_endpoints_before_bidirectional_data` in WSL

The TURN control uses one process provider shared by both concurrent Mesh scopes in each scenario. Its `transport-lab`-only helpers fund four connector profiles and four Mesh scope records across two sequential scenarios, with at most two active concurrently. The same helpers derive conservative candidate and remote-SDP claims, including concurrent digest work, from explicit signaling-frame fixture bounds. The control requires a relay-to-relay selected-pair report, bidirectional endpoint data after mutual authentication and admission, and endpoint-data refusal after authentication without mutual admission. Its legacy-media failures prove only that relay selection cannot add the frozen media surface to a data-only profile. They are not a separate real-time admission control. One selected-pair callback is sufficient because it identifies the negotiated pair shared by both endpoints; the dependency does not promise to emit that diagnostic callback on both sides. Arc 03 does not claim a live failed-transcript Endpoint Auth control.

The fixture helper is not a production constructor and is absent from the default V4 API. Its explicit callback, candidate, and remote-SDP values prove only this test workload. They do not select a deployment policy.

## 19. RT-03-18: reach LegacyV1 from normal V4 source

Attack: call application routing or ordinary-member relay from the normal V4 connector, Endpoint Auth task, or daemon path.

Required result: compatibility source stays under `legacy_v1/`, behind the `legacy-v1` feature and deprecated explicit construction. The crate root does not re-export the compatibility facades. Normal V4 source compiles with deprecated use denied. The source name `LegacyV1MemberRelay` cannot be confused with TURN or signaling. Each joined Mesh has one routing owner and, when requested, one separate member-relay owner. Corrected routed envelopes use `__mesh_route__/v1`. Plain relay envelopes use `__mesh_relay__/v1`. Their payload remains opaque except for recognition and rejection of the exact historical routed-wrapper shape. No arbitrary application payload field selects corrected routing behavior. Malformed input does not stop later valid delivery.

Controls:

- `v4_arc03h_legacy_v1_daemon_option_is_explicit`
- `legacy_v1_runtime_explicitly_enables_one_daemon_channel_relay`
- `routed_and_plain_relay_wires_are_disjoint`
- `mixed_version_historical_routed_wrapper_is_classified_for_rejection`
- `corrected_plain_relay_rejects_the_historical_routed_wrapper_shape`
- `v4_arc03h_legacy_v1_delivers_one_payload_across_two_native_hops` in WSL
- default-feature `-D deprecated` checks for `myownmesh-core` and `myownmesh`

Evidence boundary: the two-hop test is a native routing implementation control. `legacy_v1_runtime_explicitly_enables_one_daemon_channel_relay` is the supported deployment startup and owner-installation control. Together they do not claim a full supported-construction two-hop test.

Residual: this is a maintained compatibility boundary, not a hard theorem that future source edits cannot cross it. RTM-001 and RTM-002 remain open until deletion.

## 20. RT-03-19: lose the temporary media deployment path

Attack: enable generic real-time policy and assume the old H.264 and Opus adapter appears, or allow ordinary startup to infer a media profile.

Required result: normal startup remains codec-neutral. The temporary feature-gated embedder and CLI forms require an explicit reviewed profile and attach it to the connector policy. Legacy-media-only startup has no LegacyV1 runtime, network, or member-relay authority. The combined form requires both authorities to be selected explicitly. Every media profile field comes from the owner. The media engine registers only H.264 and Opus.

Controls:

- `v4_arc03h_legacy_media_profile_uses_the_supported_deployment_form`
- `v4_arc03j_legacy_media_sidecar_composes_only_with_explicit_legacy_v1_runtime`
- `v4_arc03j_v4_only_daemon_option_set_is_empty`
- `v4_arc03h_legacy_v1_daemon_option_is_explicit`
- `v4_arc03j_legacy_media_daemon_option_is_independent`
- `v4_arc03j_combined_compatibility_authorities_require_both_flags`
- `v4_arc03j_legacy_media_sidecar_rejects_an_incomplete_owner_vector`
- `v4_arc03j_legacy_media_sidecar_uses_only_the_complete_owner_vector`
- `v4_arc03j_legacy_codec_registration_is_only_h264_and_opus`
- feature-specific build and test job in `.github/workflows/ci.yml`

## 21. RT-03-20: start without connector policy

Attack: start a participating daemon without a resource provider, turn infrastructure-only startup into participation, or install hidden product-cardinality defaults.

Required result: connector-capable and infrastructure-only constructors are distinct. Infrastructure-only startup requires participation disabled. Connector-capable startup requires a resource provider but no static Mesh, peer, attempt, queue, or flow count. Hidden default cardinality is rejected.

Controls:

- `infrastructure_start_requires_node_participation_disabled`
- `ownerless_mesh_rejects_network_join_with_typed_policy_error`
- `infrastructure_runtime_rejects_later_node_enable_without_mutation`
- `elastic_data_only_connector_requires_no_cardinality_values`
- compiler rejection for ambiguous Mesh open

## 22. Elastic resource controls

Attack: impose a hidden object count, multiply capacity with child scopes, let one Mesh repeatedly reacquire shared capacity ahead of another, starve cleanup with speculative work, forge release from a reclaim notification, retain an object after releasing its lease, expire a slow operation by time, or treat storage-backed delivery like a live packet queue.

This section separates two kinds of claim. A basal-property result must hold for
any provider installed behind `ResourceProviderPort`. A concrete-policy result
describes the shipped `FiniteResourceProvider` arbitration that Arc 03 actually
executes against. Both sets remain required evidence on the exact head. A
concrete-policy control passing is evidence about this provider only; it is not
a universal conformance statement, and a replacement provider must supply its
own concrete-policy evidence for the same basal properties.

Required result — basal properties, provider independent:

- no basal Mesh, peer, attempt, session, or flow maximum exists;
- another object is admitted whenever the mock provider grants its exact claim;
- refusal names an unavailable resource dimension, and pressure is a resource result rather than an authorization result;
- one large claim may consume more than many small claims;
- many small objects coexist while resources remain;
- Mesh scopes cannot multiply the process grant;
- exact release restores capacity;
- arbitration distributes existing capacity only; it never mints capacity and never releases, revokes, replaces, or reuses another owner's live claim;
- the exact owner of a lease its contract declares reclaimable receives one exact retirement request, while the provider retains no release or cleanup authority;
- a demand cancelled before acquisition releases no victim;
- nonwaiting acquisition returns typed pressure without creating a hidden demand or requesting cleanup;
- release or failed-cleanup retention remains attributable to the exact selected claim;
- an optional local ceiling can restrict a deployment without minting capacity, and remains absent from the elastic constructors;
- `Cleanup` and `Admitted` leases are never reclamation victims; victim cleanup and eventual admission remain conditional on the exact owner completing cleanup;
- connector-local scheduling metadata is not capacity: connector-local service weights and quanta reserve no provider capacity and cannot multiply the process grant. This is a capacity-authority claim and does not discharge the claimant-share obligation below;
- creating or rotating any number of attribution child scopes for one claimant or fairness root cannot improve that claimant's service share against another root. **No control below implements this, and the shipped provider does not satisfy it. See the missing-control note in this section;**
- slow work retains its finite lease without timer-derived expiry;
- storage-backed work consumes storage leases;
- no hidden default cardinality exists.

Required result — concrete policy of the shipped `FiniteResourceProvider`:

- a selected pending turn reserves its exact charge while leaving surplus capacity borrowable, including surplus in an overlapping dimension;
- cooperative pressure orders `Cleanup`, `Admitted`, then `Speculative` and rotates equal-authority scope identities without configured weights or shares;
- that ordering and rotation prevent starvation by construction in this provider: a cleanup-class demand is not deferred indefinitely behind speculative demand, and no scope reacquires indefinitely ahead of an equal-authority scope's outstanding demand;
- each provider scope owns at most one move-only pending demand, and a cancelled demand loses that turn;
- a pending turn blocks only the resource dimensions the selected demand requires;
- scope and reservation bookkeeping passes the same admission gate as ordinary claims;
- a reclaim request is published only after the selected victim set can satisfy the deficit.

Exact source controls — basal properties:

- `increasing_one_granted_dimension_admits_exactly_one_more_claim`
- `unequal_claim_cost_not_object_count_controls_admission`
- `one_process_grant_is_conserved_across_unequal_scopes_and_authorities`
- `scope_creation_grants_no_capacity_and_unknown_scopes_are_rejected`
- `v4_arc03_mesh_scopes_share_one_grant_and_creation_does_not_multiply_it`
- `v4_arc03_concurrent_mesh_children_cannot_oversubscribe_shared_provider`
- `v4_arc03_successful_drop_releases_the_exact_provider_claim`
- `unused_capacity_is_borrowable_across_mesh_attribution_scopes`
- `cooperative_pressure_requests_exact_speculation_and_prevents_reacquisition`
- `dropping_pending_demand_cancels_its_turn_without_releasing_a_victim`
- `nonwaiting_reclaimable_admission_returns_pressure_without_requesting_cleanup`
- `slow_speculation_has_no_elapsed_time_reclaim_semantics`
- `failed_reclaim_cleanup_retains_charge_and_reports_exact_pressure`
- `arc03_remote_candidate_local_ceiling_is_explicit_and_attempt_scoped`
- `slow_storage_work_retains_only_its_finite_lease_until_explicit_drop`
- `arc03_remote_candidate_apply_releases_exact_retention`
- `arc03_remote_candidate_drop_releases_exact_retention`
- `v4_arc03_provider_pressure_names_the_exhausted_dimension`
- `v4_arc03_cleanup_submission_consumes_one_exact_reservation_capability`
- `v4_arc03_connector_operations_require_and_release_exact_work_claims`
- `v4_arc03_legacy_realtime_capability_holds_its_exact_resource_lease`
- `v4_arc03_candidate_queue_reserves_actual_string_capacity_before_node_insertion`
- `v4_arc03_native_constructor_without_close_port_retains_exact_claim`
- `v4_arc03_cancelled_pending_native_constructor_retains_exact_claim`
- `composite_request_overflow_is_not_reported_as_exact_pressure`
- vendored `test_add_remote_candidate_return_proves_internal_insertion`

Exact source controls — concrete policy of the shipped `FiniteResourceProvider`:

- `active_turn_fences_plain_scope_bookkeeping`
- `active_demander_cannot_reacquire_ahead_of_its_exact_turn`
- `insufficient_reclaim_set_is_not_published`
- `pending_turn_blocks_only_overlapping_resource_dimensions`
- `cleanup_demand_supersedes_a_speculative_turn_without_reclaiming_cleanup`
- `reclaim_and_promotion_are_linearized_in_both_orders`
- `cooperative_child_scope_and_first_lease_remain_one_transaction`
- `equal_authority_demands_rotate_without_cross_scope_reacquisition`
- `v4_arc03_elastic_connector_root_yields_to_another_mesh_fairness_turn`

These controls fix the exact ordering, rotation, per-scope pending-demand shape,
dimension-scoped blocking, and bookkeeping charge of the current provider. Each
one remains required for this head. None of them may be read as proof that a
conforming provider must arbitrate this way. The basal obligations they also
touch — no capacity minting, `Cleanup` and `Admitted` leases never reclaimed,
and no provider-side release — are stated as properties above and must hold for
any provider. The non-starvation behavior these controls also demonstrate is an
obligation of this provider's concrete policy; it is not a basal property, and
fairness-domain liveness is not settled here.

Missing control — blocking, no source control exists:

- claimant-share fairness: creating or rotating any number of attribution child
  scopes for one claimant or fairness root must not improve that claimant's
  service share against another root.

No control in this record implements that obligation, and none of the controls
listed above may be cited as evidence for it. `equal_authority_demands_rotate_without_cross_scope_reacquisition`
and `v4_arc03_elastic_connector_root_yields_to_another_mesh_fairness_turn`
exercise rotation between scope identities, which is the mechanism at issue
rather than a proof of fairness between claimants. The shipped
`FiniteResourceProvider` does not satisfy the obligation: its rotation is keyed
to process-local scope identities, and a claimant can mint child scopes to
manufacture turns. This is a disclosed nonconformance, not a pending pass, and
it must never be reported as passing. Review 4865297956 §8 defers the fix to
Slice D, which must bind pending demands to a non-multipliable fairness root.

The compiler-boundary checker separately rejects the listed basal cardinality
names and requires the elastic constructors and optional local wrappers. These
controls are claims to execute on the exact pushed head, not a statement that
the current working tree has passed them.

The progress claim is intentionally conditional. It covers registered
reclaimable speculative conflicts when the selected owner completes cleanup.
It does not promise admission while nonreclaimable admitted work owns the
resource, while an owner ignores retirement, or after cleanup failure retains
the exact charge.

## 23. Measurement and approval boundary

[`scripts/measure-v4-arc03g.ps1`](../scripts/measure-v4-arc03g.ps1) records raw queue occupancy, service delay, candidate content size, in-progress bytes, connector concurrency, close duration, process CPU, and retained-memory observations for direct, TURN, data-only, H.264, Opus, flow contention, reconnect, multi-peer, multi-Mesh, close-success, close-error, and candidate-burst scenarios. These observations characterize performance, provider cost, fairness, regression, and opaque residuals. They do not define universal product cardinality, and observing the shipped provider's arbitration does not promote that arbitration policy into a basal requirement.

Before review, the exact pushed head must pass formatting, workspace checks, Clippy, tests, doctests, compiler-boundary checks, native direct and TURN controls, retained-feature controls, and the unchanged Linux x86-64, macOS ARM64, Windows x86-64, Linux RISC-V musl, and Linux ARM64 musl matrix.

Reject claims of complete hostile-ingress admission, exact native dependency memory accounting, Endpoint Auth verification, authenticated session authority, final application flow authority, final codec policy, repository-wide close fencing, hard type-level LegacyV1 exclusion, LegacyV1 removal, or supported-platform preservation before exact-head evidence exists. Also reject any claim that the shipped `FiniteResourceProvider` arbitration policy is itself a basal invariant or universal provider conformance.
