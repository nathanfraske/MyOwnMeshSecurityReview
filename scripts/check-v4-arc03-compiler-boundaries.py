#!/usr/bin/env python3
"""Compile external Arc 03 probes and verify the exact rejection causes."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "crates" / "myownmesh-core"
DAEMON = REPO / "crates" / "myownmesh"
COMPILER_TARGET = tempfile.TemporaryDirectory(
    prefix="myownmesh-v4-arc03-compiler-target-"
)


@dataclass(frozen=True)
class RejectedProbe:
    name: str
    source: str
    code: str
    fragments: tuple[str, ...]


REJECTED = (
    RejectedProbe(
        "raw_candidate_application_is_private",
        """use myownmesh_core::transport::{LocalIceCandidate, PeerSession};
async fn bypass(session: &PeerSession, candidate: LocalIceCandidate) {
    session.add_ice_candidate(candidate).await.unwrap(); // expected-error
}
fn main() {}
""",
        "E0624",
        ("add_ice_candidate", "private"),
    ),
    RejectedProbe(
        "connector_worker_is_not_public",
        """use myownmesh_core::transport::WebRtcConnectorWorker; // expected-error
fn main() { let _ = std::mem::size_of::<WebRtcConnectorWorker>(); }
""",
        "E0603",
        ("WebRtcConnectorWorker", "private"),
    ),
    RejectedProbe(
        "legacy_media_sample_is_not_in_default_v4_api",
        """use myownmesh_core::transport::VideoSample; // expected-error
fn main() { let _ = std::mem::size_of::<VideoSample>(); }
""",
        "E0432",
        ("VideoSample", "no `VideoSample`"),
    ),
    RejectedProbe(
        "legacy_media_lane_is_not_in_default_v4_api",
        """use myownmesh_core::transport::LaneKind; // expected-error
fn main() { let _ = std::mem::size_of::<LaneKind>(); }
""",
        "E0432",
        ("LaneKind", "no `LaneKind`"),
    ),
    RejectedProbe(
        "legacy_media_profile_is_not_in_default_v4_api",
        """use myownmesh_core::LegacyWebRtcMediaProfile; // expected-error
fn main() { let _ = std::mem::size_of::<LegacyWebRtcMediaProfile>(); }
""",
        "E0432",
        ("LegacyWebRtcMediaProfile", "no `LegacyWebRtcMediaProfile`"),
    ),
    RejectedProbe(
        "legacy_v1_runtime_is_not_in_default_v4_api",
        """use myownmesh_core::legacy_v1::LegacyV1Runtime; // expected-error
fn main() { let _ = std::mem::size_of::<LegacyV1Runtime>(); }
""",
        "E0432",
        ("legacy_v1", "could not find"),
    ),
    RejectedProbe(
        "raw_peer_constructor_is_not_production_api",
        """use myownmesh_core::transport::{Role, Transport};
async fn bypass(transport: &Transport) {
    let _ = transport.open_peer(Role::Offerer, &[], &[]).await; // expected-error
}
fn main() {}
""",
        "E0599",
        ("open_peer", "not found"),
    ),
    RejectedProbe(
        "realtime_flow_capability_is_not_public",
        """use myownmesh_core::connector::ConnectorRealtimeFlowCapability; // expected-error
fn main() { let _ = std::mem::size_of::<ConnectorRealtimeFlowCapability>(); }
""",
        "E0603",
        ("ConnectorRealtimeFlowCapability", "private"),
    ),
    RejectedProbe(
        "resource_owner_cannot_be_minted_externally",
        """use myownmesh_core::{ConnectorResourceOwnerPort, ConnectorResourcePolicy};
fn bypass(policy: ConnectorResourcePolicy) {
    let _ = ConnectorResourceOwnerPort::new(policy); // expected-error
}
fn main() {}
""",
        "E0624",
        ("new", "private"),
    ),
    RejectedProbe(
        "ambiguous_mesh_open_is_removed",
        """use myownmesh_core::{Mesh, MeshConfig};
async fn bypass() {
    let _ = Mesh::open(MeshConfig::default()).await; // expected-error
}
fn main() {}
""",
        "E0599",
        ("open", "not found"),
    ),
)


POSITIVE_SOURCE = """use myownmesh_core::transport::{LocalIceCandidate, PeerSession};
fn public_diagnostic_types(_: &PeerSession, _: LocalIceCandidate) {}
fn main() { let _ = public_diagnostic_types; }
"""


AUTHORITY_POSITIVES = (
    ("v4_only_authority_set", (), POSITIVE_SOURCE),
    (
        "legacy_v1_only_authority_set",
        ("legacy-v1",),
        """#[allow(deprecated)]
fn main() {
    let _ = myownmesh_core::legacy_v1::LegacyV1Runtime::frozen();
}
""",
    ),
    (
        "legacy_media_only_authority_set",
        ("legacy-media",),
        """#[allow(deprecated)]
fn main() {
    let one = std::num::NonZeroUsize::new(1).unwrap();
    let _ = myownmesh_core::LegacyWebRtcMediaProfile::h264_opus(one, 0, 0).unwrap();
}
""",
    ),
    (
        "combined_compatibility_authority_set",
        ("legacy-v1", "legacy-media"),
        """#[allow(deprecated)]
fn main() {
    let _ = myownmesh_core::legacy_v1::LegacyV1Runtime::frozen();
    let one = std::num::NonZeroUsize::new(1).unwrap();
    let _ = myownmesh_core::LegacyWebRtcMediaProfile::h264_opus(one, 0, 0).unwrap();
}
""",
    ),
)


AUTHORITY_REJECTED = (
    (
        ("legacy-v1",),
        RejectedProbe(
            "legacy_v1_only_cannot_construct_media_authority",
            """use myownmesh_core::LegacyWebRtcMediaProfile; // expected-error
fn main() { let _ = std::mem::size_of::<LegacyWebRtcMediaProfile>(); }
""",
            "E0432",
            ("LegacyWebRtcMediaProfile", "no `LegacyWebRtcMediaProfile`"),
        ),
    ),
    (
        ("legacy-media",),
        RejectedProbe(
            "legacy_media_only_cannot_construct_legacy_v1_authority",
            """use myownmesh_core::legacy_v1::LegacyV1Runtime; // expected-error
fn main() { let _ = std::mem::size_of::<LegacyV1Runtime>(); }
""",
            "E0432",
            ("legacy_v1", "could not find"),
        ),
    ),
)


def cargo_toml() -> str:
    core_path = CORE.as_posix().replace('"', '\\"')
    bins = [
        "[[bin]]\n" f'name = "{probe.name}"\n' f'path = "src/{probe.name}.rs"\n'
        for probe in REJECTED
    ]
    bins.append(
        "[[bin]]\n"
        'name = "positive_public_types"\n'
        'path = "src/positive_public_types.rs"\n'
    )
    return (
        "[package]\n"
        'name = "myownmesh-v4-arc03-compiler-boundaries"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f'myownmesh-core = {{ path = "{core_path}" }}\n\n'
        + "\n".join(bins)
    )


def authority_cargo_toml(name: str, features: tuple[str, ...]) -> str:
    core_path = CORE.as_posix().replace('"', '\\"')
    feature_clause = ""
    if features:
        selected = ", ".join(json.dumps(feature) for feature in features)
        feature_clause = f", features = [{selected}]"
    return (
        "[package]\n"
        f'name = "{name}"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f'myownmesh-core = {{ path = "{core_path}"{feature_clause} }}\n\n'
        "[[bin]]\n"
        f'name = "{name}"\n'
        f'path = "src/{name}.rs"\n'
    )


def run_check(project: Path, binary: str) -> tuple[int, list[dict], str]:
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    environment["CARGO_TARGET_DIR"] = COMPILER_TARGET.name
    result = subprocess.run(
        [
            "cargo",
            "check",
            "--offline",
            "--message-format=json",
            "--bin",
            binary,
        ],
        cwd=project,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    diagnostics: list[dict] = []
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-message":
            continue
        if record.get("target", {}).get("name") == binary:
            diagnostics.append(record.get("message", {}))
    return result.returncode, diagnostics, result.stderr


def matches(probe: RejectedProbe, diagnostics: list[dict]) -> bool:
    marker_lines = [
        line_number
        for line_number, line in enumerate(probe.source.splitlines(), start=1)
        if "expected-error" in line
    ]
    if len(marker_lines) != 1:
        return False
    expected_line = marker_lines[0]
    expected_file = f"{probe.name}.rs"
    for diagnostic in diagnostics:
        code = (diagnostic.get("code") or {}).get("code")
        rendered = diagnostic.get("rendered") or diagnostic.get("message") or ""
        primary_span_matches = any(
            span.get("is_primary")
            and Path(span.get("file_name", "")).name == expected_file
            and span.get("line_start", 0) <= expected_line <= span.get("line_end", 0)
            for span in diagnostic.get("spans", [])
        )
        if (
            code == probe.code
            and all(fragment in rendered for fragment in probe.fragments)
            and primary_span_matches
        ):
            return True
    return False


def main() -> int:
    failures: list[str] = []
    def read_sources(*paths: Path) -> str:
        return "\n".join(path.read_text(encoding="utf-8") for path in paths)

    webrtc_source = read_sources(
        CORE / "src" / "transport" / "webrtc.rs",
        CORE / "src" / "transport" / "webrtc" / "callback.rs",
        CORE / "src" / "transport" / "webrtc" / "cleanup.rs",
        CORE / "src" / "transport" / "webrtc" / "h264.rs",
        CORE / "src" / "transport" / "webrtc" / "media.rs",
        CORE / "src" / "transport" / "webrtc" / "policy.rs",
        CORE / "src" / "transport" / "webrtc" / "realtime.rs",
    )
    attempt_source = read_sources(
        CORE / "src" / "runtime" / "attempt" / "mod.rs",
        CORE / "src" / "runtime" / "attempt" / "admission.rs",
        CORE / "src" / "runtime" / "attempt" / "lifetime.rs",
        CORE / "src" / "runtime" / "attempt" / "policy.rs",
        CORE / "src" / "runtime" / "attempt" / "resource_owner.rs",
    )
    attempt_policy_source = (
        CORE / "src" / "runtime" / "attempt" / "policy.rs"
    ).read_text(encoding="utf-8")
    webrtc_policy_source = (
        CORE / "src" / "transport" / "webrtc" / "policy.rs"
    ).read_text(encoding="utf-8")
    engine_source = (CORE / "src" / "engine" / "mod.rs").read_text(
        encoding="utf-8"
    )
    routing_path = CORE / "src" / "legacy_v1" / "routing.rs"
    relay_path = CORE / "src" / "legacy_v1" / "relay.rs"
    routing_source = routing_path.read_text(
        encoding="utf-8"
    )
    relay_source = relay_path.read_text(
        encoding="utf-8"
    )
    legacy_profile_source = (CORE / "src" / "legacy_v1.rs").read_text(
        encoding="utf-8"
    )
    lib_source = (CORE / "src" / "lib.rs").read_text(encoding="utf-8")
    core_manifest = (CORE / "Cargo.toml").read_text(encoding="utf-8")
    endpoint_auth_source = (CORE / "src" / "endpoint_auth" / "mod.rs").read_text(
        encoding="utf-8"
    )
    services_source = (DAEMON / "src" / "services.rs").read_text(encoding="utf-8")
    embedded_source = (DAEMON / "src" / "embedded.rs").read_text(encoding="utf-8")
    serve_source = (DAEMON / "src" / "cli" / "serve.rs").read_text(encoding="utf-8")
    for consumer in (
        "open_media_lane",
        "close_media_lane",
        "send_video",
        "send_audio",
        "finalize_suspended_lanes",
    ):
        signature = re.search(
            rf"pub\(crate\)\s+(?:async\s+)?fn\s+{consumer}\s*\((?P<args>.{{0,700}}?)\)\s*(?:->|\{{)",
            webrtc_source,
            flags=re.DOTALL,
        )
        if signature is None or "ConnectorRealtimeFlowCapability" not in signature.group(
            "args"
        ):
            failures.append(
                f"{consumer} does not consume ConnectorRealtimeFlowCapability"
            )
        implementation = ""
        if signature is not None:
            next_method = re.search(
                r"\n\s+pub\(crate\)\s+(?:async\s+)?fn\s+",
                webrtc_source[signature.end() :],
            )
            implementation_end = (
                signature.end() + next_method.start()
                if next_method is not None
                else min(len(webrtc_source), signature.end() + 2_000)
            )
            implementation = webrtc_source[signature.start() : implementation_end]
        if "owns_realtime_flow" not in implementation:
            failures.append(f"{consumer} does not verify exact connector ownership")
    if "enable_realtime_delivery" in webrtc_source:
        failures.append("legacy worker-only real-time enablement still exists")
    if not re.search(
        r"fn\s+admit_legacy_realtime_flow\s*\(.{0,500}?\)\s*->.*?\{.{0,500}?owns_endpoint_auth",
        webrtc_source,
        flags=re.DOTALL,
    ):
        failures.append("legacy real-time issuer does not verify exact Endpoint Auth provenance")

    if not (
        "let root = ProcessResourceRoot::global();" in webrtc_source
        and "root.install_connector_policy(policy.process())?;" in webrtc_source
        and "root.issue_mesh_connector_scope(policy.mesh())?;" in webrtc_source
    ):
        failures.append("public transport policy path does not use the process resource root")
    if "ProcessResourceRoot::global().mesh_runtime_scope()" not in engine_source:
        failures.append("public Mesh runtime path does not use the process resource root")

    for transport_policy_type in (
        "struct PendingRemoteCandidatePolicy",
        "struct LegacyWebRtcMediaProfile",
        "struct WebRtcConnectorProfile",
    ):
        if transport_policy_type in attempt_policy_source:
            failures.append(
                f"WebRTC-specific type remains in generic attempt policy: {transport_policy_type}"
            )
        if transport_policy_type not in webrtc_policy_source:
            failures.append(
                f"WebRTC-specific policy module is missing {transport_policy_type}"
            )
    process_policy = re.search(
        r"pub struct ConnectorResourcePolicy\s*\{(?P<body>.*?)\}",
        attempt_policy_source,
        flags=re.DOTALL,
    )
    if process_policy is None:
        failures.append("connector-neutral process policy type is missing")
    elif re.search(r"WebRtc|ICE|CandidatePolicy|Media|Codec", process_policy.group("body")):
        failures.append("process connector resource policy contains transport-specific fields")

    capacity_shape = re.search(
        r"pub struct ConnectorCallbackMailboxCapacities\s*\{(?P<body>.*?)\}",
        attempt_source,
        flags=re.DOTALL,
    )
    if capacity_shape is None:
        failures.append("generic callback mailbox capacity type is missing")
    else:
        body = capacity_shape.group("body")
        if "audio" in body or "video" in body:
            failures.append("generic callback mailbox capacity still names audio or video")
        for field in ("control", "endpoint_data"):
            if field not in body:
                failures.append(f"generic callback mailbox capacity is missing {field}")
        if re.search(r"\brealtime\s*:", body):
            failures.append("generic callback mailbox still contains one shared realtime queue")
        if "queue_capacity_per_flow" not in attempt_source:
            failures.append("codec-neutral per-flow realtime queue bound is missing")
        for structural_bound in (
            "max_inbound_fragment_bytes",
            "max_inbound_fragments_per_unit",
            "max_in_progress_units_per_flow",
            "max_inbound_bytes",
            "max_outbound_bytes",
            "max_pre_auth_packets",
            "max_pre_auth_content_bytes",
        ):
            if structural_bound not in attempt_source:
                failures.append(f"real-time policy is missing {structural_bound}")

    h264_source = (CORE / "src" / "transport" / "webrtc" / "h264.rs").read_text(
        encoding="utf-8"
    )
    for time_authority in ("tokio::time", "sleep(", "interval(", "timeout(", "deadline"):
        if time_authority in h264_source:
            failures.append(
                f"H.264 assembly contains forbidden elapsed-time authority: {time_authority}"
            )
    if "realtime_useful_lifetime" in webrtc_source or "realtime_useful_lifetime" in attempt_source:
        failures.append("real-time queue authority still contains realtime_useful_lifetime")
    if "pub async fn start(" in embedded_source:
        failures.append("ambiguous ownerless embedded::start constructor still exists")
    if "ConnectorOperationFence" not in webrtc_source:
        failures.append("connector operation lifecycle fence is missing")
    for lifecycle_phase in (
        "AwaitingOpen",
        "OpenPending",
        "OpenCommitted",
        "ClosedPending",
        "ClosedDelivered",
    ):
        if lifecycle_phase not in webrtc_source:
            failures.append(f"connector lifecycle owner is missing {lifecycle_phase}")
    if not (
        "lifecycle: Arc<ConnectorLifecycleOwner>" in webrtc_source
        and "self.events.lifecycle.record_open()" in webrtc_source
        and "self.events.lifecycle.record_close()" in webrtc_source
        and "self.raw.lifecycle.commit_open()" in webrtc_source
    ):
        failures.append("open and close are not owned by the fixed connector lifecycle owner")
    for forbidden_close_authority in (
        "ConnectorCloseStatus::Unproven",
        "mark_cleanup_unproven",
        "native_close_observation_limit",
        "MYOWNMESH_CONNECTOR_NATIVE_CLOSE_OBSERVATION_MS",
    ):
        if forbidden_close_authority in webrtc_source or forbidden_close_authority in attempt_source:
            failures.append(
                f"V4 native close still contains timer-derived authority: {forbidden_close_authority}"
            )
    if not (
        "ConnectorCloseStatus::Closing" in webrtc_source
        and "match native.close().await" in webrtc_source
        and "ConnectorCleanupExecutor" in attempt_source
        and re.search(
            r"tokio::sync::mpsc::channel(?:::<ConnectorCleanupJob>)?\(self\.capacity\.get\(\)\)",
            attempt_source,
        )
    ):
        failures.append("native close is not owned by the bounded process cleanup executor")

    recv_queued = re.search(
        r"async fn recv_queued\s*\(&mut self\).*?\n\s*\}",
        webrtc_source,
        flags=re.DOTALL,
    )
    if recv_queued is None or "ConnectorCallbackScheduler" not in webrtc_source:
        failures.append("bounded callback scheduler is missing")
    elif "biased;" in recv_queued.group(0):
        failures.append("callback receiver still uses permanently biased selection")
    if "reserve().await" in webrtc_source or ".reserve(\n" in webrtc_source:
        failures.append("connector callback producer can still await mailbox capacity")
    if "match mailbox.try_send(queued)" not in webrtc_source:
        failures.append("connector callback insertion does not use typed nonblocking admission")
    if not (
        "struct RemoteCandidateAttemptIdentity" in webrtc_source
        and "pending.attempt.try_enter()" in webrtc_source
        and "begin_local_ice_restart" in webrtc_source
        and "ProvisionalRemoteCandidateAttempt" in webrtc_source
        and "sdp_ice_credentials" in webrtc_source
        and "current.proves_restart_to(&credentials)" in webrtc_source
        and "candidate_matches_remote_credentials" in webrtc_source
        and "let declares_location = candidate.sdp_mline_index.is_some()" in webrtc_source
        and "if !declares_location && username_fragment.is_none()" in webrtc_source
        and "has_unambiguous_credential_pair" in webrtc_source
        and "candidate_line_username_fragment" in webrtc_source
        and "CandidateUsernameFragmentError::ConflictingDeclarations" in webrtc_source
        and "CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration"
        in webrtc_source
        and "candidate.sdp_mid" in webrtc_source
        and "adopt_queued_candidates_for_remote_restart" in webrtc_source
        and "retain_remote_restart_migratable_candidates" in webrtc_source
        and "commit_remote_description" in webrtc_source
        and "fail_remote_description" in webrtc_source
        and "has_no_viable_attempt" in webrtc_source
        and "must_retire_connector" in webrtc_source
        and "remote_description_in_flight" in webrtc_source
        and "wait_for_operations().await" in webrtc_source
    ):
        failures.append("remote candidates do not use a transactional exact ICE-attempt fence")
    if not (
        "PendingRemoteCandidateQueuePush::Retired" in webrtc_source
        and "self.attempt.retire();" in webrtc_source
        and "AttemptRetired" in webrtc_source
    ):
        failures.append("candidate-envelope refusal is not terminal for the exact attempt")
    if not re.search(
        r"match\s+candidate\.sdp_mline_index\s*\{\s*Some\(value\).*?hash\.update\(\[1\]\).*?None\s*=>\s*hash\.update\(\[0\]\)",
        webrtc_source,
        flags=re.DOTALL,
    ):
        failures.append("candidate duplicate identity does not tag media-line option presence")
    if not (
        "NativeDataChannelAdmission" in webrtc_source
        and "admit_legacy_track_shape" in webrtc_source
        and "callback_violation_reported" in webrtc_source
    ):
        failures.append("native data-channel and track cardinality are not structurally bounded")
    if not (
        "legacy_media_api: Arc<SyncMutex<Option<Arc<webrtc::api::API>>>>" in webrtc_source
        and "if legacy_media_profile.is_some()" in webrtc_source
        and "build_legacy_media_api()?" in webrtc_source
        and "legacy_media_codecs()" in webrtc_source
    ):
        failures.append("compatibility codec registration is not provider-selected and lazy")
    legacy_api = re.search(
        r"fn build_legacy_media_api\(\).*?\n\}", webrtc_source, flags=re.DOTALL
    )
    if legacy_api is None or "register_default_codecs" in legacy_api.group(0):
        failures.append("legacy media API still registers codecs outside H.264 and Opus")

    for legacy_call in (
        "routing::send_routed(",
        "routing::broadcast_flood(",
        "routing::on_routed_frame(",
    ):
        if legacy_call in engine_source:
            failures.append(f"V4 engine path still invokes legacy forwarding: {legacy_call}")

    if "pub struct LegacyV1Runtime" not in legacy_profile_source:
        failures.append("frozen LegacyV1 compatibility runtime is missing")
    if "LegacyV1Marker" in legacy_profile_source or "LegacyV1Marker" in routing_source:
        failures.append("removed LegacyV1 marker remains reachable")
    if "impl Default for LegacyV1Runtime" in legacy_profile_source:
        failures.append("LegacyV1 runtime must not be selected by default")
    if 'mod legacy_v1;' not in lib_source or 'legacy-v1 = []' not in core_manifest:
        failures.append("LegacyV1 source is not behind its explicit Cargo feature")
    if (CORE / "src" / "engine" / "routing.rs").exists():
        failures.append("LegacyV1 routing still exists under the V4 engine subtree")
    if (CORE / "src" / "services" / "relay.rs").exists():
        failures.append("LegacyV1 relay still exists under the generic services subtree")
    if "mod routing;" not in legacy_profile_source:
        failures.append("LegacyV1 facade does not privately own its routing module")
    if re.search(r"pub\s+use\s+legacy_v1::", lib_source):
        failures.append("crate-root LegacyV1 compatibility re-export remains reachable")
    for legacy_api in ("on_routed_frame", "send_routed", "broadcast_flood"):
        if not re.search(rf"pub\(crate\)\s+async\s+fn\s+{legacy_api}\s*\(", routing_source):
            failures.append(f"legacy routing API {legacy_api} is missing or externally public")
    relay_start = re.search(
        r"fn\s+start\s*\((?P<args>.{0,900}?)\)", relay_source, flags=re.DOTALL
    )
    if relay_start is None or "LegacyV1Runtime" not in relay_start.group("args"):
        failures.append("legacy relay service start lacks the explicit runtime")
    if not (
        "legacy_v1_networks: HashMap<String, LegacyNetworkRuntime>" in services_source
        and "legacy_v1_relays: HashMap<String, LegacyRelayRuntime>" in services_source
        and "LegacyNetworkRuntime::bind(runtime, &joined)" in services_source
        and "LegacyRelayRuntime::start(" in services_source
    ):
        failures.append("LegacyV1 routing and member relay do not have separate daemon owners")
    if not (
        'ROUTING_CHANNEL: &str = "__mesh_route__/v1"' in routing_source
        and 'RELAY_CHANNEL: &str = "__mesh_relay__/v1"' in relay_source
        and "Channel<routing::RoutedEnvelope>" in legacy_profile_source
        and "routing::on_routed_frame" in legacy_profile_source
        and "is_routing_wrapper" not in relay_source
        and "parse_wrapper" not in routing_source
        and "is_historical_routed_wrapper" in routing_source
        and "super::routing::is_historical_routed_wrapper(&env.payload)" in relay_source
    ):
        failures.append(
            "LegacyV1 routing and plain relay lack disjoint wires or old-wire rejection"
        )
    if not (
        "start_connector_capable_with_legacy_media" in embedded_source
        and "start_connector_capable_with_legacy_v1_and_media" in embedded_source
        and "ServeCompatibility::LegacyMedia" in serve_source
        and "LegacyV1WithMedia" in serve_source
        and "legacy_media_profile_from_lookup" in serve_source
    ):
        failures.append("independent and combined legacy-media deployment boundaries are missing")
    for name, source in (
        ("V4 connector", webrtc_source),
        ("V4 engine", engine_source),
        ("Endpoint Auth", endpoint_auth_source),
    ):
        if "LegacyV1Marker" in source or "LegacyV1Runtime" in source or "legacy_v1::" in source:
            failures.append(f"{name} path can reach the LegacyV1 runtime")

    if "LegacyPayloadRelayForbidden" not in services_source:
        failures.append("V4 daemon service policy does not reject the legacy payload relay")
    if "ServiceManager::validate_config(&cfg.services)?" not in embedded_source:
        failures.append("V4 daemon startup does not validate the payload-relay service policy")

    with tempfile.TemporaryDirectory(prefix="myownmesh-v4-arc03-compiler-") as temporary:
        project = Path(temporary)
        source_dir = project / "src"
        source_dir.mkdir()
        (project / "Cargo.toml").write_text(cargo_toml(), encoding="utf-8", newline="\n")
        shutil.copyfile(REPO / "Cargo.lock", project / "Cargo.lock")
        for probe in REJECTED:
            (source_dir / f"{probe.name}.rs").write_text(
                probe.source, encoding="utf-8", newline="\n"
            )
        (source_dir / "positive_public_types.rs").write_text(
            POSITIVE_SOURCE, encoding="utf-8", newline="\n"
        )

        positive_code, positive_diagnostics, positive_stderr = run_check(
            project, "positive_public_types"
        )
        if positive_code != 0:
            failures.append(
                "positive public-type control failed: "
                + (positive_stderr.strip() or str(positive_diagnostics))
            )

        for probe in REJECTED:
            return_code, diagnostics, stderr = run_check(project, probe.name)
            if return_code == 0:
                failures.append(f"{probe.name} compiled but rejection was required")
                continue
            if not matches(probe, diagnostics):
                summary = [
                    {
                        "code": (diagnostic.get("code") or {}).get("code"),
                        "message": diagnostic.get("message"),
                    }
                    for diagnostic in diagnostics
                ]
                failures.append(
                    f"{probe.name} failed for the wrong cause: expected {probe.code} "
                    f"and {probe.fragments}, got {summary}; cargo stderr={stderr.strip()!r}"
                )

    for name, features, source in AUTHORITY_POSITIVES:
        with tempfile.TemporaryDirectory(prefix=f"myownmesh-{name}-") as temporary:
            project = Path(temporary)
            source_dir = project / "src"
            source_dir.mkdir()
            (project / "Cargo.toml").write_text(
                authority_cargo_toml(name, features), encoding="utf-8", newline="\n"
            )
            shutil.copyfile(REPO / "Cargo.lock", project / "Cargo.lock")
            (source_dir / f"{name}.rs").write_text(
                source, encoding="utf-8", newline="\n"
            )
            return_code, diagnostics, stderr = run_check(project, name)
            if return_code != 0:
                failures.append(
                    f"{name} failed to compile for features {features}: "
                    + (stderr.strip() or str(diagnostics))
                )

    for features, probe in AUTHORITY_REJECTED:
        with tempfile.TemporaryDirectory(prefix=f"myownmesh-{probe.name}-") as temporary:
            project = Path(temporary)
            source_dir = project / "src"
            source_dir.mkdir()
            (project / "Cargo.toml").write_text(
                authority_cargo_toml(probe.name, features),
                encoding="utf-8",
                newline="\n",
            )
            shutil.copyfile(REPO / "Cargo.lock", project / "Cargo.lock")
            (source_dir / f"{probe.name}.rs").write_text(
                probe.source, encoding="utf-8", newline="\n"
            )
            return_code, diagnostics, stderr = run_check(project, probe.name)
            if return_code == 0:
                failures.append(f"{probe.name} compiled but rejection was required")
            elif not matches(probe, diagnostics):
                summary = [
                    {
                        "code": (diagnostic.get("code") or {}).get("code"),
                        "message": diagnostic.get("message"),
                    }
                    for diagnostic in diagnostics
                ]
                failures.append(
                    f"{probe.name} failed for the wrong cause: expected {probe.code} "
                    f"and {probe.fragments}, got {summary}; cargo stderr={stderr.strip()!r}"
                )

    if failures:
        print("V4 Arc 03 compiler-boundary checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "V4 Arc 03 compiler-boundary checks passed: one positive public-type "
        f"control, {len(REJECTED) + len(AUTHORITY_REJECTED)} cause-matched rejection "
        f"controls, {len(AUTHORITY_POSITIVES)} exact authority-set controls, and five "
        "exact real-time-flow consumers."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
