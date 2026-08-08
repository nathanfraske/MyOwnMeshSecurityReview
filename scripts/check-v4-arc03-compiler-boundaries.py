#!/usr/bin/env python3
"""Compile external Arc 03 probes and verify the exact rejection causes."""

from __future__ import annotations

import functools
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
# Probes compile outside the workspace and therefore inherit no root
# `[patch.crates-io]` table. These pinned vendor sources must be re-declared in
# every temporary manifest, or `cargo check --offline` fails on dependency
# resolution before it can emit an expected diagnostic.
REQUIRED_VENDOR_PATCHES = ("webrtc", "webrtc-ice")


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
        "transport_lab_fixture_grant_is_not_in_default_v4_api",
        """use myownmesh_core::transport_lab_connector_fixture_grant; // expected-error
fn main() { let _ = transport_lab_connector_fixture_grant; }
""",
        "E0432",
        ("transport_lab_connector_fixture_grant", "no `transport_lab_connector_fixture_grant`"),
    ),
    RejectedProbe(
        "transport_lab_candidate_fixture_grant_is_not_in_default_v4_api",
        """use myownmesh_core::transport_lab_remote_candidate_fixture_grant; // expected-error
fn main() { let _ = transport_lab_remote_candidate_fixture_grant; }
""",
        "E0432",
        (
            "transport_lab_remote_candidate_fixture_grant",
            "no `transport_lab_remote_candidate_fixture_grant`",
        ),
    ),
    RejectedProbe(
        "transport_lab_sdp_fixture_grant_is_not_in_default_v4_api",
        """use myownmesh_core::transport_lab_remote_description_fixture_grant; // expected-error
fn main() { let _ = transport_lab_remote_description_fixture_grant; }
""",
        "E0432",
        (
            "transport_lab_remote_description_fixture_grant",
            "no `transport_lab_remote_description_fixture_grant`",
        ),
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
        """use myownmesh_core::{ConnectorResourceOwnerPort, ResourceProviderPort};
fn bypass(provider: ResourceProviderPort) {
    let _ = ConnectorResourceOwnerPort::new(provider); // expected-error
}
fn main() {}
""",
        "E0624",
        ("new", "private"),
    ),
    RejectedProbe(
        "resource_provider_authority_cannot_be_forged",
        """use myownmesh_core::ResourceProviderAuthority;
fn bypass() {
    let _ = ResourceProviderAuthority { _private: () }; // expected-error
}
fn main() {}
""",
        "E0451",
        ("_private", "private"),
    ),
    RejectedProbe(
        "resource_lease_cannot_be_duplicated_for_stale_release",
        """use myownmesh_core::ResourceLease;
fn bypass(lease: ResourceLease) {
    let _: ResourceLease = lease.clone(); // expected-error
}
fn main() {}
""",
        "E0599",
        ("clone", "ResourceLease"),
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
    # Fairness attribution. The five probes below prove that an ordinary
    # external caller cannot construct, mint, select, or rebind a fairness
    # root. Each is paired with a positive source-shape guard in `main`, so a
    # renamed or deleted implementation fails the guard instead of silently
    # turning a rejection probe green on E0432 absence.
    RejectedProbe(
        # Proves privacy of the containing module, not mere absence: the path
        # resolves as far as `provider` and is refused at `finite`.
        "fairness_root_cannot_be_named_or_constructed_externally",
        """use myownmesh_core::resource::provider::finite::FairnessRoot; // expected-error
fn main() {
    let _ = std::mem::size_of::<FairnessRoot>();
}
""",
        "E0603",
        ("finite", "private"),
    ),
    RejectedProbe(
        # Half of a pair, and it proves absence rather than privacy. The mint is
        # `#[cfg(test)] pub(crate)` on disk, so it is not in the downstream
        # non-test API at all and an external caller gets E0599. The other half
        # is the positive source-shape guard in `main`, which proves the method
        # really exists with exactly that gate and visibility. Neither half
        # carries the claim alone, and this probe must never be read as
        # evidence of privacy.
        "fairness_root_scope_mint_is_not_public_api",
        """use myownmesh_core::resource::ResourceProviderPort;
fn bypass(port: &ResourceProviderPort) {
    let _ = port.create_fairness_root_scope(); // expected-error
}
fn main() {}
""",
        "E0599",
        ("create_fairness_root_scope", "not found"),
    ),
    RejectedProbe(
        # Proves the public scope constructor exposes no root selector: it
        # takes exactly one argument, the parent scope.
        "public_scope_creation_takes_no_root_selector",
        """use myownmesh_core::resource::{ResourceProviderPort, ResourceScope};
fn bypass(port: &ResourceProviderPort, parent: &ResourceScope, root: u64) {
    let _ = port.create_scope(parent, root); // expected-error
}
fn main() {}
""",
        "E0061",
        ("create_scope", "argument"),
    ),
    RejectedProbe(
        # Proves no ordinary public root mint: the public path requires a
        # parent scope, so a caller cannot request a parentless scope and
        # thereby obtain a fresh root.
        "ordinary_public_api_cannot_mint_a_parentless_root_scope",
        """use myownmesh_core::resource::ResourceProviderPort;
fn bypass(port: &ResourceProviderPort) {
    let _ = port.create_scope(None); // expected-error
}
fn main() {}
""",
        "E0308",
        ("&ResourceScope", "Option"),
    ),
    RejectedProbe(
        # Proves an attribution child scope cannot be rebound to another root:
        # no parent or root mutator exists on the public scope token.
        "attribution_child_scope_cannot_be_rebound_to_another_root",
        """use myownmesh_core::resource::ResourceScope;
fn bypass(scope: &ResourceScope, other: &ResourceScope) {
    scope.set_parent(other.clone()); // expected-error
}
fn main() {}
""",
        "E0599",
        ("set_parent", "not found"),
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


def toml_string(value: str) -> str:
    """Quote one TOML basic string."""

    return json.dumps(value)


@functools.lru_cache(maxsize=1)
def vendor_patch_entries() -> tuple[tuple[str, str], ...]:
    """Return the repository `[patch.crates-io]` overrides as absolute paths.

    External probes are compiled outside the workspace, so they do not inherit
    the root patch table. Without it, `cargo check --offline` tries to resolve
    the unpatched registry dependency and fails before any expected diagnostic
    is produced. The entries are read from the repository manifest so the
    probes cannot drift from the pinned vendor sources.
    """

    manifest = (REPO / "Cargo.toml").read_text(encoding="utf-8")
    section = re.search(
        r"^\[patch\.crates-io\][^\n]*\n(.*?)(?=^\[|\Z)",
        manifest,
        re.MULTILINE | re.DOTALL,
    )
    if section is None:
        raise SystemExit(
            "harness precondition failed: root Cargo.toml has no "
            "[patch.crates-io] table for the pinned vendor sources"
        )
    entries: list[tuple[str, str]] = []
    for name, relative in re.findall(
        r'^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}\n]*\bpath\s*=\s*"([^"]+)"',
        section.group(1),
        re.MULTILINE,
    ):
        resolved = (REPO / relative).resolve()
        if not (resolved / "Cargo.toml").is_file():
            raise SystemExit(
                "harness precondition failed: patched dependency "
                f"{name} has no manifest at {resolved.as_posix()}"
            )
        entries.append((name, resolved.as_posix()))
    patched = {name for name, _ in entries}
    missing = [name for name in REQUIRED_VENDOR_PATCHES if name not in patched]
    if missing:
        raise SystemExit(
            "harness precondition failed: root [patch.crates-io] is missing "
            f"{', '.join(missing)}; external probes would resolve unpinned "
            "registry sources"
        )
    return tuple(entries)


def patch_section() -> str:
    """Emit the `[patch.crates-io]` table shared by every temporary probe."""

    lines = [
        f"{name} = {{ path = {toml_string(path)} }}"
        for name, path in vendor_patch_entries()
    ]
    return "[patch.crates-io]\n" + "\n".join(lines) + "\n"


def cargo_toml() -> str:
    core_path = toml_string(CORE.as_posix())
    bins: list[str] = [
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
        f"myownmesh-core = {{ path = {core_path} }}\n\n"
        + "\n".join(bins)
        + "\n"
        + patch_section()
    )


def authority_cargo_toml(name: str, features: tuple[str, ...]) -> str:
    core_path = toml_string(CORE.as_posix())
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
        f"myownmesh-core = {{ path = {core_path}{feature_clause} }}\n\n"
        "[[bin]]\n"
        f'name = "{name}"\n'
        f'path = "src/{name}.rs"\n\n'
        + patch_section()
    )


def write_manifest(project: Path, manifest: str) -> None:
    """Write one probe manifest after checking it carries the vendor patches."""

    for name, path in vendor_patch_entries():
        if f"{name} = {{ path = {toml_string(path)} }}" not in manifest:
            raise SystemExit(
                "harness self-check failed: generated manifest in "
                f"{project.as_posix()} does not patch {name}"
            )
    (project / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")


def normalized_probe_environment() -> dict[str, str]:
    """Build the deterministic environment used for every probe compilation.

    An inherited rustc flag policy is removed. A caller such as CI may export
    `RUSTFLAGS=-D warnings` for the workspace gates, and that policy would then
    also apply to the probe project's freshly built dependency tree, including
    the isolated vendored `webrtc` sources. Those dependencies would fail on
    their own warnings before any probe could emit its expected diagnostic,
    which reports a dependency warning policy as if it were a boundary result.

    The workspace `-D warnings` gates run separately and remain required. A
    boundary probe must test its exact expected cause, fragments, and primary
    line instead, so it compiles under an explicit, flag-free policy.
    """

    environment = os.environ.copy()
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"):
        environment.pop(name, None)
    # Per-target forms of the same configuration key, for example
    # `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS`.
    for name in [
        key
        for key in environment
        if key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS")
    ]:
        environment.pop(name, None)
    return environment


def run_check(project: Path, binary: str) -> tuple[int, list[dict], str]:
    environment = normalized_probe_environment()
    environment["CARGO_TERM_COLOR"] = "never"
    environment.setdefault("CARGO_TARGET_DIR", COMPILER_TARGET.name)
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
            probe.name == "resource_provider_authority_cannot_be_forged"
            and code in (None, "E0451")
            and "ResourceProviderAuthority" in rendered
            and "private fields" in rendered
            and (primary_span_matches or code is None)
        ):
            return True
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
        CORE / "src" / "runtime" / "attempt" / "remote_candidate.rs",
    )
    provider_source = (
        CORE / "src" / "resource" / "provider.rs"
    ).read_text(encoding="utf-8")
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
        and "root.install_resource_provider(policy.resources())?;" in webrtc_source
        and "root.issue_mesh_connector_scope()?;" in webrtc_source
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
    for resource_type in (
        "pub struct ResourceClaim",
        "pub trait ResourceProvider",
        "pub struct ResourceLease",
        "pub enum ResourceClass",
        "pub struct ResourcePressure",
        "pub enum ResourceUnavailable",
        "pub enum ReclaimResult",
    ):
        if resource_type not in provider_source:
            failures.append(f"elastic resource contract is missing {resource_type}")
    # Positive source-shape guards for fairness attribution. Each rejection
    # probe above proves only that a boundary holds from outside the crate; what
    # it does not prove is that the guarded surface still exists in the shape the
    # frozen contract describes. Without these guards a renamed, deleted, or
    # re-gated implementation would let a probe keep passing on an item that is
    # simply gone. Which side carries which claim differs per probe: some prove
    # privacy against a resolvable item, and the test-only root mint proves
    # absence from the downstream API, with the guard below establishing its real
    # gate and visibility. Each per-probe comment states its own case.
    for required_shape, description in (
        ("mod finite {", "the provider-private finite module"),
        ("struct ScopeOrder(u64);", "the private ScopeOrder identity"),
        ("struct FairnessRoot(ScopeOrder);", "the private FairnessRoot attribution"),
        ("pub fn create_scope(", "the public child-scope constructor"),
        ("parent: &ResourceScope,", "the mandatory parent argument on public scope creation"),
        ("Some(parent.id())", "parent inheritance on the public scope path"),
    ):
        if required_shape not in provider_source:
            failures.append(
                f"fairness attribution surface is missing {description}: "
                f"{required_shape!r} is absent from provider.rs"
            )
    # The trusted root mint is test-only on disk, so its rejection probe can
    # only prove absence from the downstream API. This guard carries the other
    # half of that claim: the method exists, is gated by exactly `#[cfg(test)]`,
    # and is crate-visible rather than public. Removing the gate, widening the
    # visibility, or deleting the method fails here by name.
    test_only_root_mint = (
        r"#\[cfg\(test\)\]\s*"
        r"(?:(?://[^\n]*|#\[[^\]]*\])\s*)*"
        r"pub\(crate\)\s+fn\s+create_fairness_root_scope\s*\(\s*&self\s*\)"
    )
    if not re.search(test_only_root_mint, provider_source):
        failures.append(
            "the trusted root mint must be exactly `#[cfg(test)] pub(crate) fn "
            "create_fairness_root_scope(&self)` in provider.rs"
        )
    for forbidden_shape, reason in (
        ("pub use finite::FairnessRoot", "FairnessRoot must not be exported"),
        ("pub use finite::ScopeOrder", "ScopeOrder must not be exported"),
    ):
        if forbidden_shape in provider_source:
            failures.append(f"{reason}: {forbidden_shape!r} is present in provider.rs")
    # Visibility is checked by pattern rather than by exact string so that
    # `pub(crate)`, `pub(super)`, and `pub(in ...)` cannot slip past a literal
    # `pub ` match. The frozen contract is private to provider.rs.
    serde_derive = (
        r"#\[derive\([^)]*\b(?:Serialize|Deserialize)\b[^)]*\)\]"
        r"\s*(?:(?://[^\n]*|#\[[^\]]*\])\s*)*"
        r"(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+"
    )
    for pattern, reason in (
        (
            r"pub(?:\s*\([^)]*\))?\s+struct\s+FairnessRoot\b",
            "FairnessRoot must carry no visibility qualifier",
        ),
        (
            r"pub(?:\s*\([^)]*\))?\s+struct\s+ScopeOrder\b",
            "ScopeOrder must carry no visibility qualifier",
        ),
        (
            r"pub(?:\s*\([^)]*\))?\s+mod\s+finite\b",
            "the finite module must carry no visibility qualifier",
        ),
        # Serialization is forbidden for these two identities only. Unrelated
        # serialization elsewhere in provider.rs is not this control's business.
        (serde_derive + r"FairnessRoot\b", "FairnessRoot must derive no serde codec"),
        (serde_derive + r"ScopeOrder\b", "ScopeOrder must derive no serde codec"),
        (
            r"impl\b[^\n]*\b(?:Serialize|Deserialize)\b[^\n]*\bfor\s+(?:FairnessRoot|ScopeOrder)\b",
            "fairness attribution must implement no serde codec",
        ),
    ):
        if re.search(pattern, provider_source):
            failures.append(f"{reason}: provider.rs matches {pattern!r}")
    # Mutator absence is asserted on the ResourceScope surface itself rather
    # than file-wide, so unrelated internal helpers are not banned. External
    # unreachability is proved separately by the rejection probe.
    # The region is sliced by structural markers, not by brace matching: from a
    # column-zero `impl ResourceScope {` to the next column-zero `impl` item,
    # which in valid Rust cannot appear inside the block. A lazy brace regex
    # would silently stop at the first line-start `}` it met and let a later
    # method escape the scan, so the self-check below requires the two known
    # accessors to be inside the extracted region: a truncated slice fails by
    # name instead of quietly scanning nothing.
    scope_impl_regions = []
    for match in re.finditer(
        r"^impl ResourceScope \{[^\n]*$", provider_source, re.MULTILINE
    ):
        remainder = provider_source[match.end() :]
        next_item = re.search(r"^impl\b", remainder, re.MULTILINE)
        scope_impl_regions.append(
            remainder[: next_item.start()] if next_item else remainder
        )
    if not scope_impl_regions:
        failures.append(
            "fairness attribution surface is missing the inherent ResourceScope impl block"
        )
    elif not any(
        re.search(r"\bfn\s+id\b", region) and re.search(r"\bfn\s+parent_id\b", region)
        for region in scope_impl_regions
    ):
        failures.append(
            "inherent ResourceScope impl extraction is truncated: the known id and "
            "parent_id accessors are not both inside the scanned region, so the "
            "mutator scan below cannot be trusted"
        )
    for region in scope_impl_regions:
        for mutator in ("set_parent", "rebind", "reparent", "set_root", "fairness_root"):
            if re.search(rf"\bfn\s+{mutator}\b", region):
                failures.append(
                    f"ResourceScope must expose no {mutator} accessor or mutator"
                )
    resource_mod_source = (CORE / "src" / "resource" / "mod.rs").read_text(encoding="utf-8")
    for private_identity in ("FairnessRoot", "ScopeOrder"):
        if private_identity in resource_mod_source or private_identity in lib_source:
            failures.append(
                f"{private_identity} must not be re-exported outside the provider module"
            )
    for forbidden_cardinality in (
        "MAX_MESHES",
        "MAX_PEERS",
        "MAX_ATTEMPTS",
        "MAX_FLOWS",
        "ConnectorResourcePolicy",
        "MeshConnectorResourcePolicy",
    ):
        if forbidden_cardinality in attempt_source or forbidden_cardinality in provider_source:
            failures.append(
                f"basal resource contract still contains product cardinality {forbidden_cardinality}"
            )
    if not (
        "local_mailboxes: Option<ConnectorCallbackMailboxCapacities>" in attempt_policy_source
        and "local_service_weights: Option<ConnectorCallbackServiceWeights>" in attempt_policy_source
        and "local_ceiling: Option<PendingRemoteCandidateLocalCeiling>" in webrtc_policy_source
        and "pub const fn elastic_data_only()" in attempt_policy_source
        and "pub const fn elastic_realtime()" in attempt_policy_source
        and "pub const fn elastic()" in webrtc_policy_source
    ):
        failures.append("cardinality and queue ceilings are not explicit optional wrappers")

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
            failures.append("optional local per-flow real-time queue ceiling is missing")
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
        and re.search(
            r"self\.events\s*\.lifecycle\s*\.record_open\(\)", webrtc_source
        )
        and re.search(
            r"self\.events\s*\.lifecycle\s*\.record_close\(self\.callback_gate\.is_active\(\)\)",
            webrtc_source,
        )
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
        and "unbounded_channel::<ConnectorCleanupJob>()" in attempt_source
        and "_capability: ConnectorCleanupCapability" in attempt_source
    ):
        failures.append("native close is not owned by the lease-backed process cleanup executor")

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
    if "match mailbox.try_insert(queued)" not in webrtc_source:
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
        and "PendingRemoteCandidateQueuePush::InvalidBinding" in webrtc_source
        and "self.attempt.retire();" in webrtc_source
        and "AttemptRetired" in webrtc_source
        and "RemoteCandidateDisposition::InvalidBinding" in webrtc_source
        and "v4_arc03j_invalid_candidate_bindings_terminally_retire_the_attempt"
        in webrtc_source
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

    candidate_callback_start = webrtc_source.find("pc.on_ice_candidate")
    candidate_callback_end = webrtc_source.find(
        "pc.on_ice_connection_state_change", candidate_callback_start
    )
    candidate_callback = webrtc_source[candidate_callback_start:candidate_callback_end]
    conversion_order = [
        candidate_callback.find("begin_native_callback_operation"),
        candidate_callback.find(".to_json()"),
        candidate_callback.find("account_executing_payload"),
        candidate_callback.find("Box::pin(async move"),
    ]
    if candidate_callback_start < 0 or candidate_callback_end < 0 or any(
        position < 0 for position in conversion_order
    ) or conversion_order != sorted(conversion_order):
        failures.append(
            "local ICE conversion is not structurally reserved and measured before async retention"
        )

    remote_sdp_owner_start = webrtc_source.find("fn sdp_ice_credentials_owned")
    remote_sdp_owner_end = webrtc_source.find(
        "pub struct PeerSession", remote_sdp_owner_start
    )
    remote_sdp_owner = webrtc_source[remote_sdp_owner_start:remote_sdp_owner_end]
    remote_sdp_order = [
        remote_sdp_owner.find(".acquire("),
        remote_sdp_owner.find("plan_sdp_ice_credential_allocations"),
        remote_sdp_owner.find(".transition(planned_claim)"),
        remote_sdp_owner.find("parse_sdp_ice_credential_bindings"),
        remote_sdp_owner.find(".transition(retained_claim)"),
        remote_sdp_owner.find("RemoteIceCredentials::new"),
    ]
    if remote_sdp_owner_start < 0 or remote_sdp_owner_end < 0 or any(
        position < 0 for position in remote_sdp_order
    ) or remote_sdp_order != sorted(remote_sdp_order):
        failures.append(
            "remote SDP parsing or retention can occur before its finite operation lease"
        )

    remote_sdp_ingress_start = webrtc_source.find("pub(crate) async fn apply_remote_sdp")
    # Delimited by the owned applier's definition, which is where
    # `apply_remote_sdp` ends. The previous delimiter named the LegacyV1/test
    # entry point `pub(crate) async fn apply_remote_description`, and that entry
    # point was deliberately deleted in c02d966 — it bypassed this very ingress
    # — so the delimiter has been dangling since. Naming the owned applier
    # instead also survives a visibility change, which is the churn that broke
    # it, and matches the marker the residual-ownership guard below already
    # uses.
    remote_sdp_ingress_end = webrtc_source.find(
        "async fn apply_remote_description_owned", remote_sdp_ingress_start
    )
    remote_sdp_ingress = webrtc_source[
        remote_sdp_ingress_start:remote_sdp_ingress_end
    ]
    remote_sdp_ingress_order = [
        remote_sdp_ingress.find("sdp_ice_credentials_owned"),
        remote_sdp_ingress.find("RTCSessionDescription::offer"),
        remote_sdp_ingress.find("apply_remote_description_owned"),
    ]
    if (
        remote_sdp_ingress_start < 0
        or remote_sdp_ingress_end < 0
        or any(position < 0 for position in remote_sdp_ingress_order)
        or remote_sdp_ingress_order != sorted(remote_sdp_ingress_order)
        or "RTCSessionDescription::offer" in engine_source
        or "RTCSessionDescription::answer" in engine_source
    ):
        failures.append(
            "V4 remote SDP can enter dependency parsing before connector resource admission"
        )

    remote_sdp_apply_start = webrtc_source.find(
        "async fn apply_remote_description_owned"
    )
    remote_sdp_apply_end = webrtc_source.find(
        "async fn apply_remote_candidate", remote_sdp_apply_start
    )
    remote_sdp_apply = webrtc_source[remote_sdp_apply_start:remote_sdp_apply_end]
    remote_sdp_apply_order = [
        remote_sdp_apply.find("retain_remote_description_resources"),
        remote_sdp_apply.find("set_remote_description(description)"),
        remote_sdp_apply.find("finish_native_commit"),
    ]
    if remote_sdp_apply_start < 0 or remote_sdp_apply_end < 0 or any(
        position < 0 for position in remote_sdp_apply_order
    ) or remote_sdp_apply_order != sorted(remote_sdp_apply_order):
        failures.append(
            "remote SDP residual ownership is not transferred before native application"
        )

    if "LegacyPayloadRelayForbidden" not in services_source:
        failures.append("V4 daemon service policy does not reject the legacy payload relay")
    if "ServiceManager::validate_config(&cfg.services)?" not in embedded_source:
        failures.append("V4 daemon startup does not validate the payload-relay service policy")

    with tempfile.TemporaryDirectory(prefix="myownmesh-v4-arc03-compiler-") as temporary:
        project = Path(temporary)
        source_dir = project / "src"
        source_dir.mkdir()
        write_manifest(project, cargo_toml())
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
            write_manifest(project, authority_cargo_toml(name, features))
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
            write_manifest(project, authority_cargo_toml(probe.name, features))
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
