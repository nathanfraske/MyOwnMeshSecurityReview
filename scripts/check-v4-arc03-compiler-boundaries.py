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
    # The retired fixed video/audio surface. These four names were the whole
    # entry path to it: a sample type, a lane selector, the provider profile
    # that registered the fixed codec set, and the pre-V4 routing runtime. They
    # are gone from the crate under every feature selection, and these probes
    # are what turns "gone" into something that stays gone — reintroducing any
    # one of them publicly turns its probe red.
    RejectedProbe(
        "retired_video_sample_type_is_absent",
        """use myownmesh_core::transport::VideoSample; // expected-error
fn main() { let _ = std::mem::size_of::<VideoSample>(); }
""",
        "E0432",
        ("VideoSample", "no `VideoSample`"),
    ),
    RejectedProbe(
        "retired_media_lane_kind_is_absent",
        """use myownmesh_core::transport::LaneKind; // expected-error
fn main() { let _ = std::mem::size_of::<LaneKind>(); }
""",
        "E0432",
        ("LaneKind", "no `LaneKind`"),
    ),
    RejectedProbe(
        "retired_fixed_media_profile_is_absent",
        """use myownmesh_core::LegacyWebRtcMediaProfile; // expected-error
fn main() { let _ = std::mem::size_of::<LegacyWebRtcMediaProfile>(); }
""",
        "E0432",
        ("LegacyWebRtcMediaProfile", "no `LegacyWebRtcMediaProfile`"),
    ),
    RejectedProbe(
        "retired_v1_routing_runtime_is_absent",
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
        "connector_incarnation_is_not_public",
        """use myownmesh_core::connector::ConnectorIncarnation; // expected-error
fn main() { let _ = std::mem::size_of::<ConnectorIncarnation>(); }
""",
        "E0603",
        ("ConnectorIncarnation", "private"),
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
    # root. The positive public-type control is what keeps them honest: it names
    # the surface that must still exist, so a renamed or deleted implementation
    # fails there instead of silently turning a rejection probe green on E0432
    # absence.
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
        # Proves absence rather than privacy. The mint is `#[cfg(test)]
        # pub(crate)` on disk, so it is not in the downstream non-test API at
        # all and an external caller gets E0599. This probe must never be read
        # as evidence of privacy.
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


# There is one authority set, selected by no feature.
#
# Four permutations were checked here — the V4 set, two compatibility sets, and
# both composed — because each feature selected a distinct authority and the
# cross-probes proved one could not reach the other's types. The features are
# gone from the crate, so the permutations are not merely redundant: a manifest
# naming one no longer resolves. What survives is the single positive control
# that the public diagnostic types are reachable with no feature selected.
AUTHORITY_POSITIVES = (("v4_only_authority_set", (), POSITIVE_SOURCE),)


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

    if failures:
        print("V4 Arc 03 compiler-boundary checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "V4 Arc 03 compiler-boundary checks passed: one positive public-type "
        f"control, {len(REJECTED)} cause-matched rejection controls, and "
        f"{len(AUTHORITY_POSITIVES)} exact authority-set control."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
