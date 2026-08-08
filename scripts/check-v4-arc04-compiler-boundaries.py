#!/usr/bin/env python3
"""Compile external Arc 04 probes and verify the exact rejection causes.

Arc 04 adds an endpoint-authentication boundary on top of Arc 03's connector
boundary, and its central claim is negative: no caller outside this crate can
construct, rebind, or extract the values that carry authentication authority —
the connector incarnation, the channel binding, the connected handoff, the task
and its immutable context, the authenticated capability and its permit, the
per-operation admission witnesses, either contribution type, or the closed
profile selector.

A negative claim needs a compiler to be worth anything, so each probe below is
an external crate that must fail to compile *for the exact stated cause*: the
error code, message fragments, and the primary span all have to land on the one
line marked `expected-error`. A probe that merely fails is not evidence — it
could be failing because an item was renamed or deleted, which is precisely the
regression the source-shape guards in `main` exist to catch.

The harness invariants are Arc 03's, deliberately: pinned vendor patches derived
from the root manifest, a generated-manifest self-check, a normalized rustflag
environment, the workspace lockfile, one shared temporary target directory, and
`--offline`. Only the probe set and the source-shape guards are Arc 04's.
"""

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
    prefix="myownmesh-v4-arc04-compiler-target-"
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
    # ---- connector incarnation ----
    # Naming is the root capability here: an incarnation cannot be constructed,
    # compared, or rebound by a caller that cannot name the type at all. The
    # re-export is `pub(crate)`, so the module resolves and the item does not.
    RejectedProbe(
        "connector_incarnation_cannot_be_named_externally",
        """use myownmesh_core::connector::ConnectorIncarnation; // expected-error
fn main() { let _ = std::mem::size_of::<ConnectorIncarnation>(); }
""",
        "E0603",
        ("ConnectorIncarnation", "private"),
    ),
    # ---- connector binding ----
    RejectedProbe(
        "endpoint_auth_binding_cannot_be_named_externally",
        """use myownmesh_core::connector::EndpointAuthBinding; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthBinding>(); }
""",
        "E0603",
        ("EndpointAuthBinding", "private"),
    ),
    RejectedProbe(
        # The binding profile is the closed selector the transcript commits to.
        # An external caller that could name it could describe a profile the
        # connector never supplied.
        "endpoint_auth_binding_profile_cannot_be_selected_externally",
        """use myownmesh_core::connector::EndpointAuthBindingProfile; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthBindingProfile>(); }
""",
        "E0603",
        ("EndpointAuthBindingProfile", "private"),
    ),
    RejectedProbe(
        "endpoint_auth_binding_provenance_cannot_be_stated_externally",
        """use myownmesh_core::connector::EndpointAuthBindingProvenance; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthBindingProvenance>(); }
""",
        "E0603",
        ("EndpointAuthBindingProvenance", "private"),
    ),
    # ---- connected handoff ----
    RejectedProbe(
        "connected_channel_handoff_cannot_be_named_externally",
        """use myownmesh_core::connector::ConnectedChannelHandoff; // expected-error
fn main() { let _ = std::mem::size_of::<ConnectedChannelHandoff>(); }
""",
        "E0603",
        ("ConnectedChannelHandoff", "private"),
    ),
    RejectedProbe(
        # The retention trait is what a handoff runs on drop. If it were
        # nameable, an external implementor could supply a retention that simply
        # discards the connected claim.
        "connected_channel_retention_cannot_be_implemented_externally",
        """use myownmesh_core::connector::ConnectedChannelRetention; // expected-error
fn main() { let _ = std::any::type_name::<dyn ConnectedChannelRetention>(); }
""",
        "E0603",
        ("ConnectedChannelRetention", "private"),
    ),
    # ---- task and its immutable context ----
    RejectedProbe(
        "endpoint_auth_context_cannot_be_named_externally",
        """use myownmesh_core::endpoint_auth::EndpointAuthContext; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthContext>(); }
""",
        "E0603",
        ("EndpointAuthContext", "private"),
    ),
    RejectedProbe(
        "endpoint_auth_task_cannot_be_named_externally",
        """use myownmesh_core::endpoint_auth::EndpointAuthTask; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthTask>(); }
""",
        "E0603",
        ("EndpointAuthTask", "private"),
    ),
    RejectedProbe(
        # The signer moves into the task. An external caller that could name it
        # could hold the signing authority the task is supposed to own.
        "local_identity_signer_cannot_be_named_externally",
        """use myownmesh_core::endpoint_auth::LocalIdentitySigner; // expected-error
fn main() { let _ = std::mem::size_of::<LocalIdentitySigner>(); }
""",
        "E0603",
        ("LocalIdentitySigner", "private"),
    ),
    # ---- authenticated capability ----
    # The capability type itself is deliberately public: Arc 05 consumers must be
    # able to *hold* one. What must be impossible is minting one or reading its
    # private provenance, so these two probes target the constructor and the
    # readback rather than the type.
    RejectedProbe(
        "authenticated_capability_cannot_be_minted_externally",
        """use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
fn bypass() {
    let _ = AuthenticatedChannelCapability::from_verified_exchange; // expected-error
}
fn main() { bypass(); }
""",
        "E0624",
        ("from_verified_exchange", "private"),
    ),
    RejectedProbe(
        "authenticated_capability_provenance_cannot_be_extracted_externally",
        """use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
fn bypass(capability: &AuthenticatedChannelCapability) {
    let _ = capability.record(); // expected-error
}
fn main() {}
""",
        "E0624",
        ("record", "private"),
    ),
    RejectedProbe(
        # Rebinding: the only question a capability answers about its connector
        # is crate-private, and there is no setter at all. A caller that cannot
        # even ask cannot re-point one at another incarnation.
        #
        # Written as an associated-item path rather than `capability.belongs_to`,
        # which the parser reads as a field access and rejects with E0609
        # ("no field") before privacy is ever considered — that would prove the
        # absence of a field nobody claimed exists. The path form resolves to the
        # method item and is refused for the reason under test. It also needs no
        # `ConnectorIncarnation` argument, which is itself unnameable from here.
        # Same shape as the mint probe above.
        "authenticated_capability_cannot_be_rebound_externally",
        """use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
fn bypass() {
    let _ = AuthenticatedChannelCapability::belongs_to; // expected-error
}
fn main() { bypass(); }
""",
        "E0624",
        ("belongs_to", "private"),
    ),
    # ---- permit ----
    RejectedProbe(
        # The permit is public so it can be carried, but every field is private,
        # so it cannot be forged by struct literal.
        #
        # The field value is a diverging expression on purpose. Supplying a
        # concrete stand-in such as `()` fails type checking first (E0308), which
        # proves only that the field is not a unit — a caller who guessed the
        # right type would sail past that and hit the real boundary. `!` coerces
        # to the field's private type *without naming it*, so type checking has
        # nothing to complain about and the compiler reaches the privacy check
        # that is actually under test.
        "endpoint_auth_permit_cannot_be_forged_externally",
        """use myownmesh_core::endpoint_auth::EndpointAuthPermit;
fn bypass() -> EndpointAuthPermit {
    EndpointAuthPermit { runtime: unimplemented!() } // expected-error
}
fn main() { let _ = bypass; }
""",
        "E0451",
        ("runtime", "private"),
    ),
    # ---- admission witnesses ----
    # Every move-only admission witness lives in `engine::state`, which is
    # `pub(crate) mod`. Proving the module is unreachable proves all admission
    # witnesses are unreachable at once, and does so against a path that really
    # resolves as far as `engine`. Deliberately unnumbered: the set grows as
    # operations are brought under the fence, and a count here would go stale
    # silently while still reading as a precise claim. The source-shape guard in
    # `main` names them individually and is where a new witness must be added.
    RejectedProbe(
        "admission_witness_module_is_unreachable_externally",
        """use myownmesh_core::engine::state::AdmittedApplicationOperation; // expected-error
fn main() { let _ = std::mem::size_of::<AdmittedApplicationOperation>(); }
""",
        "E0603",
        ("state", "private"),
    ),
    # ---- contributions ----
    RejectedProbe(
        "peer_contribution_cannot_be_named_externally",
        """use myownmesh_core::endpoint_auth::PeerContribution; // expected-error
fn main() { let _ = std::mem::size_of::<PeerContribution>(); }
""",
        "E0603",
        ("PeerContribution", "private"),
    ),
    RejectedProbe(
        # Absence, not privacy: the local draw is re-exported only under
        # `cfg(test)`, so it is not in the downstream API at all. The paired
        # source-shape guard in `main` proves the re-export really carries that
        # exact gate, so this probe cannot go green merely because the type was
        # deleted.
        "local_contribution_is_not_in_the_downstream_api",
        """use myownmesh_core::endpoint_auth::LocalContribution; // expected-error
fn main() { let _ = std::mem::size_of::<LocalContribution>(); }
""",
        "E0432",
        ("LocalContribution", "no `LocalContribution`"),
    ),
    # ---- closed profile selection ----
    RejectedProbe(
        "endpoint_auth_profile_cannot_be_selected_externally",
        """use myownmesh_core::endpoint_auth::EndpointAuthProfile; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthProfile>(); }
""",
        "E0603",
        ("EndpointAuthProfile", "private"),
    ),
    RejectedProbe(
        # The negotiation entry point is crate-private, so no external caller can
        # run profile selection with a feature list of its own choosing.
        "profile_negotiation_cannot_be_driven_externally",
        """fn bypass() {
    let _ = myownmesh_core::endpoint_auth::negotiate_profile; // expected-error
}
fn main() { bypass(); }
""",
        "E0603",
        ("negotiate_profile", "private"),
    ),
    RejectedProbe(
        # The typed refusal is private too: an embedder cannot match on it and
        # therefore cannot build a fallback path keyed to "incompatible profile".
        "endpoint_auth_error_cannot_be_matched_externally",
        """use myownmesh_core::endpoint_auth::EndpointAuthError; // expected-error
fn main() { let _ = std::mem::size_of::<EndpointAuthError>(); }
""",
        "E0603",
        ("EndpointAuthError", "private"),
    ),
)


# The public Arc 04 surface that must keep existing. Without this, every
# absence-shaped probe above could pass simply because the modules were deleted.
POSITIVE_SOURCE = """use myownmesh_core::connector::ConnectedChannelCapability;
use myownmesh_core::endpoint_auth::{AuthenticatedChannelCapability, EndpointAuthPermit};

fn public_endpoint_auth_surface(
    _: &ConnectedChannelCapability,
    _: &AuthenticatedChannelCapability,
    _: &EndpointAuthPermit,
) {
}

fn main() {
    let _ = public_endpoint_auth_surface;
    let _ = std::mem::size_of::<AuthenticatedChannelCapability>();
    let _ = std::mem::size_of::<EndpointAuthPermit>();
}
"""


def toml_string(value: str) -> str:
    """Quote one TOML basic string."""

    return json.dumps(value)


@functools.lru_cache(maxsize=1)
def vendor_patch_entries() -> tuple[tuple[str, str], ...]:
    """Return the repository `[patch.crates-io]` overrides as absolute paths.

    External probes are compiled outside the workspace, so they do not inherit
    the root patch table. Without it, `cargo check --offline` tries to resolve
    the unpatched registry dependency and fails before any expected diagnostic
    is produced. The entries are read from the repository manifest so the probes
    cannot drift from the pinned vendor sources.
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
        'name = "positive_endpoint_auth_surface"\n'
        'path = "src/positive_endpoint_auth_surface.rs"\n'
    )
    return (
        "[package]\n"
        'name = "myownmesh-v4-arc04-compiler-boundaries"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f"myownmesh-core = {{ path = {core_path} }}\n\n"
        + "\n".join(bins)
        + "\n"
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
    # Assigned unconditionally, not defaulted. An inherited `CARGO_TARGET_DIR` —
    # from CI, from a developer's shell, or from a wrapper — would otherwise win,
    # and the probes would build into a directory this harness does not own and
    # does not clean up. Worse, they would then share artifacts with whatever
    # else uses that directory, so a probe's result could depend on a build it
    # did not perform. The harness-owned temporary target is the only correct
    # destination.
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


def source_shape_failures() -> list[str]:
    """Positive guards for the surfaces the probes above claim to fence.

    A rejection probe proves only that a boundary holds from outside. It does
    not prove the guarded thing still exists in the shape the review fixed, and
    an absence-shaped probe stays green when its target is simply deleted. These
    guards carry that other half.
    """

    failures: list[str] = []
    features_source = (CORE / "src" / "protocol" / "features.rs").read_text(
        encoding="utf-8"
    )
    endpoint_auth_source = (CORE / "src" / "endpoint_auth" / "mod.rs").read_text(
        encoding="utf-8"
    )
    handshake_source = (CORE / "src" / "engine" / "handshake.rs").read_text(
        encoding="utf-8"
    )
    binding_source = (CORE / "src" / "connector" / "binding.rs").read_text(
        encoding="utf-8"
    )
    capability_source = (CORE / "src" / "endpoint_auth" / "capability.rs").read_text(
        encoding="utf-8"
    )
    task_source = (CORE / "src" / "endpoint_auth" / "task.rs").read_text(
        encoding="utf-8"
    )
    incarnation_source = (CORE / "src" / "connector" / "incarnation.rs").read_text(
        encoding="utf-8"
    )

    # The advertised profile id exists, is exactly one stable string, and this
    # build advertises what it requires. Two MyOwnMesh peers that both required
    # an id neither advertised could never authenticate.
    if 'ENDPOINT_AUTH_V1: &\'static str = "endpoint_auth_v1"' not in features_source:
        failures.append(
            "the closed endpoint-auth feature id is missing or renamed in features.rs"
        )
    advertised = re.search(
        r"pub const ADVERTISED_FEATURES: &\[&str\] = &\[(?P<body>.*?)\];",
        features_source,
        flags=re.DOTALL,
    )
    if advertised is None or "Feature::ENDPOINT_AUTH_V1" not in advertised.group("body"):
        failures.append(
            "ADVERTISED_FEATURES does not advertise the endpoint-auth profile this "
            "build requires"
        )

    # The typed refusal and the one-outcome selector.
    if "IncompatibleProfile" not in endpoint_auth_source:
        failures.append("the typed incompatible-auth-profile refusal is missing")
    negotiation = re.search(
        r"pub\(crate\) fn negotiate_profile\s*\((?P<args>.*?)\)\s*->\s*"
        r"(?P<ret>Result<EndpointAuthProfile, EndpointAuthError>)",
        endpoint_auth_source,
        flags=re.DOTALL,
    )
    if negotiation is None:
        failures.append(
            "profile selection is not the crate-private "
            "`negotiate_profile(...) -> Result<EndpointAuthProfile, EndpointAuthError>`"
        )
    # Exactly one closed profile: a second variant would make the selector a
    # negotiation, which is what the review forbids.
    profile_enum = re.search(
        r"pub\(crate\) enum EndpointAuthProfile \{(?P<body>.*?)\n\}",
        endpoint_auth_source,
        flags=re.DOTALL,
    )
    if profile_enum is None:
        failures.append("the closed EndpointAuthProfile enum is missing")
    else:
        variants = [
            line.strip().rstrip(",")
            for line in profile_enum.group("body").splitlines()
            if line.strip() and not line.strip().startswith("//")
        ]
        if variants != ["V1Ed25519Dtls"]:
            failures.append(
                "EndpointAuthProfile must expose exactly one closed variant, found "
                f"{variants!r}; a second variant turns advertisement into negotiation"
            )

    # The gate runs before any proof work. Order is the property: a check that
    # ran after the contribution was bound would already have signed something
    # for an unauthenticatable peer.
    on_hello_start = handshake_source.find("pub async fn on_hello(")
    on_hello_end = handshake_source.find("pub async fn on_auth_response(", on_hello_start)
    if on_hello_start < 0 or on_hello_end < 0:
        failures.append("on_hello or on_auth_response is missing from handshake.rs")
    else:
        on_hello = handshake_source[on_hello_start:on_hello_end]
        order = [
            on_hello.find("negotiate_profile(&hello.features)"),
            on_hello.find("PeerContribution::from_wire"),
            on_hello.find("accept_peer_hello"),
        ]
        if any(position < 0 for position in order) or order != sorted(order):
            failures.append(
                "on_hello does not refuse an unadvertised endpoint-auth profile before "
                "parsing the peer contribution and binding the attempt"
            )
        if "DropReason::AuthFailed" not in on_hello:
            failures.append("the profile refusal in on_hello does not fail closed")
        for downgrade_marker in ("fallback", "downgrade", "legacy_profile"):
            if re.search(rf"\b{downgrade_marker}\s*\(", on_hello):
                failures.append(
                    f"on_hello contains a {downgrade_marker} path for an unadvertised profile"
                )

    # The binding has exactly one constructor, it names its own profile, and it
    # is fail-closed on a missing component.
    if binding_source.count("pub(crate) fn webrtc_certificate_fingerprints") != 1:
        failures.append(
            "EndpointAuthBinding must have exactly one crate-private constructor"
        )
    if "if local_component.is_empty() || remote_component.is_empty()" not in binding_source:
        failures.append(
            "EndpointAuthBinding construction is not fail-closed on a missing component"
        )
    if re.search(r"^\s*pub\s+fn\s+", binding_source, re.MULTILINE):
        failures.append("EndpointAuthBinding must expose no public constructor or accessor")

    # The capability records the connector's stated binding context and the task
    # compares it on install.
    for recorded in ("binding_profile", "binding_provenance", "local_role"):
        if f"{recorded}:" not in capability_source:
            failures.append(f"the authenticated binding record does not retain {recorded}")
    for compared in (
        "record.local_role() == exchange.context.local_role()",
        "record.binding_profile() == exchange.context.binding().profile()",
        "record.binding_provenance() == exchange.context.binding().provenance()",
    ):
        if compared not in task_source:
            failures.append(f"EndpointAuthTask::issued does not compare {compared}")

    # The generic incarnation is identity only: a second liveness source here
    # could disagree with the transport's own.
    for forbidden in (r"\bfn\s+is_active\b", r"\bfn\s+retire\b", r"\bAtomicBool\b"):
        if re.search(forbidden, incarnation_source):
            failures.append(
                "the generic connector incarnation must carry identity only, but "
                f"incarnation.rs matches {forbidden!r}"
            )

    # The local draw is re-exported only under cfg(test). This is the other half
    # of the absence probe above: without it, deleting the type would keep that
    # probe green.
    if not re.search(
        r"#\[cfg\(test\)\]\s*pub\(crate\) use contribution::LocalContribution;",
        endpoint_auth_source,
    ):
        failures.append(
            "the local contribution must be re-exported exactly under #[cfg(test)], "
            "so production generation stays inside EndpointAuthTask"
        )
    if not re.search(
        r"pub\(crate\) use contribution::PeerContribution;", endpoint_auth_source
    ):
        failures.append(
            "the peer contribution re-export is missing; the production inbound path "
            "parses it"
        )

    # Deletion-falsifiability half of the
    # `admission_witness_module_is_unreachable_externally` probe. That probe
    # proves only that `engine::state` cannot be reached from outside the crate,
    # and an unreachable module that no longer contains the witnesses refuses a
    # caller just as flatly as one that does — so on its own it stays green when
    # a witness is renamed or deleted. These guards carry the other half: each
    # witness must still exist, under its exact name, and still be crate-internal
    # rather than public. The declarations are matched by regex so formatting may
    # move but the name and the visibility qualifier may not.
    state_source = (CORE / "src" / "engine" / "state.rs").read_text(encoding="utf-8")
    for witness, declaration in (
        (
            "AdmittedLegacyOperation",
            r"pub\(super\)\s+struct\s+AdmittedLegacyOperation\s*<\s*'a\s*>",
        ),
        (
            "AdmittedApplicationOperation",
            r"pub\(super\)\s+struct\s+AdmittedApplicationOperation\b",
        ),
        (
            "AdmittedRealtimeOperation",
            r"pub\(super\)\s+struct\s+AdmittedRealtimeOperation\b",
        ),
        (
            "AdmittedRenegotiation",
            r"pub\(super\)\s+struct\s+AdmittedRenegotiation\b",
        ),
    ):
        if not re.search(declaration, state_source):
            failures.append(
                f"the {witness} admission witness is missing, renamed, or no longer "
                "declared `pub(super)` in engine/state.rs; the module-privacy probe "
                "cannot carry that claim on its own"
            )
    return failures


def main() -> int:
    failures = source_shape_failures()

    with tempfile.TemporaryDirectory(prefix="myownmesh-v4-arc04-compiler-") as temporary:
        project = Path(temporary)
        source_dir = project / "src"
        source_dir.mkdir()
        write_manifest(project, cargo_toml())
        shutil.copyfile(REPO / "Cargo.lock", project / "Cargo.lock")
        for probe in REJECTED:
            (source_dir / f"{probe.name}.rs").write_text(
                probe.source, encoding="utf-8", newline="\n"
            )
        (source_dir / "positive_endpoint_auth_surface.rs").write_text(
            POSITIVE_SOURCE, encoding="utf-8", newline="\n"
        )

        positive_code, positive_diagnostics, positive_stderr = run_check(
            project, "positive_endpoint_auth_surface"
        )
        if positive_code != 0:
            failures.append(
                "positive endpoint-auth surface control failed: "
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

    if failures:
        print("V4 Arc 04 compiler-boundary checks failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "V4 Arc 04 compiler-boundary checks passed: one positive public "
        f"endpoint-auth surface control and {len(REJECTED)} cause-matched rejection "
        "controls over connector incarnation, channel binding, connected handoff, "
        "task context, authenticated capability, permit, admission witnesses, both "
        "contribution types, and closed profile selection."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
