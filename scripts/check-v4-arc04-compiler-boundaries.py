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


def impl_body(source: str, type_name: str) -> str | None:
    """Return the whole body of `impl <type_name>`, or None if it is absent.

    Anchored on column-zero boundaries — the `impl` header and the next
    top-level `}` — rather than on a non-greedy brace match. A non-greedy match
    is only correct as long as no inner line ever begins a brace at column zero,
    which is a formatting accident rather than a guarantee; a guard that
    silently inspected the first method alone would report every later method as
    absent, or miss a widened one entirely. Slicing to the next top-level item
    makes the extraction independent of what the method bodies contain.
    """

    header = re.search(
        rf"^impl {re.escape(type_name)}\b[^\n]*\{{\n", source, re.MULTILINE
    )
    if header is None:
        return None
    rest = source[header.end() :]
    end = re.search(r"^\}", rest, re.MULTILINE)
    return rest[: end.start()] if end is not None else rest


def function_body(source: str, name: str) -> str | None:
    """Return one free function's source, or None if it is absent.

    Anchored the same way as `impl_body`: from the signature's column-zero
    `fn`/visibility keyword to the next top-level `}`. Any visibility qualifier
    and an optional `async` are accepted, so a guard written against this does
    not silently start passing because the function was narrowed or widened.
    """

    header = re.search(
        rf"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn {re.escape(name)}\b",
        source,
        re.MULTILINE,
    )
    if header is None:
        return None
    rest = source[header.start() :]
    end = re.search(r"^\}", rest, re.MULTILINE)
    return rest[: end.start()] if end is not None else rest


def call_arguments(source: str, name: str) -> str | None:
    """Return the argument text of the first `name(...)` call in `source`.

    Paren-balanced rather than line- or regex-shaped, so a multi-line closure
    argument is returned whole and rustfmt may re-wrap the call freely. This is
    what lets a guard ask what happens *inside* a fenced closure rather than
    guessing at its extent from indentation.
    """

    call = re.search(rf"\b{re.escape(name)}\s*\(", source)
    if call is None:
        return None
    depth = 0
    for index in range(call.end() - 1, len(source)):
        character = source[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return source[call.end() : index]
    return None


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
        (
            "AdmittedInboundApplicationOperation",
            r"pub\(super\)\s+struct\s+AdmittedInboundApplicationOperation\b",
        ),
        (
            "AdmittedInboundDispatch",
            r"pub\(super\)\s+struct\s+AdmittedInboundDispatch\b",
        ),
    ):
        if not re.search(declaration, state_source):
            failures.append(
                f"the {witness} admission witness is missing, renamed, or no longer "
                "declared `pub(super)` in engine/state.rs; the module-privacy probe "
                "cannot carry that claim on its own"
            )

    # The inbound witness replaced an `Option<bool>` that outlived its fence, so
    # the two properties that make it a witness rather than a flag are guarded
    # here: it cannot be quietly ignored, and it authorizes exactly one dispatch
    # because the only way to open it consumes it.
    if not re.search(
        r"#\[must_use[^\n]*\]\s*(?:#\[[^\n]*\]\s*)*"
        r"pub\(super\) struct AdmittedInboundApplicationOperation\b",
        state_source,
    ):
        failures.append(
            "AdmittedInboundApplicationOperation is not #[must_use]; an admitted "
            "inbound frame that can be dropped silently is the Option<bool> again"
        )
    if not re.search(
        r"pub\(super\)\s+fn\s+into_dispatch\s*\(\s*self\s*,?\s*\)",
        state_source,
    ):
        failures.append(
            "AdmittedInboundApplicationOperation::into_dispatch must take `self` by "
            "value; a `&self` form would let one admission dispatch a frame twice"
        )

    # The dispatch witness had a check-then-act defect: it answered currency as
    # a boolean and the caller acted on that answer afterwards, outside the
    # registry mutation fence, so a replacement could land in the gap between
    # "still current" and the effect. The repair was to run the effect *inside*
    # `PeerRegistry::with_current`, which holds the mutation lock across the
    # whole closure. These three guards pin that shape, because the defect is
    # reintroduced by ordinary-looking code and no probe above can see it.
    dispatch_body = impl_body(state_source, "AdmittedInboundDispatch")
    if dispatch_body is None:
        failures.append(
            "the AdmittedInboundDispatch impl block is missing or reshaped in "
            "engine/state.rs, so its fenced-dispatch shape cannot be checked"
        )
    else:
        # Anything wider than `pub(super)`, in any of the forms rustfmt emits:
        # bare `pub`, a restricted-but-wider `pub(crate)` or `pub(in ...)`, and
        # the `async` variants of each. `pub(super)` is the one accepted form,
        # so the check is a negative lookahead rather than a list of the ways to
        # get it wrong.
        if re.search(
            r"^\s*pub(?!\(super\))(?:\([^)]*\))?\s+(?:async\s+)?fn\s+",
            dispatch_body,
            re.MULTILINE,
        ):
            failures.append(
                "AdmittedInboundDispatch exposes a method wider than `pub(super)`; "
                "every method on an admission witness must stay `pub(super)`"
            )
        if not re.search(r"peers\.with_current\s*\(", dispatch_body):
            failures.append(
                "AdmittedInboundDispatch no longer dispatches through "
                "`PeerRegistry::with_current`; the effect must run inside the "
                "registry mutation fence, not after a currency answer"
            )
        if re.search(r"\bget_if_current\s*\(", dispatch_body):
            failures.append(
                "AdmittedInboundDispatch uses `get_if_current`; that is the "
                "check-then-act shape this witness exists to remove, because a "
                "replacement can land between the check and the effect"
            )
        # A currency *predicate* on the witness is the boolean again with a new
        # name: whatever it returns is already stale by the time a caller reads
        # it, and every caller must then act outside the fence.
        if re.search(r"\bfn\s+is_current\b", dispatch_body):
            failures.append(
                "AdmittedInboundDispatch exposes an `is_current` boolean accessor; "
                "currency must be established and consumed inside one fenced "
                "operation, never handed to a caller to act on"
            )
        # The whole point of the witness is that it names an installation rather
        # than a device id. An accessor that handed the device id back would
        # restore the re-resolution escape it was built to close.
        if re.search(r"\bfn\s+(device_id|peer_id|peer_device_id)\b", dispatch_body):
            failures.append(
                "AdmittedInboundDispatch exposes a device-id accessor; the device id "
                "is the re-resolution key this witness exists to remove, and handlers "
                "must take identity from its owner token instead"
            )

    # The other half of the same defect, at the call sites: taking the fenced
    # helper's `Option` and collapsing it to a bool re-creates the stale answer
    # the repair removed, even though the helper itself is now correct.
    #
    # Narrow on purpose, and anchored rather than windowed. For each call it
    # looks at exactly one place — whatever immediately follows that call's own
    # closing `)`, on the same line — so an unrelated `.is_some()` elsewhere in
    # the function cannot be misattributed to it. It does not follow a result
    # through an intermediate binding. It is a recurrence guard, not a proof.
    for module in ("mod.rs", "heartbeat.rs", "reliable.rs", "handshake.rs"):
        source = (CORE / "src" / "engine" / module).read_text(encoding="utf-8")
        for call in re.finditer(r"\bwith_captured_peer\s*\(", source):
            tail = source[call.start() :]
            # A call closed on its own line, or a multi-line call closed by the
            # closure's `})`. Whichever applies, `after` is the text that would
            # carry a conversion.
            single_line = re.match(r"with_captured_peer\s*\([^\n]*\)(?P<after>[^\n]*)", tail)
            if single_line is not None:
                after = single_line.group("after")
            else:
                closing = re.search(r"^[ \t]*\}\s*\)(?P<after>[^\n]*)", tail, re.MULTILINE)
                after = closing.group("after") if closing is not None else ""
            if re.match(r"\s*\.(is_some|is_none|unwrap_or)\s*\(", after):
                failures.append(
                    f"engine/{module} turns a with_captured_peer result into a bool "
                    "at the call site; the fenced effect's own return value must be "
                    "used, not a currency verdict acted on outside the fence"
                )

    # The inbound handlers that take a dispatch witness are crate-internal. They
    # were narrowed from `pub` once every caller was known to live in
    # `engine::mod`, so re-widening one would put a witness-taking signature back
    # on the module's public surface for no caller that needs it.
    for module, handlers in (
        ("heartbeat.rs", ("on_ping", "on_pong")),
        ("reliable.rs", ("on_channel_seq_admitted",)),
    ):
        source = (CORE / "src" / "engine" / module).read_text(encoding="utf-8")
        for handler in handlers:
            if not re.search(
                rf"^pub\(super\) async fn {handler}\b", source, re.MULTILINE
            ):
                failures.append(
                    f"engine/{module}::{handler} is no longer declared "
                    "`pub(super) async fn`; the inbound handlers that take an "
                    "admission witness must stay crate-internal"
                )

    # The inbound reliable path had the same defect one layer down, and in its
    # most damaging form. The receiver's high-water mark was advanced inside the
    # admission fence while the payload was delivered under a *second* fence, so
    # a replacement landing in the gap fenced out the delivery and left the mark
    # advanced. The sender's retransmit was then classified a duplicate,
    # acknowledged, and the caller's `enqueue` resolved `Ok` for a payload that
    # reached no subscriber — a silent loss reported as a success.
    #
    # The repair makes the mark and the delivery one fenced step. These guards
    # pin that shape, because it is undone by ordinary-looking refactors — a
    # `deliver` flag returned "for clarity", a delivery hoisted out of the
    # closure — and no compiler probe can see either.
    reliable_source = (CORE / "src" / "engine" / "reliable.rs").read_text(encoding="utf-8")
    admission_result = re.search(
        r"pub\(crate\) enum InboundReliableAdmission \{(?P<body>.*?)\n\}",
        reliable_source,
        flags=re.DOTALL,
    )
    if admission_result is None:
        failures.append(
            "the InboundReliableAdmission result is missing or reshaped in "
            "engine/reliable.rs, so the fenced inbound-reliable shape cannot be checked"
        )
    else:
        # Comment lines are stripped first: the guard is about what the type
        # carries, and the doc comments here legitimately discuss the boolean
        # that used to be carried.
        carried = "\n".join(
            line
            for line in admission_result.group("body").splitlines()
            if not line.strip().startswith("//")
        )
        if re.search(r"\bbool\b", carried):
            failures.append(
                "InboundReliableAdmission carries a boolean out of the admission "
                "fence; a delivery verdict decided under one fence and acted on "
                "under another is exactly the gap a replacement lands in"
            )

    seq_handler = function_body(reliable_source, "on_channel_seq_admitted")
    if seq_handler is None:
        failures.append(
            "engine/reliable.rs::on_channel_seq_admitted is missing or reshaped, so "
            "the fenced mark-and-deliver step cannot be checked"
        )
    else:
        fenced = call_arguments(seq_handler, "with_captured_peer")
        if fenced is None:
            failures.append(
                "on_channel_seq_admitted no longer runs through "
                "`with_captured_peer`; the high-water mark and the delivery must "
                "move inside the registry mutation fence, not around it"
            )
        else:
            for required, consequence in (
                (
                    "advance_inbound_mark_and_deliver",
                    "the high-water mark is no longer advanced inside the fenced "
                    "closure",
                ),
                (
                    "dispatch_channel_frame",
                    "the payload is no longer handed to the subscribers inside the "
                    "same fenced closure",
                ),
            ):
                if required not in fenced:
                    failures.append(
                        f"on_channel_seq_admitted: {consequence}; a mark that can "
                        "advance without the delivery makes the sender's retransmit "
                        "read as a duplicate and be acked"
                    )
            if ".await" in fenced:
                failures.append(
                    "the fenced closure in on_channel_seq_admitted awaits; it runs "
                    "under the non-reentrant PeerRegistry mutation lock, and an await "
                    "there is also the gap the mark and the delivery must not have "
                    "between them"
                )

    mark_helper = function_body(reliable_source, "advance_inbound_mark_and_deliver")
    if mark_helper is None:
        failures.append(
            "engine/reliable.rs::advance_inbound_mark_and_deliver is missing or "
            "renamed; the mark advance and the delivery must stay one call"
        )
    else:
        advance = mark_helper.find("mark.last_seq = seq")
        hand_off = mark_helper.find("deliver(payload)")
        if advance < 0 or hand_off < 0 or hand_off < advance:
            failures.append(
                "advance_inbound_mark_and_deliver does not advance the mark and then "
                "hand the payload on in the same branch; the biconditional it exists "
                "to hold is that the mark moves if and only if the payload was "
                "delivered"
            )
        if ".await" in mark_helper:
            failures.append(
                "advance_inbound_mark_and_deliver awaits; it is called from inside "
                "the registry fence and must be one synchronous step"
            )

    engine_source = (CORE / "src" / "engine" / "mod.rs").read_text(encoding="utf-8")

    # `AdmittedRpcCall` is the heaviest fenced authority: it authorizes one run
    # of arbitrary embedder code. Three structural facts are guarded, and only
    # three, because only three are true.
    #
    # It claims **authorization atomicity, not cancellation.** A replacement
    # landing before the mint refuses the authority and the handler never runs;
    # a replacement landing after the mint does not cancel anything, and the
    # handler runs to completion. Nothing below asserts otherwise, and no guard
    # here should ever be read as evidence that an authorized run can be
    # revoked. What the capture buys is that the run is owner-bound, so its
    # replies fail closed against a superseded installation.
    if not re.search(
        r"#\[must_use[^\n]*\]\s*struct AdmittedRpcCall\b", engine_source
    ):
        failures.append(
            "AdmittedRpcCall must stay a module-private `#[must_use] struct` in "
            "engine/mod.rs; a visibility qualifier would hand the authority to run "
            "embedder code to another module, and dropping #[must_use] would let "
            "one be minted and silently discarded"
        )
    rpc_mint = re.search(
        r"with_captured_peer\s*\(.{0,400}?AdmittedRpcCall\s*\{.{0,300}?\}\s*\)\s*else",
        engine_source,
        re.DOTALL,
    )
    if rpc_mint is None:
        failures.append(
            "AdmittedRpcCall is no longer minted inside `with_captured_peer`; the "
            "authority to run a handler must be taken at the same fenced "
            "linearization point that proves the installation is current"
        )
    elif ".await" in rpc_mint.group(0):
        failures.append(
            "the fenced closure that mints an AdmittedRpcCall awaits; it must build "
            "a value and call nothing, or embedder code runs under the "
            "non-reentrant PeerRegistry mutation lock and a handler that calls back "
            "into the mesh deadlocks"
        )

    if not re.search(r"^pub\(crate\) mod state;", engine_source, re.MULTILINE):
        failures.append(
            "engine::state is no longer declared `pub(crate) mod state;`; that "
            "declaration is what keeps every admission witness in it out of the "
            "downstream API, and the module-privacy probe depends on it"
        )

    failures.extend(terminal_lifecycle_failures(task_source))
    failures.extend(rpc_binding_failures(engine_source))
    failures.extend(refused_open_failures(engine_source))
    return failures


def terminal_lifecycle_failures(task_source: str) -> list[str]:
    """Arc 04F1: the task has exactly one way to end, and it holds the lock.

    The property is an interleaving, so no external probe can reach it: a
    caller outside the crate cannot name the task at all, and the defect it
    replaces was visible only to two threads. What makes the invariant hold is
    that `terminalize` is the *sole* writer of both the terminal state and the
    `retired` cache and can only be called with the exchange guard in hand.
    Sole-writer claims are exactly what a source-shape guard can carry and a
    control cannot: a control proves the paths it drives, while a second writer
    added tomorrow is proved absent only by counting.
    """

    failures: list[str] = []

    if "retire_terminally" in task_source:
        failures.append(
            "endpoint_auth/task.rs still mentions `retire_terminally`; that was the "
            "transition that could run without the exchange guard, and its removal "
            "is what makes `terminalize` the only way for a task to end"
        )
    if not re.search(
        r"fn terminalize\s*\(\s*&self,\s*exchange:\s*&mut EndpointAuthExchange,",
        task_source,
    ):
        failures.append(
            "EndpointAuthTask::terminalize must take `exchange: &mut "
            "EndpointAuthExchange`; taking the guard as an argument is what makes it "
            "uncallable without the lock, and a `&self`-only form would restore a "
            "transition that can run beside a live critical section"
        )

    # Two sole-writer counts. `state = ExchangeState::Terminal(` is the
    # authoritative write; `retired.store(` is the lock-free observation cache.
    # If either gains a second writer the two can disagree, and a task could
    # report itself retired while its state would still admit a signature.
    terminal_writes = len(
        re.findall(r"\bstate\s*=\s*ExchangeState::Terminal\s*\(", task_source)
    )
    if terminal_writes != 1:
        failures.append(
            "endpoint_auth/task.rs assigns ExchangeState::Terminal "
            f"{terminal_writes} times; exactly one writer is the invariant, and a "
            "second one can commit a terminal state the retired cache does not know "
            "about"
        )
    cache_writes = len(re.findall(r"\bretired\.store\s*\(", task_source))
    if cache_writes != 1:
        failures.append(
            f"endpoint_auth/task.rs writes the `retired` cache {cache_writes} times; "
            "exactly one writer, inside the locked transition, is what stops the "
            "cache leading the state it is supposed to reflect"
        )

    # `retire` must take the lock before it marks anything. Marking first is
    # the exact defect: an operation already inside the critical section would
    # then be free to sign or move the handoff out after every observer could
    # already see a retired task.
    retire_body = fn_body(task_source, "pub(crate) fn retire(&self)")
    if retire_body is None:
        failures.append(
            "EndpointAuthTask::retire is missing or reshaped in endpoint_auth/task.rs, "
            "so its lock ordering cannot be checked"
        )
    else:
        if "self.lock()" not in retire_body:
            failures.append(
                "EndpointAuthTask::retire no longer takes the exchange lock itself; "
                "retirement must linearize through the same lock every operation uses"
            )
        if re.search(r"retired\.store\s*\(", retire_body):
            failures.append(
                "EndpointAuthTask::retire marks the retired cache directly; nothing "
                "may be marked before the lock, or a task reports itself retired "
                "while a locked operation can still sign"
            )

    # The test-only rendezvous seam. It parks a thread *inside* the exchange
    # critical section, which is precisely what production must never be able to
    # do, so every part of it is required to carry a `cfg(test)` gate. No probe
    # can see this: the seam is invisible from outside the crate either way.
    for item, pattern in (
        ("the LifecycleTrap enum", r"enum LifecycleTrap\b"),
        ("the LifecycleBarrier struct", r"struct LifecycleBarrier\b"),
        ("the EndpointAuthTask barrier field", r"^\s*barrier:\s*std::sync::OnceLock"),
        ("EndpointAuthTask::trap", r"fn trap\s*\(&self,\s*point:\s*LifecycleTrap"),
        ("EndpointAuthTask::arm_barrier", r"fn arm_barrier\b"),
    ):
        if not cfg_test_gated(task_source, pattern, "#[cfg(test)]"):
            failures.append(
                f"{item} is not immediately preceded by `#[cfg(test)]` in "
                "endpoint_auth/task.rs; the lifecycle rendezvous can hold a thread "
                "inside the exchange critical section and must not exist in a "
                "production build"
            )

    return failures


def rpc_binding_failures(engine_source: str) -> list[str]:
    """Arc 04F2: a request id is a routing key, not an authority.

    Reconciliation, recorded here on purpose: `PendingEntry` is deliberately
    left `pub`, exactly as downstream already had it, and this guard does NOT
    require it to be narrowed. Naming that type gets a caller no closer to an
    entry. The authority boundary is the `pending` map being private together
    with the three bound operations that are the only way to reach it, so that
    is what is guarded and nothing more. Narrowing `PendingEntry` would have
    been public API removal that bought no boundary.
    """

    failures: list[str] = []
    rpc_source = (CORE / "src" / "rpc.rs").read_text(encoding="utf-8")

    # The boundary itself. A `pub(crate)` field would let the engine's inbound
    # arms look an entry up by request id alone, which is the whole escape.
    if not re.search(r"^\s{4}pending: DashMap<String, PendingOp>,", rpc_source, re.MULTILINE):
        failures.append(
            "RpcInner::pending must stay a private `DashMap<String, PendingOp>`; any "
            "visibility qualifier on it re-opens settling an operation by request id "
            "alone, which is the authority the device binding exists to remove"
        )
    if not re.search(r"^struct PendingOp \{", rpc_source, re.MULTILINE):
        failures.append(
            "PendingOp must stay a private struct in rpc.rs; it is the record that "
            "carries the binding, and a nameable one invites construction elsewhere"
        )
    for field in ("expect_from", "effect"):
        if not re.search(rf"^\s{{4}}{field}:", rpc_source, re.MULTILINE):
            failures.append(
                f"PendingOp no longer carries `{field}`; the binding needs both the "
                "canonical device and the effect whose class it is checked against"
            )

    # Both conjuncts. A wrong source with the right class and a right source
    # with the wrong class are equally not this operation's response, and
    # dropping either half silently re-opens exactly one of the two attacks.
    if not re.search(
        r"self\.expect_from\s*==\s*from\s*&&\s*self\.effect\.class\(\)\s*==\s*class",
        rpc_source,
    ):
        failures.append(
            "PendingOp::accepts no longer requires both the bound device and the "
            "response class; dropping the source half lets a foreign peer settle "
            "another peer's call, and dropping the class half lets a single "
            "response end a stream"
        )
    # Class derived from the variant, never stored beside it: a second field
    # could disagree with the effect it describes and strand the call.
    if not re.search(
        r"fn class\(&self\) -> PendingClass \{\s*match self \{", rpc_source
    ):
        failures.append(
            "PendingEntry::class must derive the class by matching its own variant; "
            "a stored class is a second source of truth that can disagree with the "
            "effect it describes"
        )

    # Collision-safe insertion. Overwriting an occupied id strands the previous
    # caller on a oneshot that can never resolve and hands its reply elsewhere.
    claim_body = fn_body(rpc_source, "fn claim_request_id")
    if claim_body is None:
        failures.append("RpcInner::claim_request_id is missing from rpc.rs")
    else:
        if "self.pending.entry(" not in claim_body:
            failures.append(
                "claim_request_id no longer uses the entry API; the occupancy test "
                "and the insert must be one step or a concurrent call can take the "
                "id between them"
            )
        if not re.search(r"Entry::Occupied\(_\)\s*=>\s*Err\(effect\)", claim_body):
            failures.append(
                "claim_request_id no longer hands the effect back on an occupied id; "
                "anything other than refusing displaces the pending owner"
            )

    # The three bound operations each require the authenticated source.
    for operation in ("take_single_response", "stream_chunk_sender", "take_stream_end"):
        body = fn_body(rpc_source, f"pub(crate) fn {operation}")
        if body is None:
            failures.append(f"RpcInner::{operation} is missing from rpc.rs")
            continue
        if "from: &str" not in body:
            failures.append(
                f"RpcInner::{operation} no longer takes the authenticated source; a "
                "request id on its own must never reach a pending operation"
            )
        if ".accepts(" not in body:
            failures.append(
                f"RpcInner::{operation} no longer checks the binding with `accepts`; "
                "the predicate and the removal have to be the same shard-locked step "
                "or a refused frame can still mutate the rightful owner's operation"
            )

    # The engine side: the source is taken from the admitted owner token, never
    # from the frame. `_dispatch` is the pre-F2 defect in literal form — the
    # witness bound and then thrown away.
    for handler in ("on_rpc_response", "on_rpc_stream_chunk", "on_rpc_stream_end"):
        body = fn_body(engine_source, f"async fn {handler}(")
        if body is None:
            failures.append(f"engine/mod.rs::{handler} is missing")
            continue
        if "_dispatch" in body:
            failures.append(
                f"engine/mod.rs::{handler} binds the dispatch witness as `_dispatch`; "
                "discarding it is exactly the defect that made a request id an "
                "authority any authenticated peer could use"
            )
        if "dispatch.owner().device_id()" not in body:
            failures.append(
                f"engine/mod.rs::{handler} no longer settles against "
                "`dispatch.owner().device_id()`; the source must come from the "
                "admitted owner token and never from the frame"
            )
    # Scoped to `rpc.pending` on purpose. A bare `.pending` check would fire on
    # engine/governance.rs, which has an unrelated proposal list of that name.
    if re.search(r"\brpc\.pending\b", engine_source):
        failures.append(
            "engine/mod.rs reaches RpcInner::pending directly; every settle must go "
            "through one of the three bound operations"
        )

    return failures


def refused_open_failures(engine_source: str) -> list[str]:
    """Arc 04F3: a refused open closes the channel and drops the exact peer.

    Retiring alone left a live native channel and an addressable peer entry
    behind: nothing could be proved about that channel, yet it stayed allocated
    and reachable. The repair fences the connector first and only then removes
    the peer, and both halves are ordering claims a control can demonstrate on
    one path but only a count can pin against a future edit.
    """

    failures: list[str] = []
    webrtc_source = (CORE / "src" / "transport" / "webrtc.rs").read_text(
        encoding="utf-8"
    )

    arm = re.search(
        r"let Some\(binding\) = worker\.endpoint_auth_binding\(\)\.await else \{"
        r"(?P<body>.*?)\n            \};",
        engine_source,
        re.DOTALL,
    )
    if arm is None:
        failures.append(
            "the missing-binding branch of the DataChannelOpen arm is missing or "
            "reshaped in engine/mod.rs, so its fail-closed shape cannot be checked"
        )
    else:
        body = arm.group("body")
        if "worker.refuse_data_channel_open()" not in body:
            failures.append(
                "the missing-binding branch no longer calls "
                "`refuse_data_channel_open`; retiring alone leaves a live native "
                "channel that nothing can prove anything about, and there is no "
                "watchdog behind this — a close not started here never starts"
            )
        if not re.search(r"drop_peer_if_current\(state, &owner,", body):
            failures.append(
                "the missing-binding branch no longer drops the peer through "
                "`drop_peer_if_current(state, &owner, ..)`; keying on the owner "
                "token captured before the await is what leaves a replacement "
                "installed during it untouched"
            )
        # Ordering: fence the connector before touching the registry, so the
        # close is in flight and the claim is already in conservative retention.
        #
        # Compared over code lines only. The branch's own comment explains the
        # ordering and names `drop_peer_if_current` in prose several lines above
        # the call, so comparing raw offsets reads that mention as the call and
        # reports a correct branch as inverted.
        code = "\n".join(
            line for line in body.splitlines() if not line.strip().startswith("//")
        )
        if "worker.refuse_data_channel_open()" in code and "drop_peer_if_current" in code:
            if code.index("worker.refuse_data_channel_open()") > code.index(
                "drop_peer_if_current"
            ):
                failures.append(
                    "the missing-binding branch drops the peer before fencing the "
                    "connector; the close must already be in flight and the claim "
                    "already retained before the registry is touched"
                )
        if re.search(r"\bconfirm_data_channel_open\b", body):
            failures.append(
                "the missing-binding branch confirms the data channel itself; the "
                "refusal must not promote, and the one confirm belongs inside "
                "`refuse_data_channel_open`"
            )

    # `refuse_data_channel_open` is confirm-then-start: it takes the connected
    # claim so the close owner has something exact to retain, drops it, and
    # starts exactly one close synchronously.
    refuse_body = fn_body(webrtc_source, "pub(crate) fn refuse_data_channel_open")
    if refuse_body is None:
        failures.append(
            "WebRtcConnectorWorker::refuse_data_channel_open is missing from "
            "transport/webrtc.rs"
        )
    else:
        if "self.confirm_data_channel_open()" not in refuse_body:
            failures.append(
                "refuse_data_channel_open no longer confirms before starting; without "
                "taking the connected claim the close owner has no exact claim to "
                "retain conservatively"
            )
        if "self.close_owner.start()" not in refuse_body:
            failures.append(
                "refuse_data_channel_open no longer starts the close owner; the "
                "refusal must start exactly one close, synchronously, because "
                "nothing else will"
            )

    # `drop_peer_if_current` is exact-owner, never a device-id re-resolve.
    drop_body = fn_body(engine_source, "pub(crate) async fn drop_peer_if_current")
    if drop_body is None:
        failures.append("engine/mod.rs::drop_peer_if_current is missing")
    elif "remove_if_current(owner)" not in drop_body:
        failures.append(
            "drop_peer_if_current no longer removes through `remove_if_current(owner)`; "
            "resolving the peer any other way would let a refusal on one channel "
            "remove a replacement installed for the same device"
        )

    # The control-only native-close hold point. Like the F1 rendezvous it can
    # park real cleanup, so it must be unable to exist in a production build.
    cleanup_source = (CORE / "src" / "transport" / "webrtc" / "cleanup.rs").read_text(
        encoding="utf-8"
    )
    lab_gate = '#[cfg(all(test, feature = "transport-lab"))]'
    for item, source, pattern in (
        ("the NativeCloseGate struct", cleanup_source, r"struct NativeCloseGate\b"),
        (
            "WebRtcConnectorWorker::install_native_close_gate_for_test",
            webrtc_source,
            r"fn install_native_close_gate_for_test\b",
        ),
    ):
        if not cfg_test_gated(source, pattern, lab_gate):
            failures.append(
                f"{item} is not gated on `{lab_gate}`; the native-close hold point "
                "can park a real cleanup and must not exist in a production build"
            )

    return failures


def fn_body(source: str, signature: str) -> str | None:
    """Return the body of the item introduced by `signature`.

    Sliced from the signature to the next line whose closing brace sits at the
    signature's own indentation, so the whole item is covered however its
    arguments and inner blocks are wrapped.
    """

    start = source.find(signature)
    if start < 0:
        return None
    line_start = source.rfind("\n", 0, start) + 1
    indent = source[line_start:start]
    end = re.search(rf"^{indent}}}", source[start:], re.MULTILINE)
    return source[start : start + end.start()] if end is not None else source[start:]


def cfg_test_gated(source: str, pattern: str, gate: str) -> bool:
    """Whether every match of `pattern` carries `gate` in its own attribute run.

    Walks the lines immediately above each match backwards, stepping over doc
    comments, ordinary comments and other attributes, and stops at the first
    line that is none of those. The gate has to appear inside that run. Reading
    only the item's own attribute block is the point: an unrelated `#[cfg(test)]`
    elsewhere in the file must not be able to vouch for an ungated item.

    A pattern that matches nothing answers False. The item is required to exist,
    so a deletion or a rename is a failure rather than a silent pass.
    """

    matches = list(re.finditer(pattern, source, re.MULTILINE))
    if not matches:
        return False
    for match in matches:
        # Slice to the start of the match's OWN line. Slicing to the match
        # itself would leave a partial line (`    ` or `pub(crate) `) as the
        # last entry, which is neither a comment nor an attribute, so the walk
        # would stop on it and report every indented item as ungated.
        line_start = source.rfind("\n", 0, match.start()) + 1
        # Gated by its own attribute run, or — for a method — by the `impl`
        # block that encloses it. Both are real gates: an item inside a
        # `#[cfg(test)] impl` block is compiled out exactly as surely as one
        # carrying the attribute itself.
        if attribute_run_carries(source, line_start, gate):
            continue
        if enclosing_impl_carries(source, line_start, gate):
            continue
        return False
    return True


def attribute_run_carries(source: str, line_start: int, gate: str) -> bool:
    """Whether the attribute run directly above `line_start` contains `gate`.

    Steps over doc comments, ordinary comments, blank lines and other
    attributes, and stops at the first line that is none of those.
    """

    for line in reversed(source[:line_start].splitlines()):
        stripped = line.strip()
        if stripped == gate:
            return True
        if not stripped or stripped.startswith("//") or stripped.startswith("#["):
            continue
        return False
    return False


def enclosing_impl_carries(source: str, inner: int, gate: str) -> bool:
    """Whether the innermost `impl` block containing `inner` carries `gate`."""

    header = None
    for match in re.finditer(r"^impl [^\n]*\{$", source[:inner], re.MULTILINE):
        header = match
    if header is None:
        return False
    return attribute_run_carries(source, header.start(), gate)


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
