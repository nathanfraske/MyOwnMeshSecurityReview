#!/usr/bin/env python3
"""Verify that shipped artifacts do not contain the transport-lab seam."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import zipfile


REMOVED_V3_MARKERS = (
    b"NetworkStateBroadcast",
    b"RosterSummary",
    b"RosterRequest",
    b"RosterEntries",
    b"GovernanceSnapshot",
    b"GovernanceMfaEnroll",
    b"SelfStandDownReference",
    b"CanonicalDeviceId",
    b"LegacyAuthority",
    b"network_state::",
    b"governance_state",
)

FORBIDDEN_MARKERS = (
    b"MYOWNMESH_TRANSPORT_LAB_MFA_BARRIER",
    b"TransportLab",
    b"transport_lab",
    b"transport-lab",
    *REMOVED_V3_MARKERS,
)
SCAN_CHUNK_SIZE = 64 * 1024
DESKTOP_RELEASE_TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "macos-aarch64": "aarch64-apple-darwin",
    "macos-x86_64": "x86_64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
}
APPLIANCE_RELEASE_JOBS = {
    "daemon-riscv64": ("linux-riscv64", "riscv64gc-unknown-linux-musl"),
    "daemon-aarch64-musl": ("linux-aarch64-musl", "aarch64-unknown-linux-musl"),
}
MINISIGN_ARCHIVE_NAME = "minisign-0.11-linux.tar.gz"
MINISIGN_ARCHIVE_SHA256 = (
    "F0A0954413DF8531BEFED169E447A66DA6868D79052ED7E892E50A4291AF7AE0"
)
# SemVer 2.0 with the release ref's required `v` prefix. Numeric version and
# prerelease identifiers cannot have leading zeroes; build identifiers can.
RELEASE_TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
# Resolved from each official repository's existing major/version ref on
# 2026-10-23; action.yml was inspected at these commits (including the Rust
# installer's embedded 1.88.0 and its live-bootstrap fallback). Review updates
# at https://github.com/<repository>/commit/<sha>; never resolve tags in CI.
ACTION_COMMITS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "dtolnay/rust-toolchain": "360a4e93673de6630fac2478bc9e35244b01a759",
    "Swatinem/rust-cache": "d1527c8f67ef9af357290475d4af4b0fab8f12e0",
    "pnpm/action-setup": "b906affcce14559ad1aafd4ab0e942779e9f58b1",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "tauri-apps/tauri-action": "84b9d35b5fc46c1e45415bdb6144030364f7ebc5",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "softprops/action-gh-release": "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
}
# These are exact selection policies, not binary digest attestations. The
# hosted image, rustup/distribution infrastructure, Node/Python downloads,
# pnpm bootstrap, OS packages, caches and protected signer remain trust roots.
PYTHON_VERSION = "3.13.17"  # python/cpython v3.13.17, 64e080d38154391ff2d2caa1161c298bb7cd8f30
NODE_VERSION = "20.20.2"  # nodejs/node v20.20.2, 3626fea570e44896ad99aaf3bf6e59def5adede5
ZIG_ARCHIVE_URL = "https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz"
# Official x86_64-linux digest: https://ziglang.org/download/index.json, 0.13.0.
ZIG_ARCHIVE_SHA256 = "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"
CARGO_ZIGBUILD_REPOSITORY = "https://github.com/rust-cross/cargo-zigbuild"
# Official v0.20.1 commit; Cargo.toml declares Rust 1.74 and includes Cargo.lock.
CARGO_ZIGBUILD_COMMIT = "bbb57ac6a5eb90f53617a5c218fda03080599e4a"


def fail(message: str) -> None:
    raise SystemExit(f"release artifact check: {message}")


def scan_bytes(label: str, payload: bytes) -> None:
    scan_stream(label, io.BytesIO(payload))


def scan_stream(label: str, stream: object) -> None:
    """Scan a binary stream in bounded chunks, retaining marker overlap."""
    overlap = b""
    overlap_size = max(len(marker) for marker in FORBIDDEN_MARKERS) - 1
    while True:
        chunk = stream.read(SCAN_CHUNK_SIZE)
        if not chunk:
            return
        window = overlap + chunk
        found = [marker.decode("ascii") for marker in FORBIDDEN_MARKERS if marker in window]
        if found:
            fail(
                f"{label} contains transport-lab marker(s) or removed V3 marker(s): "
                f"{', '.join(found)}"
            )
        overlap = window[-overlap_size:]


def scan_file(path: pathlib.Path) -> None:
    if not path.is_file():
        fail(f"artifact does not exist: {path}")
    with path.open("rb") as stream:
        scan_stream(str(path), stream)


def verify_release_public_key(path: pathlib.Path, public_key: str) -> None:
    """Require a compiled daemon to carry the publication trust anchor."""
    if not public_key.strip():
        fail("release trust-anchor verification requires a non-empty public key")
    if not path.is_file():
        fail(f"artifact does not exist: {path}")
    marker = public_key.strip().encode("ascii", errors="strict")
    try:
        payload = path.read_bytes()
    except OSError as error:
        fail(f"cannot read release trust-anchor artifact {path}: {error}")
    if marker not in payload:
        fail(f"{path} does not embed the configured release public key")


def iter_regular_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Return every regular file below *root*, refusing ambiguous entries."""
    if root.is_symlink():
        fail(f"artifact tree root is an unsupported symlink: {root}")
    if not root.is_dir():
        fail(f"artifact tree does not exist or is not a directory: {root}")
    files: list[pathlib.Path] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            fail(f"cannot enumerate artifact tree {current}: {error}")
        for entry in entries:
            path = pathlib.Path(entry.path)
            if entry.is_symlink():
                fail(f"artifact tree contains an unsupported symlink: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                files.append(path)
            else:
                fail(f"artifact tree contains a non-regular entry: {path}")
    if not files:
        fail(f"artifact tree contains no regular files: {root}")
    return sorted(files)


def scan_tree(root: pathlib.Path) -> None:
    """Scan every regular file in an installer/bundle tree."""
    files = iter_regular_files(root)
    empty = [str(path) for path in files if path.stat().st_size == 0]
    if empty:
        fail("installer tree contains empty regular file(s): " + ", ".join(empty))
    for path in files:
        scan_file(path)


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(SCAN_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot read checksum payload {path}: {error}")
    return digest.hexdigest()


def verify_checksum_sidecars(root: pathlib.Path) -> None:
    """Validate every checksum sidecar against its sibling payload."""
    files = iter_regular_files(root)
    by_name: dict[str, pathlib.Path] = {}
    for path in files:
        if path.name in by_name:
            fail(f"checksum tree has duplicate basename: {path.name}")
        by_name[path.name] = path

    for sidecar in files:
        if not sidecar.name.endswith(".sha256"):
            continue
        payload_name = sidecar.name[: -len(".sha256")]
        payload = by_name.get(payload_name)
        if payload is None:
            fail(
                f"checksum sidecar {sidecar.name} has no matching payload "
                f"{payload_name}"
            )
        try:
            lines = sidecar.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            fail(f"cannot read checksum sidecar {sidecar}: {error}")
        if len(lines) != 1 or not lines[0].strip():
            fail(f"checksum sidecar {sidecar.name} must contain exactly one record")
        match = re.fullmatch(r"\s*([0-9a-fA-F]{64})\s+(\*?)(.+?)\s*", lines[0])
        if match is None or match.group(3) != payload_name:
            fail(f"checksum sidecar {sidecar.name} names the wrong payload")
        actual = _sha256_file(payload)
        if match.group(1).lower() != actual:
            fail(
                f"checksum mismatch for {payload_name}: "
                f"declared {match.group(1).lower()}, actual {actual}"
            )


def required_signature_targets(root: pathlib.Path) -> list[pathlib.Path]:
    """Return release files that must carry detached signature provenance."""
    files = iter_regular_files(root)
    targets = [
        path
        for path in files
        if not path.name.endswith((".minisig", ".sha256"))
    ]
    if not targets:
        fail(f"signature tree contains no release payloads: {root}")
    expected_signatures = {
        path.with_name(path.name + ".minisig") for path in targets
    }
    orphaned = sorted(
        path.name
        for path in files
        if path.name.endswith(".minisig") and path not in expected_signatures
    )
    if orphaned:
        fail(
            "orphan signature sidecar(s) have no release payload: "
            + ", ".join(orphaned)
        )
    missing = [
        path.name
        for path in targets
        if not path.with_name(path.name + ".minisig").is_file()
    ]
    if missing:
        fail(
            "signature provenance missing for release payload(s): "
            + ", ".join(sorted(missing))
        )
    return targets


def write_asset_manifest(roots: list[pathlib.Path], output: pathlib.Path) -> None:
    """Write the build-owned exact release basename/digest allowlist."""
    assets: dict[str, str] = {}
    for root in roots:
        for path in iter_regular_files(root):
            name = path.name
            if name.endswith(".minisig"):
                continue
            if name in assets:
                fail(f"asset manifest has duplicate release basename: {name}")
            assets[name] = _sha256_file(path)
    if not assets:
        fail("asset manifest contains no release payloads")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"assets": dict(sorted(assets.items()))}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_asset_allowlist(root: pathlib.Path) -> dict[str, str]:
    """Load and validate all source/build-owned JSON allowlists below *root*."""
    if not root.is_dir() or root.is_symlink():
        fail(f"asset allowlist directory does not exist: {root}")
    paths = sorted(root.glob("*.json"))
    if not paths:
        fail(f"asset allowlist directory contains no manifests: {root}")
    assets: dict[str, str] = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            fail(f"asset allowlist contains a non-regular manifest: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"invalid asset allowlist {path}: {error}")
        entries = document.get("assets") if isinstance(document, dict) else None
        if not isinstance(entries, dict) or not entries:
            fail(f"asset allowlist {path} has no assets object")
        for name, digest in entries.items():
            if (
                not isinstance(name, str)
                or pathlib.PurePath(name).name != name
                or name in ("", ".", "..")
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None
            ):
                fail(f"asset allowlist {path} contains an invalid asset record")
            old = assets.get(name)
            if old is not None and old.lower() != digest.lower():
                fail(f"asset allowlist has conflicting digest for {name}")
            assets[name] = digest.lower()
    return assets


def verify_asset_allowlist(root: pathlib.Path, allowlist: pathlib.Path) -> dict[str, str]:
    expected = load_asset_allowlist(allowlist)
    actual = {
        path.name: _sha256_file(path)
        for path in iter_regular_files(root)
        if not path.name.endswith(".minisig")
    }
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    mismatched = sorted(
        name for name in set(expected) & set(actual) if expected[name] != actual[name]
    )
    if missing or unexpected or mismatched:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        if mismatched:
            details.append("digest mismatch " + ", ".join(mismatched))
        fail("release asset allowlist mismatch: " + "; ".join(details))
    return expected


def _gh_json(repository: str, endpoint: str) -> dict | None:
    """Read one GitHub API object, distinguishing a missing object from failure."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/{endpoint}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if "404" in detail or "Not Found" in detail:
            return None
        fail(f"GitHub preflight query failed for {endpoint}: {detail}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"GitHub preflight returned invalid JSON for {endpoint}: {error}")
    if not isinstance(value, dict):
        fail(f"GitHub preflight returned a non-object for {endpoint}")
    return value


def _gh_release_create(repository: str, tag: str, commit: str) -> None:
    result = subprocess.run(
        [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repository,
            "--target",
            commit,
            "--draft",
            "--verify-tag",
            "--title",
            tag,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail(f"could not create the exact draft release {tag}: {detail}")


def _resolve_tag_commit(repository: str, tag: str, tag_ref: dict) -> str:
    """Resolve a lightweight or annotated tag to its exact commit SHA."""
    tag_object = tag_ref.get("object")
    seen: set[str] = set()
    while isinstance(tag_object, dict) and tag_object.get("type") == "tag":
        tag_sha = tag_object.get("sha")
        if not isinstance(tag_sha, str) or not tag_sha or tag_sha in seen:
            fail(f"release tag {tag} has an invalid or cyclic annotated target")
        seen.add(tag_sha)
        annotated = _gh_json(repository, f"git/tags/{tag_sha}")
        if annotated is None:
            fail(f"release tag {tag} has an unreadable annotated target {tag_sha}")
        tag_object = annotated.get("object")
    if not isinstance(tag_object, dict) or tag_object.get("type") != "commit":
        fail(f"release tag {tag} does not resolve to a commit")
    sha = tag_object.get("sha")
    if not isinstance(sha, str) or not sha:
        fail(f"release tag {tag} has no commit SHA")
    return sha


def validate_release_tag(tag: str) -> None:
    """Reject shell syntax, ref/path syntax and noncanonical release versions."""
    if RELEASE_TAG.fullmatch(tag) is None:
        fail("release tag must be vMAJOR.MINOR.PATCH with optional SemVer prerelease/build identifiers")


def preflight_release(tag: str, commit: str, repository: str) -> None:
    """Validate an existing exact release ref before reading or creating a draft."""
    validate_release_tag(tag)
    if not tag or not commit or not repository:
        fail("release preflight requires non-empty tag, commit, and repository")

    tag_ref = _gh_json(repository, f"git/ref/tags/{tag}")
    if tag_ref is None:
        fail(f"release tag {tag} must already exist before release work")
    resolved_commit = _resolve_tag_commit(repository, tag, tag_ref)
    if resolved_commit != commit:
        fail(
            f"release tag {tag} targets {resolved_commit}, "
            f"not the requested commit {commit}"
        )

    release = _gh_json(repository, f"releases/tags/{tag}")
    if release is not None:
        if release.get("draft") is not True:
            fail(f"release tag {tag} is already public; refusing to overwrite it")
        if release.get("target_commitish") != commit:
            fail(
                f"draft release {tag} targets {release.get('target_commitish')}, "
                f"not the requested commit {commit}"
            )
        return

    _gh_release_create(repository, tag, commit)
    created = _gh_json(repository, f"releases/tags/{tag}")
    if created is None or created.get("draft") is not True:
        fail(f"release preflight did not establish a draft for {tag}")
    if created.get("target_commitish") != commit:
        fail(
            f"new draft release {tag} targets {created.get('target_commitish')}, "
            f"not the requested commit {commit}"
        )


def verify_signature_tree(
    root: pathlib.Path,
    public_key: str,
    minisign_binary: str = "minisign",
    asset_allowlist: pathlib.Path | None = None,
) -> None:
    """Verify every release payload has a valid detached minisign signature."""
    if not public_key.strip():
        fail("signature provenance requires a non-empty minisign public key")
    verify_checksum_sidecars(root)
    if asset_allowlist is not None:
        verify_asset_allowlist(root, asset_allowlist)
    for path in required_signature_targets(root):
        signature = path.with_name(path.name + ".minisig")
        try:
            result = subprocess.run(
                [
                    minisign_binary,
                    "-Vm",
                    str(path),
                    "-P",
                    public_key,
                    "-x",
                    str(signature),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            fail(f"cannot verify release signature for {path}: {error}")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            fail(f"invalid release signature for {path}: {detail}")


def verify_remote_release_assets(
    root: pathlib.Path,
    repository: str,
    tag: str,
    public_key: str,
    asset_allowlist: pathlib.Path | None = None,
    remote_tree: pathlib.Path | None = None,
) -> None:
    """Recheck the draft's complete payload/signature set after upload.

    When *remote_tree* is supplied, it must be a fresh download of the
    release.  Its payload bytes are checked against the build-owned digest
    allowlist and its detached signatures are verified independently, so
    release metadata cannot stand in for the bytes that will be published.
    """
    if not repository or not tag:
        fail("remote asset verification requires a repository and tag")
    expected_payloads = verify_asset_allowlist(root, asset_allowlist) if asset_allowlist else None
    verify_signature_tree(root, public_key, asset_allowlist=asset_allowlist)
    release = _gh_json(repository, f"releases/tags/{tag}?per_page=100")
    if release is None:
        fail(f"release {tag} disappeared before publication")
    if release.get("draft") is not True:
        fail(f"release {tag} is no longer a draft before publication")
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail(f"release {tag} returned no typed asset list")
    remote_names: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail(f"release {tag} returned an invalid asset record")
        if asset.get("state") != "uploaded":
            fail(f"release {tag} asset {asset['name']} is not uploaded")
        remote_names.append(asset["name"])
    if len(remote_names) != len(set(remote_names)):
        fail(f"release {tag} returned duplicate asset names")
    expected_names = (
        list(expected_payloads)
        + [f"{name}.minisig" for name in expected_payloads if not name.endswith(".sha256")]
        if expected_payloads is not None
        else [path.name for path in iter_regular_files(root)]
    )
    if set(remote_names) != set(expected_names):
        missing = sorted(set(expected_names) - set(remote_names))
        unexpected = sorted(set(remote_names) - set(expected_names))
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        fail(f"release {tag} asset/signature set mismatch: {'; '.join(details)}")
    if remote_tree is not None:
        if expected_payloads is None:
            fail("remote asset verification requires a build-owned asset allowlist")
        remote_files = {path.name for path in iter_regular_files(remote_tree)}
        if remote_files != set(expected_names):
            missing = sorted(set(expected_names) - remote_files)
            unexpected = sorted(remote_files - set(expected_names))
            details = []
            if missing:
                details.append("download missing " + ", ".join(missing))
            if unexpected:
                details.append("download unexpected " + ", ".join(unexpected))
            fail("downloaded release asset set mismatch: " + "; ".join(details))
        verify_asset_allowlist(remote_tree, asset_allowlist)
        verify_signature_tree(
            remote_tree,
            public_key,
            asset_allowlist=asset_allowlist,
        )


def verify_minisign_installation(path: pathlib.Path, sign_job: str) -> None:
    """Require an immutable, verified signer before any signing key is exposed."""
    archive_declaration = f'minisign_archive="{MINISIGN_ARCHIVE_NAME}"'
    if archive_declaration not in sign_job:
        fail(f"sign job does not pin the minisign archive name: {path}")
    if (
        "https://github.com/jedisct1/minisign/releases/download/0.11/"
        "$minisign_archive"
    ) not in sign_job:
        fail(f"sign job does not pin the minisign 0.11 download URL: {path}")
    if MINISIGN_ARCHIVE_SHA256 not in sign_job:
        fail(f"sign job does not pin the minisign archive digest: {path}")
    digest_check = (
        'printf \'%s  %s\\n\' "$minisign_archive_sha256" "$minisign_archive" '
        "| sha256sum --check"
    )
    if digest_check not in sign_job:
        fail(f"sign job does not verify the minisign archive digest: {path}")

    install_start = sign_job.find("      - name: Install minisign\n")
    gate_start = sign_job.find("      - name: Gate on signing key\n")
    digest_start = sign_job.find(digest_check, install_start)
    extract_start = sign_job.find('          tar -xzf "$minisign_archive"', install_start)
    binary_check = sign_job.find("          test -x minisign-linux/x86_64/minisign", install_start)
    install_command = sign_job.find(
        "          sudo install -m 0755 minisign-linux/x86_64/minisign /usr/local/bin/minisign",
        install_start,
    )
    if install_start < 0 or digest_start < 0 or extract_start < 0:
        fail(f"sign job has no complete minisign installation verification: {path}")
    if digest_start >= extract_start:
        fail(f"sign job verifies the minisign archive after extraction: {path}")
    if binary_check < 0 or install_command < 0 or binary_check >= install_command:
        fail(f"sign job does not verify the minisign executable before install: {path}")
    if gate_start < 0 or gate_start <= install_command:
        fail(f"signing keys are exposed before signer verification: {path}")
    pre_gate = sign_job[:gate_start]
    for key_name in ("MINISIGN_SECRET_KEY", "MINISIGN_PUBLIC_KEY", "MYOWNMESH_RELEASE_PUBKEY"):
        if key_name in pre_gate:
            fail(f"signing key {key_name} is exposed before signer verification: {path}")


def zip_member_is_regular_file(member: zipfile.ZipInfo) -> bool:
    if member.is_dir():
        return False
    if member.create_system == 3:
        mode = (member.external_attr >> 16) & 0xFFFF
        if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            return False
    return True


def scan_archive(path: pathlib.Path, expected_members: list[str]) -> None:
    if not path.is_file():
        fail(f"archive does not exist: {path}")
    if not expected_members:
        fail(f"archive scan requires at least one expected member: {path}")
    if len(set(expected_members)) != len(expected_members):
        fail(f"{path} has duplicate expected member arguments")
    expected = set(expected_members)
    entry_counts = {name: 0 for name in expected}
    regular_counts = {name: 0 for name in expected}
    empty_members: set[str] = set()
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.filename in expected:
                    entry_counts[member.filename] += 1
                    if zip_member_is_regular_file(member):
                        regular_counts[member.filename] += 1
                        if member.file_size == 0:
                            empty_members.add(member.filename)
                if not zip_member_is_regular_file(member):
                    continue
                with archive.open(member) as stream:
                    scan_stream(f"{path}!{member.filename}", stream)
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.name in expected:
                    entry_counts[member.name] += 1
                if member.isfile():
                    if member.name in expected:
                        regular_counts[member.name] += 1
                        if member.size == 0:
                            empty_members.add(member.name)
                    stream = archive.extractfile(member)
                    if stream is not None:
                        with stream:
                            scan_stream(f"{path}!{member.name}", stream)
    else:
        fail(f"unsupported archive type: {path}")
    duplicates = sorted(name for name, count in entry_counts.items() if count > 1)
    if duplicates:
        fail(f"{path} has duplicate expected member entr{'y' if len(duplicates) == 1 else 'ies'}: {', '.join(duplicates)}")
    nonregular = sorted(name for name in expected if regular_counts[name] != 1)
    if nonregular:
        fail(f"{path} expected member(s) are not exactly one regular file: {', '.join(nonregular)}")
    if empty_members:
        fail(f"{path} expected member(s) are empty: {', '.join(sorted(empty_members))}")
    missing = sorted(name for name in expected if entry_counts[name] == 0)
    if missing:
        fail(f"{path} is missing expected member(s): {', '.join(missing)}")


def verify_tag_shell_boundary(path: pathlib.Path, text: str) -> None:
    """Keep tag expressions in workflow data, never in generated shell source."""
    run_indent: int | None = None
    script_lines: list[str] = []
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip())
        if line.strip() and run_indent is not None and indent <= run_indent:
            run_indent = None
        run = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
        if run is not None:
            run_indent = len(run.group(1)) + (2 if line.lstrip().startswith("- ") else 0)
        if run is None and run_indent is None:
            continue
        script_lines.append(line)
    for expression in re.findall(r"\$\{\{(.*?)\}\}", "\n".join(script_lines), re.DOTALL):
        if re.search(
            r"\binputs\b|\bgithub\s*(?:\.\s*ref(?:_name)?\b|\[\s*['\"]ref(?:_name)?['\"]\s*\])"
            r"|\benv\s*(?:\.\s*TAG\b|\[\s*['\"]TAG['\"]\s*\])",
            expression,
        ):
            fail(f"release workflow interpolates tag data into shell source: {path}")


def reviewed_action(repository: str) -> str:
    return f"{repository}@{ACTION_COMMITS[repository]}"


def workflow_invocations(
    path: pathlib.Path, text: str,
) -> tuple[list[tuple[int, str, str]], set[int]]:
    """Inventory executable YAML keys in the supported block-mapping syntax.

    This is deliberately not a general YAML parser. Reject alternate mappings,
    aliases and flow objects rather than silently losing invocation coverage.
    Literal/folded scalar contents (shell scripts, upload paths) are data.
    """
    invocations: list[tuple[int, str, str]] = []
    step_starts: set[int] = set()
    scalar_indent: int | None = None
    inside_steps = False
    offset = 0
    for line in text.splitlines(keepends=True):
        current_offset = offset
        offset += len(line)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent_text = line[:len(line) - len(line.lstrip())]
        indent = len(indent_text)
        if scalar_indent is not None and indent > scalar_indent:
            continue
        scalar_indent = None
        if indent <= 4:
            inside_steps = False
        if "\t" in indent_text:
            fail(f"unsupported YAML indentation in provenance policy: {path}")
        # Expressions are scalar values; their braces are not YAML flow maps.
        metadata = re.sub(r"\$\{\{.*?\}\}", "expression", stripped)
        if (
            metadata.startswith(("---", "...", "%", "? ", ": ", "<<:"))
            or re.match(r"^(?:-\s+)?[\"']", metadata)
            or re.search(r"(?:^|[\s:,\[{])(?:[&*][A-Za-z_]|!!|!<)", metadata)
        ):
            fail(f"unsupported YAML mapping/alias in provenance policy: {path}")
        matrix_row = False
        if "{" in metadata or "}" in metadata:
            # The only current flow mappings are fixed platform matrix rows.
            if re.fullmatch(
                r"-\s*\{\s*name:\s*[A-Za-z0-9_-]+,\s*os:\s*[A-Za-z0-9_.-]+"
                r"(?:,\s*target:\s*[A-Za-z0-9_-]+)?\s*\}\s*(?:#.*)?",
                metadata,
            ) is None:
                fail(f"unsupported YAML flow mapping in provenance policy: {path}")
            matrix_row = True
        field = re.match(r"^( *)(- +)?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*:[ \t]*(.*)$", line.rstrip())
        if field is None:
            if not matrix_row and re.fullmatch(r"-\s+[A-Za-z0-9_.-]+\s*(?:#.*)?", metadata) is None:
                fail(f"unsupported YAML syntax in provenance policy: {path}")
            continue
        key_indent = len(field.group(1)) + len(field.group(2) or "")
        key, value = field.group(3), field.group(4)
        if key in ("jobs", "steps") and value and not value.startswith("#"):
            fail(f"unsupported YAML jobs/steps value in provenance policy: {path}")
        if key == "steps":
            if key_indent != 4:
                fail(f"unsupported YAML steps location in provenance policy: {path}")
            inside_steps = True
        if inside_steps and indent == 6 and field.group(2):
            step_starts.add(current_offset)
        if key in ("uses", "run"):
            if key_indent != 8 or not inside_steps:
                fail(f"uncovered YAML {key} invocation in provenance policy: {path}")
            invocations.append((current_offset, key, value))
        if re.fullmatch(r"[|>][-+]?\s*(?:#.*)?", value):
            scalar_indent = key_indent
    return invocations, step_starts


def workflow_step_fields(
    path: pathlib.Path, step: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """Read active step/with fields, never comments or block-scalar contents.

    Invocation coverage has already constrained the YAML syntax. Keep values
    raw so policy checks can require complete literals, not substring decoys.
    Duplicate mappings are ambiguous and must not select a policy value.
    """
    fields: dict[str, str] = {}
    inputs: dict[str, str] = {}
    inside_with = False
    scalar_indent: int | None = None
    for line in step.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if scalar_indent is not None and indent > scalar_indent:
            continue
        scalar_indent = None
        field = re.match(r"^( *)(- +)?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*:[ \t]*(.*)$", line)
        if field is None:
            continue
        key_indent = len(field.group(1)) + len(field.group(2) or "")
        key, value = field.group(3), field.group(4)
        mapping: dict[str, str] | None = None
        if key_indent == 8:
            mapping = fields
            inside_with = key == "with" and (not value or value.startswith("#"))
        elif key_indent == 10 and inside_with:
            mapping = inputs
        if mapping is not None:
            if key in mapping:
                fail(f"duplicate YAML policy field {key}: {path}")
            mapping[key] = value
        if re.fullmatch(r"[|>][-+]?\s*(?:#.*)?", value):
            scalar_indent = key_indent
    return fields, inputs


def workflow_literal_matches(value: str, expected: str) -> bool:
    """Accept only the complete plain/quoted literal, plus a YAML comment."""
    literal = re.escape(expected)
    return re.fullmatch(
        rf"(?:{literal}|'{literal}'|\"{literal}\")(?:[ \t]+#.*)?[ \t]*", value,
    ) is not None


def verify_workflow_provenance(path: pathlib.Path) -> None:
    """Check reviewed source pins; this does not attest builders or isolate keys."""
    text = path.read_text(encoding="utf-8")
    invocations, step_starts = workflow_invocations(path, text)
    matches = [
        match for match in re.finditer(
            r"(?ms)^      - .*?(?=^      - |^  [A-Za-z0-9_-]+:|\Z)", text
        ) if match.start() in step_starts
    ]
    if not matches or not any(key == "uses" for _, key, _ in invocations):
        fail(f"workflow provenance requires covered step invocations: {path}")
    covered: set[int] = set()
    steps = [match.group() for match in matches]
    parsed_steps: list[tuple[dict[str, str], dict[str, str]]] = []
    for index, (match, step) in enumerate(zip(matches, steps)):
        declarations = [item for item in invocations if match.start() <= item[0] < match.end()]
        if len(declarations) != 1:
            fail(f"uncovered or multiple YAML invocations in step: {path}")
        parsed_steps.append(workflow_step_fields(path, step))
        position, kind, value = declarations[0]
        covered.add(position)
        if kind == "uses":
            literal = re.fullmatch(r"([^\s#'\"]+)(?:\s+#.*)?", value)
            if literal is None:
                fail(f"unsupported YAML Action reference in provenance policy: {path}")
            reference = literal.group(1)
            repository, separator, commit = reference.partition("@")
            if not separator or ACTION_COMMITS.get(repository) != commit:
                fail(f"unreviewed or mutable Action reference {reference}: {path}")
            _, inputs = parsed_steps[index]
            if repository == "dtolnay/rust-toolchain":
                guard = parsed_steps[index - 1][0] if index > 0 else {}
                # The command must run unconditionally and its failure must
                # stop the installer, not merely exist in the YAML.
                if (
                    "if" in guard or "continue-on-error" in guard
                    or re.fullmatch(
                        r"command -v rustup(?:[ \t]+#.*)?[ \t]*",
                        guard.get("run", ""),
                    ) is None
                ):
                    fail(f"Rust installer lacks preinstalled-rustup gate: {path}")
            if repository == "actions/setup-python":
                if not workflow_literal_matches(inputs.get("python-version", ""), PYTHON_VERSION):
                    fail(f"Python selection is not pinned to {PYTHON_VERSION}: {path}")
            if repository == "actions/setup-node":
                if not workflow_literal_matches(inputs.get("node-version", ""), NODE_VERSION):
                    fail(f"Node selection is not pinned to {NODE_VERSION}: {path}")
            if repository == "Swatinem/rust-cache" and not workflow_literal_matches(
                inputs.get("cache-bin", ""), "false",
            ):
                fail(f"Rust cache must not restore executable tools: {path}")
            if repository == "tauri-apps/tauri-action":
                if re.search(
                    r"(?m)^          args: --target \$\{\{ matrix\.platform\.target \}\} -- --locked[ \t]*$",
                    step,
                ) is None:
                    fail(f"Tauri build must forward Cargo --locked after --: {path}")

        # Bash removes the escaped newline, not surrounding whitespace. Keep
        # indentation and quoted bytes intact; command patterns below permit
        # horizontal whitespace only between the fixed, reviewed arguments.
        logical = step.replace("\\\n", "")
        downloads = [
            line for line in logical.splitlines()
            if not line.lstrip().startswith("#")
            and re.search(r"\b(?:curl|wget|pip\S* install|cargo install)\b", line)
        ]
        if not downloads:
            continue
        if step.startswith("      - name: Install minisign\n"):
            # The release-specific verifier checks this archive and its order.
            continue
        if not step.startswith("      - name: Install Zig + cargo-zigbuild\n"):
            fail(f"unreviewed online tool installer in workflow: {path}")
        digest_check = (
            f'printf \'%s  %s\\n\' "{ZIG_ARCHIVE_SHA256}" "$zig_archive" '
            "| sha256sum --check"
        )
        extract = 'tar -xJf "$zig_archive" -C "$cross_root"'
        required = (
            'set -euo pipefail',
            'cross_root="$(mktemp -d "$RUNNER_TEMP/myownmesh-cross-tools.XXXXXX")"',
            digest_check,
            extract,
            'printf \'%s\\n\' "$cross_root/zig-linux-x86_64-0.13.0" '
            '"$cross_root/cargo-zigbuild/bin" >> "$GITHUB_PATH"',
        )
        curl_command = (
            r'(?m)^[ \t]*curl[ \t]+-fsSL[ \t]+-o[ \t]+"\$zig_archive"[ \t]+'
            + re.escape(f'"{ZIG_ARCHIVE_URL}"') + r'[ \t]*$'
        )
        cargo_command = (
            r'(?m)^[ \t]*cargo[ \t]+install[ \t]+--git[ \t]+'
            + re.escape(CARGO_ZIGBUILD_REPOSITORY)
            + r'[ \t]+--rev[ \t]+' + re.escape(CARGO_ZIGBUILD_COMMIT)
            + r'[ \t]+--locked[ \t]+--root[ \t]+"\$cross_root/cargo-zigbuild"'
            + r'[ \t]+cargo-zigbuild[ \t]*$'
        )
        if (
            any(fragment not in logical for fragment in required)
            or re.search(curl_command, logical) is None
            or re.search(cargo_command, logical) is None
        ):
            fail(f"cross-tool installer lacks reviewed digest/revision custody: {path}")
        if logical.index(digest_check) >= logical.index(extract):
            fail(f"Zig archive must be digest-checked before extraction: {path}")
        if len(downloads) != 2:
            fail(f"cross-tool installer contains an unreviewed download: {path}")
    if covered != {position for position, _, _ in invocations}:
        fail(f"uncovered YAML invocation in provenance policy: {path}")


def verify_workflow(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    verify_tag_shell_boundary(path, text)
    if not re.search(r"(?ms)^concurrency:\s*\n\s+group:\s*release-", text):
        fail(f"release workflow lacks per-tag concurrency fencing: {path}")
    lines = text.splitlines()
    jobs: dict[str, str] = {}
    current_job: str | None = None
    for line in lines:
        match = re.match(r"^  ([A-Za-z0-9_-]+):$", line)
        if match:
            current_job = match.group(1)
            jobs[current_job] = ""
        elif current_job is not None:
            jobs[current_job] += line + "\n"

    def job_needs(body: str) -> set[str]:
        lines = body.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^    needs:\s*(.*)$", line)
            if match is None:
                continue
            value = match.group(1).strip()
            if value:
                if value.startswith("[") and value.endswith("]"):
                    return {
                        item.strip().strip("'\"")
                        for item in value[1:-1].split(",")
                        if item.strip()
                    }
                return {value.strip("'\"")}
            dependencies: set[str] = set()
            for dependency_line in lines[index + 1 :]:
                item = re.match(r"^      -\s*[\"']?([A-Za-z0-9_-]+)[\"']?\s*$", dependency_line)
                if item is not None:
                    dependencies.add(item.group(1))
                    continue
                if dependency_line.strip() and not dependency_line.startswith("      "):
                    break
            return dependencies
        return set()

    dependencies = {job_name: job_needs(body) for job_name, body in jobs.items()}
    unknown_dependencies = sorted(
        f"{job_name}->{dependency}"
        for job_name, needs in dependencies.items()
        for dependency in needs
        if dependency not in jobs
    )
    if unknown_dependencies:
        fail(
            "release workflow has unknown job dependency(ies): "
            + ", ".join(unknown_dependencies)
        )

    visit_state: dict[str, int] = {}

    def visit(job_name: str) -> None:
        state = visit_state.get(job_name, 0)
        if state == 1:
            fail(f"release workflow has a dependency cycle at {job_name}")
        if state == 2:
            return
        visit_state[job_name] = 1
        for dependency in dependencies.get(job_name, ()):
            visit(dependency)
        visit_state[job_name] = 2

    for job_name in jobs:
        visit(job_name)

    sign_job = jobs.get("sign", "")
    if not sign_job:
        fail(f"release workflow has no signer job: {path}")
    verify_minisign_installation(path, sign_job)

    def depends_on(job_name: str, prerequisite: str) -> bool:
        pending = list(dependencies.get(job_name, ()))
        visited: set[str] = set()
        while pending:
            dependency = pending.pop()
            if dependency == prerequisite:
                return True
            if dependency in visited:
                continue
            visited.add(dependency)
            pending.extend(dependencies.get(dependency, ()))
        return False

    preflight = jobs.get("prepare-release", "")
    if not preflight:
        fail(f"release workflow has no source-owned prepare-release job: {path}")
    if "--ci-workflow .github/workflows/ci.yml" not in jobs.get("release-gates", ""):
        fail(f"release gates do not verify CI provenance policy: {path}")
    for required in (
        "--preflight-release",
        "--tag",
        'TAG: ${{ inputs.tag || github.ref_name }}',
        '--tag "$TAG"',
        "--commit",
        "$GITHUB_SHA",
        "--repository",
        "$GITHUB_REPOSITORY",
    ):
        if required not in preflight:
            fail(f"prepare-release does not verify {required}: {path}")
    for platform, target in DESKTOP_RELEASE_TARGETS.items():
        row = re.search(
            rf"-\s*\{{\s*name:\s*{re.escape(platform)},"
            rf"\s*os:\s*[^,]+,\s*target:\s*{re.escape(target)}\s*\}}",
            text,
        )
        if row is None:
            fail(
                f"release workflow is missing required release target "
                f"{platform} ({target})"
            )
    for job_name, (platform, target) in APPLIANCE_RELEASE_JOBS.items():
        body = jobs.get(job_name, "")
        if f"({platform})" not in body or target not in body:
            fail(
                f"release workflow is missing required release target "
                f"{platform} ({target})"
            )
    if "--tree" not in text or "release/bundle" not in text:
        fail(f"release workflow does not scan every Tauri installer tree: {path}")
    if "--archive" not in text or "--member" not in text:
        fail(f"release workflow does not verify packaged archive members: {path}")
    if text.count("--preflight-release") < 2:
        fail(f"release workflow does not re-resolve the exact tag before publish: {path}")
    if "--asset-allowlist" not in text or "--write-asset-manifest" not in text:
        fail(f"release workflow lacks source-owned release asset allowlists: {path}")
    if reviewed_action("actions/download-artifact") not in text:
        fail(f"release workflow does not retrieve build-owned asset allowlists: {path}")
    if reviewed_action("actions/upload-artifact") not in text:
        fail(f"release workflow does not publish build-owned asset allowlists: {path}")
    if "MYOWNMESH_RELEASE_PUBKEY" not in text or "MINISIGN_PUBLIC_KEY" not in text:
        fail(f"release workflow does not bind artifacts to the publication key: {path}")
    for job_name, body in jobs.items():
        script_lines = [
            index
            for index, line in enumerate(body.splitlines())
            if re.search(r"\bpython(?:3)?\s+[^#]*(?:scripts/|\$GITHUB_WORKSPACE/scripts/)", line)
        ]
        checkout_lines = [
            index for index, line in enumerate(body.splitlines()) if "actions/checkout@" in line
        ]
        if script_lines and (not checkout_lines or min(checkout_lines) > min(script_lines)):
            fail(f"release job {job_name} uses a script before checkout")
        if checkout_lines:
            for required in (
                "ref: ${{ github.sha }}",
                "fetch-depth: 0",
                "git rev-parse HEAD",
                "git merge-base --is-ancestor",
                "git remote get-url origin",
                "$GITHUB_REPOSITORY",
            ):
                if required not in body:
                    fail(f"release job {job_name} lacks exact checkout/origin proof: {required}")
        action_publisher = "action-gh-release@" in body or "tauri-apps/tauri-action@" in body
        command_writer = re.search(r"\bgh\s+release\s+(?:upload|edit)\b", body) is not None
        if not (action_publisher or command_writer):
            continue
        if not depends_on(job_name, "prepare-release"):
            fail(f"release writer job {job_name} does not depend on prepare-release")
        if not depends_on(job_name, "release-gates"):
            fail(f"release writer job {job_name} does not depend on release-gates")
        if "action-gh-release@" in body and not re.search(r"(?m)^\s+draft:\s*true\s*$", body):
            fail(f"publisher job {job_name} can publish a non-draft release")
        if "tauri-apps/tauri-action@" in body and not re.search(
            r"(?m)^\s+releaseDraft:\s*true\s*$", body
        ):
            fail(f"publisher job {job_name} can publish a non-draft Tauri release")

        if "tauri-apps/tauri-action@" in body:
            if "MYOWNMESH_RELEASE_PUBKEY" not in body or "MINISIGN_PUBLIC_KEY" not in body:
                fail(f"Tauri publisher job {job_name} lacks publication-key binding")
            if not re.search(
                r"[\"']?\$MYOWNMESH_RELEASE_PUBKEY[\"']?\s*=\s*[\"']?\$MINISIGN_PUBLIC_KEY|[\"']?\$MINISIGN_PUBLIC_KEY[\"']?\s*=\s*[\"']?\$MYOWNMESH_RELEASE_PUBKEY",
                body,
            ):
                fail(f"Tauri publisher job {job_name} lacks key equality proof")

        if job_name == "sign":
            signature_step = re.search(
                r"(?ms)^      - name: Sign and upload signatures\n(?P<body>.*?)(?=^      - name:|\Z)",
                body,
            )
            remote_step = re.search(
                r"(?ms)^      - name: Recheck uploaded payload/signature set while draft\n(?P<body>.*?)(?=^      - name:|\Z)",
                body,
            )
            if signature_step is None or "MINISIGN_PUBLIC_KEY" not in signature_step.group("body"):
                fail("sign step does not receive MINISIGN_PUBLIC_KEY")
            if remote_step is None or "MINISIGN_PUBLIC_KEY" not in remote_step.group("body"):
                fail("release asset verification step does not receive MINISIGN_PUBLIC_KEY")
            sign_start = body.find("Sign and upload signatures")
            first_allowlist = body.find("--asset-allowlist")
            if first_allowlist < 0 or first_allowlist > sign_start:
                fail("sign job does not reject stale assets before signing")

    for job_name, body in jobs.items():
        for line_number, line in enumerate(body.splitlines(), 1):
            release_build = re.search(
                r"cargo\s+(?:zigbuild|build)\s+[^\n]*--release[^\n]*--bin\s+myownmesh",
                line,
            )
            if release_build and "--no-default-features" not in line:
                fail(f"release daemon build at {path}:{line_number} lacks --no-default-features")
            if release_build and "--locked" not in line:
                fail(f"release daemon build at {path}:{line_number} lacks --locked")
            if release_build and (
                "MYOWNMESH_RELEASE_PUBKEY" not in body
                or "--release-public-key" not in body
            ):
                fail(f"release daemon build in {job_name} lacks publication-key binding")
            if re.search(r"cargo\s+(?:zigbuild|build)\s+[^\n]*--release[^\n]*--features[^\n]*transport-lab", line):
                fail(f"release workflow enables transport-lab at {path}:{line_number}")
    if "--signature-tree" not in text or "--public-key" not in text:
        fail(f"release workflow does not verify detached signatures before publish: {path}")
    if "--verify-release-assets" not in text:
        fail(f"release workflow does not recheck uploaded release assets: {path}")
    if "gh release edit \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft=false" in text:
        if text.index("--signature-tree") > text.index("--draft=false"):
            fail(f"release workflow publishes before signature verification: {path}")
        if text.index("--verify-release-assets") > text.index("--draft=false"):
            fail(f"release workflow publishes before asset-set verification: {path}")
        publish_index = text.index('gh release edit "$TAG" --repo "$GITHUB_REPOSITORY" --draft=false')
        preflight_positions = [
            match.start() for match in re.finditer(r"--preflight-release", text)
        ]
        if len(preflight_positions) < 2 or preflight_positions[-1] >= publish_index:
            fail(f"release workflow lacks an immediate late exact-tag preflight: {path}")
        late_preflight = text[preflight_positions[-1] : publish_index]
        for required in ("--tag", "--commit", "$GITHUB_SHA", "--repository"):
            if required not in late_preflight:
                fail(f"late exact-tag preflight does not verify {required}: {path}")
        publish_marker = "      - name: Publish signed release\n"
        publish_start = text.rfind(publish_marker)
        if publish_start < 0:
            fail(f"release workflow has no named final publish step: {path}")
        publish_body = text[publish_start:]
        for required in (
            "--preflight-release",
            "--verify-release-assets",
            "--remote-tree",
            "gh release download",
            "gh release edit \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft=false",
        ):
            if required not in publish_body:
                fail(f"final publish step lacks immediate verification: {required}")
    if "signing/minisign.key" in text:
        fail(f"release workflow places the minisign secret in the payload tree: {path}")
    verify_workflow_provenance(path)


def verify_manifest(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    features = re.search(r"(?ms)^\[features\]\s*(.*?)(?=^\[|\Z)", text)
    if features is None:
        fail(f"manifest has no [features] section: {path}")
    body = features.group(1)
    if not re.search(r"(?m)^default\s*=\s*\[\s*\]\s*$", body):
        fail(f"shipped CLI defaults are not empty: {path}")
    if not re.search(r'(?m)^transport-lab\s*=\s*\[\s*"myownmesh-core/transport-lab"\s*\]\s*$', body):
        fail(f"transport-lab test feature forwarding changed unexpectedly: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path)
    parser.add_argument("--archive", type=pathlib.Path)
    parser.add_argument(
        "--tree",
        action="append",
        default=[],
        type=pathlib.Path,
        help="scan every regular file below an installer/bundle tree",
    )
    parser.add_argument(
        "--member",
        action="append",
        default=[],
        help="exact regular-file member required in --archive (repeatable)",
    )
    parser.add_argument("--workflow", type=pathlib.Path)
    parser.add_argument("--ci-workflow", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--signature-tree", type=pathlib.Path)
    parser.add_argument("--public-key")
    parser.add_argument("--release-public-key")
    parser.add_argument("--asset-allowlist", type=pathlib.Path)
    parser.add_argument("--write-asset-manifest", type=pathlib.Path)
    parser.add_argument(
        "--remote-tree",
        type=pathlib.Path,
        help="freshly downloaded release tree to verify against the build allowlist",
    )
    parser.add_argument("--verify-release-assets", action="store_true")
    parser.add_argument("--preflight-release", action="store_true")
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--repository")
    args = parser.parse_args()
    if args.preflight_release:
        preflight_release(
            args.tag or "",
            args.commit or "",
            args.repository or os.environ.get("GITHUB_REPOSITORY", ""),
        )
        print("release draft preflight: PASS")
        return
    if not any(
        (
            args.binary,
            args.archive,
            args.tree,
            args.workflow,
            args.ci_workflow,
            args.manifest,
            args.signature_tree,
            args.verify_release_assets,
            args.write_asset_manifest,
            args.remote_tree,
        )
    ):
        parser.error("at least one scan target is required")
    if args.binary:
        scan_file(args.binary)
        if args.release_public_key:
            verify_release_public_key(args.binary, args.release_public_key)
    if args.archive:
        scan_archive(args.archive, args.member)
    for tree in args.tree:
        scan_tree(tree)
    if args.asset_allowlist and not args.signature_tree:
        if not args.tree:
            parser.error("--asset-allowlist requires --tree or --signature-tree")
        verify_asset_allowlist(args.tree[0], args.asset_allowlist)
    if args.write_asset_manifest:
        if not args.tree:
            parser.error("--write-asset-manifest requires at least one --tree")
        write_asset_manifest(args.tree, args.write_asset_manifest)
    if args.workflow:
        verify_workflow(args.workflow)
    if args.ci_workflow:
        verify_workflow_provenance(args.ci_workflow)
    if args.manifest:
        verify_manifest(args.manifest)
    if args.verify_release_assets:
        if args.signature_tree is None or args.public_key is None:
            parser.error("--verify-release-assets requires --signature-tree and --public-key")
        if args.remote_tree is not None and args.asset_allowlist is None:
            parser.error("--remote-tree requires --asset-allowlist")
        verify_remote_release_assets(
            args.signature_tree,
            args.repository or os.environ.get("GITHUB_REPOSITORY", ""),
            args.tag or os.environ.get("TAG", ""),
            args.public_key,
            args.asset_allowlist,
            args.remote_tree,
        )
    elif args.signature_tree:
        if args.public_key is None:
            parser.error("--signature-tree requires --public-key")
        verify_signature_tree(
            args.signature_tree,
            args.public_key,
            asset_allowlist=args.asset_allowlist,
        )
    elif args.remote_tree:
        parser.error("--remote-tree requires --verify-release-assets")
    print("release artifact boundary: PASS")


if __name__ == "__main__":
    main()
