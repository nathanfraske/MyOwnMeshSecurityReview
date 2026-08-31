#!/usr/bin/env python3
"""Verify that shipped artifacts do not contain the transport-lab seam."""

from __future__ import annotations

import argparse
import io
import pathlib
import re
import stat
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


def verify_workflow(path: pathlib.Path) -> None:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        release_build = re.search(
            r"cargo\s+(?:zigbuild|build)\s+[^\n]*--release[^\n]*--bin\s+myownmesh",
            line,
        )
        if release_build and "--no-default-features" not in line:
            fail(f"release daemon build at {path}:{line_number} lacks --no-default-features")
        if re.search(r"cargo\s+(?:zigbuild|build)\s+[^\n]*--release[^\n]*--features[^\n]*transport-lab", line):
            fail(f"release workflow enables transport-lab at {path}:{line_number}")


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
        "--member",
        action="append",
        default=[],
        help="exact regular-file member required in --archive (repeatable)",
    )
    parser.add_argument("--workflow", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    args = parser.parse_args()
    if not any((args.binary, args.archive, args.workflow, args.manifest)):
        parser.error("at least one scan target is required")
    if args.binary:
        scan_file(args.binary)
    if args.archive:
        scan_archive(args.archive, args.member)
    if args.workflow:
        verify_workflow(args.workflow)
    if args.manifest:
        verify_manifest(args.manifest)
    print("release artifact boundary: PASS")


if __name__ == "__main__":
    main()
