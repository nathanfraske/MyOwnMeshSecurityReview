#!/usr/bin/env python3
"""Exercise the shipped three-daemon Closed-member relay contract.

This runner deliberately speaks only the daemon's public Unix control socket.
It starts three isolated ``serve`` processes, creates and exports a signed
Closed network on A, imports the signed bootstrap and paged semantic facts on
B/C, and then verifies the authenticated A-B-B-C opaque relay in both
directions.  The finite grant is supplied by the owner; this script never
invents capacity or uses an in-process test seam.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, BinaryIO, Callable, Final


LINE_LIMIT: Final = 8 * 1024 * 1024
GRANT_ENV: Final = "MYOWNMESH_RESOURCE_GRANT"
REALTIME_ENV: Final = "MYOWNMESH_CONNECTOR_REALTIME_POLICY"
GRANT_DIMENSIONS: Final = (
    "accounted_memory_bytes", "queued_bytes", "socket_or_handle",
    "native_transport_object", "worker_or_task", "callback_or_scheduled_work",
    "storage_bytes", "storage_object", "relay_or_provider_allocation",
    "parsing_or_cpu_work", "opaque_dependency_residual",
)
REQUIRED_CONTROLS: Final = (
    "network_create_closed", "network_import_closed", "network_bootstrap_export",
    "semantic_fact_page_export", "semantic_fact_page_import",
    "closed_relay_open", "closed_relay_accept", "closed_relay_send",
    "closed_relay_recv", "closed_relay_state", "closed_relay_close",
)


class ContractError(RuntimeError):
    """The public process contract could not be established."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_grant(raw: str) -> dict[str, int]:
    """Validate a complete finite owner-selected grant."""

    if not raw.strip() or any(word in raw.lower() for word in ("unbounded", "infinite")):
        raise ContractError("--resource-grant must be finite")
    values: dict[str, int] = {}
    for item in raw.split(","):
        if "=" not in item:
            raise ContractError("grant entries must be dimension=value")
        name, value = (part.strip() for part in item.split("=", 1))
        if name not in GRANT_DIMENSIONS or name in values:
            raise ContractError(f"invalid or repeated grant dimension {name!r}")
        try:
            amount = int(value, 10)
        except ValueError as error:
            raise ContractError(f"grant dimension {name!r} is not an integer") from error
        if amount < 0:
            raise ContractError(f"grant dimension {name!r} is negative")
        values[name] = amount
    missing = [name for name in GRANT_DIMENSIONS if name not in values]
    if missing:
        raise ContractError("grant omits dimensions: " + ", ".join(missing))
    return values


def read_json_line(reader: BinaryIO) -> Any:
    line = reader.readline(LINE_LIMIT + 1)
    if not line or len(line) > LINE_LIMIT or not line.endswith(b"\n"):
        raise ContractError("control response exceeded the fixed line contract")
    try:
        return json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"control response was not JSON: {error}") from error


def request(control_socket: Path, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    """Send one public request and preserve refusals for negative controls."""

    if not hasattr(socket, "AF_UNIX"):
        raise ContractError("the shipped direct control client requires AF_UNIX")
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(control_socket))
        stream.sendall(encoded)
        with stream.makefile("rb") as reader:
            response = read_json_line(reader)
    if not isinstance(response, dict):
        raise ContractError(f"{body.get('op')} returned a non-object")
    return response


def require_ok(control_socket: Path, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    response = request(control_socket, body, timeout)
    if response.get("ok") is not True:
        raise ContractError(f"{body.get('op')} refused: {response.get('error')}")
    return response


def refusal_observation(response: dict[str, Any]) -> dict[str, str | None]:
    """Extract the bounded public refusal reason and optional typed code."""

    reason = response.get("error")
    if not isinstance(reason, str) or not reason.strip():
        raise ContractError(f"refusal omitted a bounded reason: {response!r}")
    data = response.get("data")
    code = data.get("code") if isinstance(data, dict) else None
    if code is not None and (not isinstance(code, str) or not code.strip()):
        raise ContractError(f"refusal carried an invalid typed code: {response!r}")
    return {"code": code, "reason": reason}


def require_refusal(control_socket: Path, body: dict[str, Any], timeout: float) -> tuple[dict[str, Any], dict[str, str | None]]:
    response = request(control_socket, body, timeout)
    if response.get("ok") is True:
        raise ContractError(f"{body.get('op')} unexpectedly succeeded")
    return response, refusal_observation(response)


def missing_surface(control_wire: str) -> tuple[str, ...]:
    def tokens(name: str) -> tuple[str, str]:
        return name, "".join(part.title() for part in name.split("_"))

    return tuple(name for name in REQUIRED_CONTROLS if not any(token in control_wire for token in tokens(name)))


def require_control_surface(control_wire: str) -> None:
    missing = missing_surface(control_wire)
    if missing:
        raise ContractError("public wire omits: " + ", ".join(missing))


def status(control_socket: Path, timeout: float) -> dict[str, Any]:
    response = require_ok(control_socket, {"op": "status"}, timeout)
    data = response.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("device_id"), str):
        raise ContractError("status omitted canonical device_id")
    return data


def active_peers(control_socket: Path, network: str, timeout: float) -> list[dict[str, Any]]:
    response = require_ok(control_socket, {"op": "peers_list", "network": network}, timeout)
    peers = (response.get("data") or {}).get("peers")
    if not isinstance(peers, list):
        raise ContractError("peers_list omitted peers")
    return [peer for peer in peers if isinstance(peer, dict) and peer.get("status") == "active" and peer.get("authenticated") is True]


def wait_for(label: str, timeout: float, poll_interval: float, probe: Callable[[], Any]) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
            last = value
        except (OSError, ValueError, ContractError) as error:
            last = repr(error)
        time.sleep(poll_interval)
    raise ContractError(f"timed out waiting for {label}; last={last!r}")


def semantic_policy() -> dict[str, int]:
    return {
        "max_fact_encoded_bytes": 65_535,
        "max_dependencies_per_fact": 64,
        "max_authority_uses_per_fact": 32,
        "max_authority_predecessors_per_use": 64,
        "max_admitted_facts": 100_000,
        "max_admitted_bytes": 128 * 1024 * 1024,
        "max_quarantined_facts": 4_096,
        "max_quarantined_bytes": 16 * 1024 * 1024,
        "max_quarantined_facts_per_author": 256,
        "max_quarantined_bytes_per_author": 4 * 1024 * 1024,
        "max_retained_facts_per_author": 10_000,
        "max_retained_bytes_per_author": 16 * 1024 * 1024,
        "max_dependency_edges": 1_000_000,
        "max_ready_batch": 256,
        "max_pending_proofs": 10_000,
        "max_pending_proof_bytes": 16 * 1024 * 1024,
        "max_proof_records": 100_000,
        "max_proof_bytes": 64 * 1024 * 1024,
        "max_proof_links": 100_000,
        "max_author_usage_rows": 100_000,
        "max_provisional_rows": 100_000,
        "max_transaction_dirty_main_pages": 1_024,
        "max_uncheckpointed_wal_frames": 1_018,
        "max_freelist_pages": 1_024,
        "max_fragmented_pages": 1_024,
        "max_main_journal_bytes": 8 * 1024 * 1024,
        "max_database_bytes": 2 * 1024 * 1024 * 1024,
        "max_wal_bytes": 8_413_072,
        "wal_checkpoint_threshold_bytes": 32 + 1_018 * (4_096 + 24),
        "emergency_reserve_bytes": 8 * 1024 * 1024,
    }


def daemon_config() -> dict[str, Any]:
    return {"version": 2, "networks": []}


def closed_config(local_id: str, network: str, relay_id: str) -> dict[str, Any]:
    return {
        "id": local_id,
        "network_id": network,
        "label": "closed-relay-process-e2e",
        "kind": "closed",
        "semantic_policy": semantic_policy(),
        "topology": {"kind": "star", "hub": relay_id},
        "signaling": {"strategy": "none", "mdns": True, "servers": [], "redundancy": 1,
                       "denylist": [], "public_fallback": False},
        "closed_relay": {
            "enabled": True, "max_allocations": 1, "max_allocations_per_member": 1,
            "max_pending_handshakes": 4, "pending_handshake_timeout_ms": 30_000,
            "replay_window": 64, "max_frame_ciphertext_bytes": 16_174,
            "queue_items_per_direction": 64, "queue_bytes_per_direction": 4 * 1024 * 1024,
            "bandwidth_rate_bytes_per_second": 1024 * 1024, "bandwidth_burst_bytes": 2 * 1024 * 1024,
            "idle_timeout_ms": 30_000, "max_lifetime_ms": 3_600_000,
            "max_control_bytes": 16 * 1024, "shutdown_grace_ms": 5_000,
        },
        "stun_servers": [], "turn_servers": [],
        "pinned_peers": [], "auto_approve": True,
    }


def closed_data(response: dict[str, Any], variant: str) -> dict[str, Any]:
    if response.get("ok") is not True:
        raise ContractError(f"closed relay {variant} refused: {response.get('error')}")
    data = response.get("data")
    value = data.get("closed_relay") if isinstance(data, dict) else None
    if isinstance(value, dict) and variant in value and isinstance(value[variant], dict):
        value = value[variant]
    elif not (isinstance(value, dict) and value.get("kind") == variant):
        raise ContractError(f"closed relay reply is not {variant}: {response!r}")
    if not isinstance(value, dict):
        raise ContractError(f"closed relay reply is not {variant}: {response!r}")
    return value


def open_and_accept(sockets: dict[str, Path], network: str, relay: str, target: str, timeout: float) -> tuple[dict[str, Any], dict[str, Any]]:
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="relay-open-accept") as pool:
        opened = pool.submit(require_ok, sockets["a"], {"op": "closed_relay_open", "network": network, "relay": relay, "target": target}, timeout)
        accepted = pool.submit(require_ok, sockets["c"], {"op": "closed_relay_accept", "network": network, "wait_ms": int(timeout * 1000)}, timeout)
        return closed_data(opened.result(), "opened"), closed_data(accepted.result(), "accepted")


def terminate(process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    forced = False
    if process.poll() is None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            forced = True
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait(timeout=timeout)
    return {"pid": process.pid, "returncode": process.returncode, "forced": forced}


def terminate_all(processes: dict[str, subprocess.Popen[bytes]], timeout: float) -> dict[str, Any]:
    """Attempt every daemon even when one cleanup path itself fails."""

    terminals: dict[str, Any] = {}
    for name, process in reversed(tuple(processes.items())):
        try:
            terminals[name] = terminate(process, timeout)
        except Exception as error:
            terminals[name] = {"pid": process.pid, "returncode": process.poll(),
                               "forced": True, "error": repr(error)}
    return terminals


def close_logs(logs: dict[str, tuple[BinaryIO, BinaryIO]]) -> dict[str, str]:
    """Close every captured stream while preserving the first close failure."""

    errors: dict[str, str] = {}
    for name, streams in logs.items():
        for index, stream in enumerate(streams):
            try:
                stream.close()
            except Exception as error:
                errors[f"{name}:{index}"] = repr(error)
    return errors


def process_tree(root_pid: int) -> set[int]:
    """Return a bounded /proc snapshot of one process tree on Linux."""

    if not sys.platform.startswith("linux"):
        return {root_pid}
    parents: dict[int, int] = {}
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            stat = (entry / "stat").read_text(encoding="utf-8")
            parents[int(entry.name)] = int(stat.rsplit(")", 1)[1].split()[1])
        except (FileNotFoundError, OSError, ValueError, IndexError):
            continue
    found = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in found and pid not in found:
                found.add(pid)
                changed = True
    return found


def process_observation(processes: dict[str, subprocess.Popen[bytes]], seen: dict[str, set[int]]) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for name, process in processes.items():
        tree = process_tree(process.pid)
        seen.setdefault(name, set()).update(tree - {process.pid})
        records[name] = {"pid": process.pid, "returncode": process.poll(), "tree_pids": sorted(tree)}
    return records


def orphan_observation(processes: dict[str, subprocess.Popen[bytes]], seen: dict[str, set[int]]) -> dict[str, list[int] | None]:
    if not sys.platform.startswith("linux"):
        return {name: None for name in processes}
    return {name: sorted(pid for pid in pids if Path(f"/proc/{pid}").exists()) for name, pids in seen.items()}


def run(args: argparse.Namespace, grant: dict[str, int]) -> dict[str, Any]:
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        raise ContractError("three-process public control requires Unix sockets")
    binary = args.binary.resolve(strict=True)
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if any(artifact_dir.iterdir()):
        raise ContractError(f"artifact directory must be empty: {artifact_dir}")
    network = "relay" + secrets.token_hex(8)
    homes = {name: artifact_dir / f"home-{name}" for name in ("a", "b", "c")}
    sockets = {name: home / "daemon.sock" for name, home in homes.items()}
    if any(len(os.fsencode(path)) > 100 for path in sockets.values()):
        raise ContractError("control socket path exceeds Unix's portable limit")
    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, tuple[BinaryIO, BinaryIO]] = {}
    seen_process_children: dict[str, set[int]] = {}
    manifest: dict[str, Any] = {"schema": "myownmesh-closed-relay-e2e/v1", "network": network,
        "binary": str(binary), "binary_sha256": sha256_file(binary), "grant": grant,
        "controls": {}, "processes": {}, "process_observations": {}, "clean_terminal": False,
        "max_fact_pages": args.max_fact_pages}
    try:
        for name, home in homes.items():
            home.mkdir(parents=True)
            write_json(home / "config.json", daemon_config())
            stdout = (artifact_dir / f"daemon-{name}.stdout.log").open("wb")
            stderr = (artifact_dir / f"daemon-{name}.stderr.log").open("wb")
            logs[name] = (stdout, stderr)
            environment = os.environ.copy()
            environment.update({"MYOWNMESH_HOME": str(home), "MYOWNMESH_LOG_FORMAT": "json",
                                GRANT_ENV: args.resource_grant, REALTIME_ENV: "disabled"})
            kwargs: dict[str, Any] = {"env": environment, "stdin": subprocess.DEVNULL,
                "stdout": stdout, "stderr": stderr, "start_new_session": True}
            processes[name] = subprocess.Popen([str(binary), "serve"], **kwargs)
        manifest["process_observations"] = {"spawned": process_observation(processes, seen_process_children)}
        for name in homes:
            wait_for(f"{name} status", args.timeout, args.poll_interval,
                     lambda name=name: status(sockets[name], args.timeout))
        manifest["process_observations"]["ready"] = process_observation(processes, seen_process_children)
        ids = {name: status(sockets[name], args.timeout)["device_id"] for name in homes}
        if len(set(ids.values())) != 3 or any(not value for value in ids.values()):
            raise ContractError(f"A/B/C device identities were not pairwise distinct: {ids!r}")
        relay_id, target_id = ids["b"], ids["c"]
        config_a = closed_config("a", network, relay_id)
        require_ok(sockets["a"], {"op": "network_create_closed", "config": config_a}, args.timeout)
        bootstrap = (require_ok(sockets["a"], {"op": "network_bootstrap_export", "network": network}, args.timeout).get("data") or {}).get("bootstrap")
        identity = (require_ok(sockets["a"], {"op": "semantic_state_identity", "network": network}, args.timeout).get("data") or {}).get("semantic_state_identity")
        context_id = identity.get("context_id") if isinstance(identity, dict) else None
        if not isinstance(bootstrap, dict) or not isinstance(context_id, str):
            raise ContractError("bootstrap or semantic context identity was malformed")
        for target in (ids["b"], ids["c"]):
            require_ok(sockets["a"], {"op": "governance_propose_role_grant", "network": network,
                                       "target": target, "role": "member", "mfa_code": None}, args.timeout)
        cursor: str | None = None
        pages = 0
        while pages < args.max_fact_pages:
            page_request = {"context_id": context_id, "cursor": cursor, "max_facts": 64,
                            "max_encoded_bytes": 1024 * 1024}
            page = (require_ok(sockets["a"], {"op": "semantic_fact_page_export", "network": network,
                                               "request": page_request}, args.timeout).get("data") or {}).get("semantic_fact_page")
            if not isinstance(page, dict):
                raise ContractError("semantic fact export omitted a page")
            for name in ("b", "c"):
                if pages == 0:
                    require_ok(sockets[name], {"op": "network_import_closed", "config": closed_config(name, network, relay_id),
                                               "expected_context_id": context_id, "bootstrap": bootstrap}, args.timeout)
                require_ok(sockets[name], {"op": "semantic_fact_page_import", "network": network, "page": page}, args.timeout)
            pages += 1
            if page.get("complete") is True:
                break
            cursor = page.get("next_cursor")
            if not isinstance(cursor, str) or not cursor:
                raise ContractError("incomplete semantic page omitted next_cursor")
        else:
            raise ContractError("semantic fact pagination exceeded the owner-selected page bound")
        for name, expected in (("a", relay_id), ("c", relay_id)):
            wait_for(f"{name} authenticated peer", args.timeout, args.poll_interval,
                     lambda name=name, expected=expected: any(peer.get("device_id") == expected for peer in active_peers(sockets[name], network, args.timeout)))
        wait_for("B authenticated A and C", args.timeout, args.poll_interval,
                 lambda: all(peer_id in {peer.get("device_id") for peer in active_peers(sockets["b"], network, args.timeout)} for peer_id in (ids["a"], ids["c"])))
        if any(peer.get("device_id") == ids["c"] for peer in active_peers(sockets["a"], network, args.timeout)) or any(peer.get("device_id") == ids["a"] for peer in active_peers(sockets["c"], network, args.timeout)):
            raise ContractError("star topology exposed a direct A/C peer")
        first_a, first_c = open_and_accept(sockets, network, relay_id, target_id, args.timeout)
        if first_a.get("peer") != target_id or first_a.get("relay") != relay_id or first_c.get("peer") != ids["a"] or first_c.get("relay") != relay_id:
            raise ContractError("relay endpoint metadata did not preserve A/B/C route")
        if first_a.get("session_id") != first_c.get("session_id") or not first_a.get("allocation_epoch"):
            raise ContractError("relay endpoints did not share a nonzero session epoch")
        if int(first_a.get("max_allocations", 0)) != 1:
            raise ContractError("fixture did not retain the exact one-allocation ceiling")
        handle_a, handle_c = first_a["handle"], first_c["handle"]
        _, wrong_handle_refusal = require_refusal(sockets["a"], {"op": "closed_relay_state", "handle": "wrong-handle"}, args.timeout)
        _, pending_refusal = require_refusal(sockets["c"], {"op": "closed_relay_accept", "network": network, "wait_ms": 1}, args.timeout)
        max_frame = int(first_a["max_frame_bytes"])
        _, oversize_refusal = require_refusal(sockets["a"], {"op": "closed_relay_send", "handle": handle_a, "payload": [65] * (max_frame + 1)}, args.timeout)
        _, capacity_refusal = require_refusal(sockets["a"], {"op": "closed_relay_open", "network": network, "relay": relay_id, "target": target_id}, args.timeout)
        payload_ac = list(range(min(args.payload_bytes, 255)))
        payload_ca = list(reversed(payload_ac))
        require_ok(sockets["a"], {"op": "closed_relay_send", "handle": handle_a, "payload": payload_ac}, args.timeout)
        received = closed_data(require_ok(sockets["c"], {"op": "closed_relay_recv", "handle": handle_c, "wait_ms": int(args.timeout * 1000)}, args.timeout), "received")
        if received.get("payload") != payload_ac:
            raise ContractError("A-to-C opaque payload was not exact")
        require_ok(sockets["c"], {"op": "closed_relay_send", "handle": handle_c, "payload": payload_ca}, args.timeout)
        received = closed_data(require_ok(sockets["a"], {"op": "closed_relay_recv", "handle": handle_a, "wait_ms": int(args.timeout * 1000)}, args.timeout), "received")
        if received.get("payload") != payload_ca:
            raise ContractError("C-to-A opaque payload was not exact")
        state = closed_data(require_ok(sockets["a"], {"op": "closed_relay_state", "handle": handle_a}, args.timeout), "state")
        if int(state.get("active_allocations", 0)) < 1:
            raise ContractError("state did not expose the live allocation")
        require_ok(sockets["c"], {"op": "closed_relay_close", "handle": handle_c}, args.timeout)
        require_ok(sockets["a"], {"op": "closed_relay_close", "handle": handle_a}, args.timeout)
        _, duplicate_close_refusal = require_refusal(sockets["a"], {"op": "closed_relay_close", "handle": handle_a}, args.timeout)
        second_a, second_c = open_and_accept(sockets, network, relay_id, target_id, args.timeout)
        if second_a.get("generation") == first_a.get("generation") or second_a.get("allocation_epoch") == first_a.get("allocation_epoch"):
            raise ContractError("successor reused the old relay generation")
        _, stale_a_refusal = require_refusal(sockets["a"], {"op": "closed_relay_state", "handle": handle_a}, args.timeout)
        _, stale_c_refusal = require_refusal(sockets["c"], {"op": "closed_relay_state", "handle": handle_c}, args.timeout)
        require_ok(sockets["c"], {"op": "closed_relay_close", "handle": second_c["handle"]}, args.timeout)
        require_ok(sockets["a"], {"op": "closed_relay_close", "handle": second_a["handle"]}, args.timeout)
        manifest["controls"] = {"authenticated_ab_bc": True, "no_direct_ac": True, "bidirectional_opaque_payload": True,
            "wrong_handle_refused": wrong_handle_refusal, "pending_wait_refused": pending_refusal,
            "oversize_refused": oversize_refusal, "capacity_refused": capacity_refusal,
            "duplicate_close_refused": duplicate_close_refusal, "stale_handle_refused": {"a": stale_a_refusal, "c": stale_c_refusal},
            "replacement_generation": True, "resource_terminal": {"live_state": state, "configured_max_allocations": 1, "closed": True, "successor_admitted": True,
                "pending_capacity_public": False, "provider_baseline_public": False},
            "refusal_contract": {"bounded_reason": True, "typed_code_exposed": all(
                observation["code"] is not None for observation in (
                    wrong_handle_refusal, pending_refusal, oversize_refusal,
                    capacity_refusal, duplicate_close_refusal, stale_a_refusal, stale_c_refusal,
                )), "typed_code_public_gap": True}}
        manifest["process_observations"]["pre_shutdown"] = process_observation(processes, seen_process_children)
    finally:
        shutdown: dict[str, Any] = {}
        for name in homes:
            try:
                require_ok(sockets[name], {"op": "forget_all_networks"}, min(args.timeout, 5.0))
                shutdown[name] = "accepted"
            except (ContractError, OSError) as error:
                shutdown[name] = f"unavailable: {error}"
        manifest["public_shutdown"] = shutdown
        terminals = terminate_all(processes, args.timeout)
        manifest["processes"] = terminals
        manifest["process_observations"]["terminal"] = process_observation(processes, seen_process_children)
        manifest["orphan_children"] = orphan_observation(processes, seen_process_children)
        manifest["no_orphan_children"] = all(not pids for pids in manifest["orphan_children"].values() if pids is not None)
        manifest["log_close_errors"] = close_logs(logs)
        manifest["clean_terminal"] = all(value["returncode"] == 0 and not value["forced"] for value in terminals.values()) and manifest["no_orphan_children"] is True and not manifest["log_close_errors"]
        write_json(artifact_dir / "manifest.json", manifest)
    if not manifest["clean_terminal"]:
        raise ContractError(f"processes did not terminate cleanly: {manifest['processes']!r}")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--resource-grant", required=True)
    parser.add_argument("--control-wire", type=Path)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--payload-bytes", type=int, default=32)
    parser.add_argument("--max-fact-pages", type=int, required=True,
                        help="owner-selected bound for semantic fact pages")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout <= 0 or args.poll_interval <= 0 or args.payload_bytes <= 0 or args.max_fact_pages <= 0:
        raise ContractError("timeout, poll interval, payload size, and page bound must be positive")
    if args.control_wire is not None:
        try:
            require_control_surface(args.control_wire.read_text(encoding="utf-8"))
        except OSError as error:
            raise ContractError(f"cannot inspect control wire: {error}") from error
    manifest = run(args, validate_grant(args.resource_grant))
    print(f"closed relay E2E completed; artifacts: {args.artifact_dir.resolve()}")
    return 0 if manifest["clean_terminal"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"closed relay E2E error: {error}", file=sys.stderr)
        raise SystemExit(2)
