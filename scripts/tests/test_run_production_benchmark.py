from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "run-production-benchmark.py"
SPEC = importlib.util.spec_from_file_location("production_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


COMPLETE_GRANT = ",".join(f"{name}=1" for name in benchmark.GRANT_DIMENSIONS)


def _provider_snapshot() -> dict[str, object]:
    return {
        "owner_active_candidates": 0,
        "owner_failed_cleanup_candidates": 0,
        "owner_accounting_poisoned": False,
        "owner_queued_jobs": 0,
        "owner_active_jobs": 0,
        "owner_completed_jobs": 0,
        "owner_failed_jobs": 0,
        "owner_executor_failed": False,
        "mesh_active_candidates": 0,
        "mesh_failed_cleanup_candidates": 0,
        "mesh_accounting_poisoned": False,
    }


def _scale_metric(selector: str, scale_n: int) -> dict[str, object]:
    return {
        "selector": selector,
        "scale_n": scale_n,
        "admitted_delta": scale_n,
        "unresolved": 0,
        "admission_total_ms": 1.0,
        "delta_write_total_ms": 0.5,
        "admission_p50_ms": 0.001,
        "admission_p95_ms": 0.002,
        "compaction_ms": 0.25,
        "startup_plus_restore_ms": 2.0,
        "db_main_bytes_peak": 10,
        "db_wal_bytes_peak": 2,
        "db_shm_bytes_peak": 3,
        "db_journal_bytes_peak": 4,
        "db_total_bytes_peak": 19,
        "db_main_bytes_after_compaction": 10,
        "db_wal_bytes_after_compaction": 0,
        "db_shm_bytes_after_compaction": 0,
        "db_total_bytes_after": 10,
        "provider_baseline": _provider_snapshot(),
        "provider_final": _provider_snapshot(),
    }


def _open_metric() -> dict[str, object]:
    footprint = {field: 0 for field in benchmark.SEMANTIC_FOOTPRINT_FIELDS}
    return {
        "selector": "semantic_ledger_scale_open_presence_zero",
        "cycles": 5,
        "db_baseline": footprint,
        "db_final": dict(footprint),
        "provider_baseline": _provider_snapshot(),
        "provider_final": _provider_snapshot(),
    }


def _proof_metric() -> dict[str, object]:
    footprint = {field: 4 for field in ("main_bytes", "wal_bytes", "shm_bytes", "journal_bytes")}
    operations = {
        operation: {"before": dict(footprint), "after": dict(footprint)}
        for operation in benchmark.SEMANTIC_PROOF_OPERATIONS
    }
    return {
        "selector": benchmark.SEMANTIC_PROOF_SELECTOR,
        "seeded_proof_count": 15,
        "linked_fact_count": 5,
        "configured_max_database_bytes": 256 * 1024 * 1024,
        "operations": operations,
        "unrelated_rows_preserved": True,
        "no_op_footprints_equal": True,
        "reopened_exact_equality": True,
        "reopened_pending_count": 13,
        "reopened_terminal_count": 2,
    }


def _capacity_metric() -> dict[str, object]:
    return {
        "selector": benchmark.SEMANTIC_CAPACITY_SELECTOR,
        "footprint": {
            "event": "semantic_capacity_footprint",
            "M": 100,
            "W": 20,
            "S": 30,
            "R": 50,
            "B": 200,
            "provider_baseline_storage": 0,
            "provider_live_storage": 200,
            "provider_baseline_opaque_dependency_residual": 1,
            "provider_live_opaque_dependency_residual": 2,
        },
        "terminal": {
            "event": "semantic_capacity_terminal",
            "provider_storage": 0,
            "provider_opaque_dependency_residual": 0,
            "provider_retained_after_failed_cleanup": 0,
        },
    }


def _purge_metric() -> dict[str, object]:
    absent = {"before_bytes": None, "after_bytes": None, "recreated_bytes": None}
    return {
        "selector": benchmark.SEMANTIC_PURGE_SELECTOR,
        "purge_elapsed_ms": 3,
        "recreate_elapsed_ms": 4,
        "files": {
            "main": {"before_bytes": 100, "after_bytes": None, "recreated_bytes": 100},
            "wal": dict(absent),
            "shm": dict(absent),
            "journal": {"before_bytes": 20, "after_bytes": None, "recreated_bytes": None},
            "neighbor": {"before_bytes": 7, "after_bytes": 7, "recreated_bytes": 7},
        },
        "neighbor_survived": True,
        "competing_writer_busy": True,
        "terminal_baseline": {
            "primary_shutdown_ok": True,
            "restarted_shutdown_ok": True,
            "primary_shutdown_elapsed_ms": 5,
        },
    }


def test_percentiles_are_deterministic_and_interpolated() -> None:
    assert benchmark.percentile([10.0, 20.0, 30.0, 40.0], 0.50) == 25.0
    assert benchmark.percentile([10.0, 20.0, 30.0, 40.0], 0.95) == 38.5
    assert benchmark.summarize([10.0, 20.0, 30.0, 40.0]) == {
        "count": 4,
        "p50_ms": 25.0,
        "p95_ms": 38.5,
        "p99_ms": 39.7,
    }


def test_empty_percentile_is_explicitly_unavailable() -> None:
    assert benchmark.percentile([], 0.99) is None
    assert benchmark.summarize([]) == {"count": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None}


def test_finite_grant_and_localbroker_controls() -> None:
    class Args:
        runs = messages = payload_bytes = 1
        timeout = poll_interval = 1.0
        resource_grant = COMPLETE_GRANT
        daemon_arg = ["serve"]

    benchmark.validate(Args())
    Args.resource_grant = "unbounded"
    try:
        benchmark.validate(Args())
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("unbounded grants must be rejected")
    Args.resource_grant = COMPLETE_GRANT
    Args.daemon_arg = ["LocalBroker"]
    try:
        benchmark.validate(Args())
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("LocalBroker must be rejected")


def test_finite_grant_parser_requires_every_canonical_dimension() -> None:
    assert benchmark.parse_finite_grant(COMPLETE_GRANT) == {
        name: 1 for name in benchmark.GRANT_DIMENSIONS
    }
    for invalid in (
        COMPLETE_GRANT.replace("queued_bytes=1,", ""),
        COMPLETE_GRANT.replace("queued_bytes=1", "queued_bytes=-1"),
        f"{COMPLETE_GRANT},queued_bytes=2",
        f"{COMPLETE_GRANT},unknown=1",
    ):
        try:
            benchmark.parse_finite_grant(invalid)
        except benchmark.BenchmarkError:
            pass
        else:
            raise AssertionError(f"invalid finite grant accepted: {invalid}")


def test_semantic_metric_validation_requires_exact_provider_and_storage_shapes() -> None:
    metric = _scale_metric("semantic_ledger_scale_n_1k", 1_000)
    assert benchmark.validate_semantic_metric(metric, metric["selector"], 1_000) == metric
    malformed = dict(metric)
    malformed["provider_final"] = {"owner_active_candidates": 0}
    try:
        benchmark.validate_semantic_metric(malformed, metric["selector"], 1_000)
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("malformed provider metrics must be rejected")


def test_proof_metric_validation_requires_capacity_and_reopen_controls() -> None:
    metric = _proof_metric()
    assert benchmark.validate_semantic_metric(metric, metric["selector"], -1) == metric
    for field, value in (
        ("configured_max_database_bytes", False),
        ("reopened_exact_equality", False),
        ("reopened_pending_count", 12),
        ("reopened_terminal_count", True),
    ):
        malformed = dict(metric)
        malformed[field] = value
        try:
            benchmark.validate_semantic_metric(malformed, metric["selector"], -1)
        except benchmark.BenchmarkError:
            pass
        else:
            raise AssertionError(f"invalid proof field accepted: {field}={value!r}")
    missing = dict(metric)
    del missing["reopened_exact_equality"]
    try:
        benchmark.validate_semantic_metric(missing, metric["selector"], -1)
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("missing proof reopen field must be rejected")


def test_capacity_and_purge_metric_validation_is_fail_closed() -> None:
    capacity = _capacity_metric()
    bad_capacity = dict(capacity)
    bad_capacity["footprint"] = dict(capacity["footprint"])
    bad_capacity["footprint"]["B"] = 201
    try:
        benchmark.validate_semantic_metric(
            bad_capacity, benchmark.SEMANTIC_CAPACITY_SELECTOR, -2
        )
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("inconsistent capacity envelope must be rejected")

    purge = _purge_metric()
    bad_purge = dict(purge)
    bad_purge["terminal_baseline"] = dict(purge["terminal_baseline"])
    bad_purge["terminal_baseline"]["restarted_shutdown_ok"] = False
    try:
        benchmark.validate_semantic_metric(bad_purge, benchmark.SEMANTIC_PURGE_SELECTOR, -3)
    except benchmark.BenchmarkError:
        pass
    else:
        raise AssertionError("unclean purge terminal baseline must be rejected")


def test_semantic_ledger_runs_exact_ignored_cases_and_records_identity() -> None:
    metrics = {
        "semantic_ledger_scale_n_1k": _scale_metric("semantic_ledger_scale_n_1k", 1_000),
        "semantic_ledger_scale_n_10k": _scale_metric("semantic_ledger_scale_n_10k", 10_000),
        "semantic_ledger_scale_n_100k": _scale_metric("semantic_ledger_scale_n_100k", 100_000),
        "semantic_ledger_scale_open_presence_zero": _open_metric(),
        benchmark.SEMANTIC_PROOF_SELECTOR: _proof_metric(),
        benchmark.SEMANTIC_CAPACITY_SELECTOR: _capacity_metric(),
        benchmark.SEMANTIC_PURGE_SELECTOR: _purge_metric(),
        benchmark.SEMANTIC_HANDSHAKE_SELECTOR: {
            "selector": benchmark.SEMANTIC_HANDSHAKE_SELECTOR,
            "evidence": f"test {benchmark.SEMANTIC_HANDSHAKE_SELECTOR} ... ok",
        },
        benchmark.SEMANTIC_ROUTE_SELECTOR: {
            "selector": benchmark.SEMANTIC_ROUTE_SELECTOR,
            "evidence": f"test {benchmark.SEMANTIC_ROUTE_SELECTOR} ... ok",
        },
    }
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["capture_output"] is True
        selector = command[-1]
        if selector in (benchmark.SEMANTIC_HANDSHAKE_SELECTOR, benchmark.SEMANTIC_ROUTE_SELECTOR):
            metric_line = f"test {selector} ... ok"
        elif selector == benchmark.SEMANTIC_CAPACITY_SELECTOR:
            metric_line = json.dumps(metrics[selector]["footprint"]) + "\n" + json.dumps(metrics[selector]["terminal"])
        else:
            metric_line = json.dumps(metrics[selector])
        if selector in (benchmark.SEMANTIC_PROOF_SELECTOR, benchmark.SEMANTIC_PURGE_SELECTOR):
            prefix = benchmark.SEMANTIC_PREFIXES[selector]
            metric_line = prefix + " " + metric_line
        return subprocess.CompletedProcess(command, 0, metric_line + "\n", "")

    args = Namespace(
        mode="semantic-ledger",
        semantic_timeout=10.0,
        repo_root=Path(__file__).parents[2],
    )
    with tempfile.TemporaryDirectory() as temporary:
        artifact_dir = Path(temporary)
        with patch.object(benchmark.subprocess, "run", fake_run):
            manifest = benchmark.run_semantic_ledger(args, artifact_dir)
        assert (artifact_dir / "semantic-ledger.json").is_file()

    assert [command[-1] for command in calls] == list(metrics)
    assert any(command[3] == "myownmesh-core" for command in calls)
    assert any(command[3] == "myownmesh" for command in calls)
    ignored_selectors = {
        "semantic_ledger_scale_n_1k",
        "semantic_ledger_scale_n_10k",
        "semantic_ledger_scale_n_100k",
        "semantic_ledger_scale_open_presence_zero",
        benchmark.SEMANTIC_PURGE_SELECTOR,
    }
    assert all(
        ("--ignored" in command) == (command[-1] in ignored_selectors)
        and "--exact" in command
        for command in calls
    )
    assert manifest["claims"] == {
        "capacity_or_slo": False,
        "reported_curves_only": True,
        "exact_no_churn_assertions": True,
    }
    assert {entry["selector"] for entry in manifest["cases"]} == set(metrics)
    assert len(manifest["source_identity"]) == 7
    assert all(len(entry["sha256"]) == 64 for entry in manifest["source_identity"])
    assert all(entry["returncode"] == 0 and entry["elapsed_ms"] >= 0 for entry in manifest["cases"])
    assert all(len(entry["output_sha256"]) == 64 for entry in manifest["cases"])


def test_semantic_ledger_fails_closed_on_nonzero_case() -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(command, 17, "", "fixture failure")

    args = Namespace(mode="semantic-ledger", semantic_timeout=1.0, repo_root=Path(__file__).parents[2])
    with tempfile.TemporaryDirectory() as temporary:
        artifact_dir = Path(temporary)
        with patch.object(benchmark.subprocess, "run", fake_run):
            try:
                benchmark.run_semantic_ledger(args, artifact_dir)
            except benchmark.BenchmarkError as error:
                assert "semantic_ledger_scale_n_1k" in str(error)
            else:
                raise AssertionError("nonzero semantic case must fail closed")
        assert not (artifact_dir / "semantic-ledger.json").exists()


def test_run_once_uses_public_control_direction_repeats_and_cleans_up() -> None:
    class FakeProcess:
        next_pid = 50000

        def __init__(self) -> None:
            self.pid = FakeProcess.next_pid
            FakeProcess.next_pid += 1
            self.returncode = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            del timeout
            self.returncode = 0
            return self.returncode

    class FakeSampler:
        instances: list["FakeSampler"] = []

        def __init__(self, processes: dict[str, FakeProcess]) -> None:
            self.processes = processes
            self.phases: list[str] = []
            FakeSampler.instances.append(self)

        def sample(self, phase: str) -> None:
            self.phases.append(phase)

        def result(self) -> dict[str, object]:
            return {
                "available": False,
                "method": None,
                "cpu_metric": None,
                "peak_rss_bytes": {name: None for name in self.processes},
                "cumulative_cpu_seconds": {name: None for name in self.processes},
                "samples": self.phases,
            }

    class Closable:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    processes: list[FakeProcess] = []
    requests: list[tuple[str, dict[str, object]]] = []
    sent_payloads: list[dict[str, object]] = []
    active_network = ""
    event_stream = Closable()
    event_reader = Closable()

    def fake_popen(*args: object, **kwargs: object) -> FakeProcess:
        del args, kwargs
        process = FakeProcess()
        processes.append(process)
        return process

    def fake_request(control_socket: Path, body: dict[str, object], timeout: float) -> dict[str, object]:
        nonlocal active_network
        del timeout
        requests.append((str(control_socket), body))
        if body["op"] == "peers_list":
            is_a = "home-a" in str(control_socket)
            remote = "device-b" if is_a else "device-a"
            return {"ok": True, "data": {"peers": [{"device_id": remote, "status": "active", "authenticated": True}]}}
        if body["op"] == "channel_send_reliable":
            active_network = str(body["network"])
            sent_payloads.append(body["payload"])
        return {"ok": True, "data": {}}

    def fake_read_event(*args: object, **kwargs: object) -> tuple[dict[str, object], float]:
        del args, kwargs
        payload = sent_payloads[-1]
        return {
            "kind": "channel_inbound",
            "network": active_network,
            "channel": benchmark.CHANNEL,
            "from": "device-a",
            "payload": payload,
        }, 0.001

    class Args(Namespace):
        runs = 1
        messages = 3
        payload_bytes = 8
        timeout = 1.0
        poll_interval = 0.001
        resource_grant = COMPLETE_GRANT
        connector_realtime_policy = "disabled"
        daemon_arg = ["serve"]

    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary)
        with (
            patch.object(benchmark.subprocess, "Popen", fake_popen),
            patch.object(benchmark, "ProcSampler", FakeSampler),
            patch.object(benchmark, "request", fake_request),
            patch.object(benchmark, "open_events", lambda *args: (event_stream, event_reader, "c1", "cap")),
            patch.object(benchmark, "read_event", fake_read_event),
            patch.object(benchmark.os, "killpg", create=True),
        ):
            result = benchmark.run_once(Args(), run_dir, Path("shipped"), 1)

    assert len(processes) == 2
    assert len(sent_payloads) == 3
    send_requests = [body for _, body in requests if body["op"] == "channel_send_reliable"]
    assert all(body["peer"] == "device-b" for body in send_requests)
    assert all(message["event"]["from"] == "device-a" for message in result["messages"])
    assert set(result["terminals"]) == {"a", "b"}
    assert result["clean_terminal"] is True
    assert set(result["timings_ms_by_daemon"]) == {"a", "b"}
    assert all(
        set(timings) == {"control_ready", "discovery", "promotion"}
        for timings in result["timings_ms_by_daemon"].values()
    )
    assert "pre-terminate" in FakeSampler.instances[0].phases
    assert event_stream.closed and event_reader.closed
