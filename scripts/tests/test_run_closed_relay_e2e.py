import importlib.util
import pathlib
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "run-closed-relay-e2e.py"
SPEC = importlib.util.spec_from_file_location("run_closed_relay_e2e", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ClosedRelayProcessControls(unittest.TestCase):
    def test_complete_finite_grant_is_required(self) -> None:
        raw = ",".join(f"{name}=1" for name in runner.GRANT_DIMENSIONS)
        self.assertEqual(set(runner.validate_grant(raw)), set(runner.GRANT_DIMENSIONS))
        with self.assertRaises(runner.ContractError):
            runner.validate_grant(raw.replace("opaque_dependency_residual=1", "opaque_dependency_residual=-1"))
        with self.assertRaises(runner.ContractError):
            runner.validate_grant(raw.replace("storage_bytes=1", "storage_bytes=infinite"))

    def test_public_wire_surface_is_exact(self) -> None:
        runner.require_control_surface("\n".join(runner.REQUIRED_CONTROLS))
        self.assertEqual(runner.missing_surface("closed_relay_open"), tuple(name for name in runner.REQUIRED_CONTROLS if name != "closed_relay_open"))

    def test_checked_in_wire_exposes_every_real_operation(self) -> None:
        wire = (pathlib.Path(__file__).resolve().parents[2] / "crates" / "myownmesh" / "src" / "control" / "wire.rs").read_text(encoding="utf-8")
        self.assertEqual(runner.missing_surface(wire), ())

    def test_route_config_is_closed_star(self) -> None:
        config = runner.closed_config("a", "net", "relay")
        self.assertEqual(config["kind"], "closed")
        self.assertEqual(config["topology"], {"kind": "star", "hub": "relay"})
        self.assertTrue(config["closed_relay"]["enabled"])

    def test_negative_reply_is_not_accepted_as_success(self) -> None:
        self.assertEqual(runner.closed_data({"ok": True, "data": {"closed_relay": {"received": {"payload": [1]}}}}, "received")["payload"], [1])
        with self.assertRaises(runner.ContractError):
            runner.closed_data({"ok": True, "data": {"closed_relay": {"kind": "state"}}}, "received")

    def test_refusal_requires_reason_and_preserves_optional_code(self) -> None:
        observation = runner.refusal_observation({"ok": False, "error": "queue pressure", "data": {"code": "queue_pressure"}})
        self.assertEqual(observation, {"code": "queue_pressure", "reason": "queue pressure"})
        with self.assertRaises(runner.ContractError):
            runner.refusal_observation({"ok": False, "data": {"code": "queue_pressure"}})

    def test_cleanup_attempts_all_processes_after_one_failure(self) -> None:
        class FakeProcess:
            def __init__(self, pid: int) -> None:
                self.pid = pid

            def poll(self) -> int | None:
                return None

        processes = {name: FakeProcess(index) for index, name in enumerate(("a", "b", "c"), 1)}

        def fake_terminate(process: FakeProcess, _timeout: float) -> dict[str, object]:
            if process.pid == 2:
                raise OSError("injected cleanup failure")
            return {"pid": process.pid, "returncode": 0, "forced": False}

        with patch.object(runner, "terminate", side_effect=fake_terminate):
            terminals = runner.terminate_all(processes, 1.0)
        self.assertEqual(set(terminals), {"a", "b", "c"})
        self.assertIn("error", terminals["b"])

    def test_source_has_three_process_and_terminal_controls(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for marker in ("network_create_closed", "network_import_closed", "semantic_fact_page_export", "closed_relay_send", "closed_relay_recv", "closed_relay_close", "forget_all_networks", "refusal_observation", "terminate_all", "ThreadPoolExecutor", "start_new_session", "process_tree", "orphan_children", "max_fact_pages", "manifest.json"):
            self.assertIn(marker, source)
        self.assertNotIn("LocalBroker", source)
        self.assertNotIn("REQUIRED_SURFACE", source)


if __name__ == "__main__":
    unittest.main()
