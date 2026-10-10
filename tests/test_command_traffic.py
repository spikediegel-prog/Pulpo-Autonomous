import builtins
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core import (CommandTrafficSettings, CommandTrafficRejected, DurableJournal,
                  ExecutionEnvelope, ExecutionState, ExecutionTracker,
                  OfflineMissionLease, OfflineProtocol)
from core.traffic import CommandTrafficIntake

HAS_ROUTER = importlib.util.find_spec("sentry_traffic") is not None


class TrafficDefaultTests(unittest.TestCase):
    def test_invalid_host_settings_fail_without_writes(self):
        for kwargs in ({"max_items": True}, {"ttl_ns": 0},
                       {"max_command_bytes": 2, "max_bytes": 1}):
            with self.assertRaises(ValueError):
                CommandTrafficSettings(**kwargs)
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableJournal(Path(directory) / "events.jsonl")
            for settings in ({"max_items": 2}, "active", True):
                with self.assertRaises(ValueError):
                    ExecutionTracker(None, journal, traffic_settings=settings)
            self.assertFalse(journal.path.exists())

    def test_default_needs_no_router_and_opt_in_has_no_missing_dependency_fallback(self):
        original = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name == "sentry_traffic":
                raise ModuleNotFoundError("sentry_traffic unavailable")
            return original(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch("builtins.__import__", side_effect=unavailable):
            journal = DurableJournal(Path(directory) / "events.jsonl")
            self.assertIsNone(ExecutionTracker(None, journal)._traffic_intake)
            with self.assertRaises(ModuleNotFoundError):
                ExecutionTracker(None, journal, traffic_settings=CommandTrafficSettings())
            self.assertFalse(journal.path.exists())


@unittest.skipUnless(HAS_ROUTER, "install the local sentry-traffic package for router integration tests")
class CommandTrafficTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.envelope = ExecutionEnvelope("permit-1", "observe", "unit-1", "unit-1",
                                          "robotics", self.now, self.now + timedelta(hours=2))
        self.lease = OfflineMissionLease.issue(
            self.envelope, lease_id="lease-1", principal="operator-1", policy_id="policy-1",
            deployment_id="deployment-1", session_id="session-1", nonce="nonce-1",
            max_disconnected=timedelta(hours=1), safe_fallback="hold",
            issued_at=self.now, max_commands=1)

    def tracker(self, name="active", settings=None, security=None):
        return ExecutionTracker(OfflineProtocol(self.lease), DurableJournal(self.root / name),
                                security, traffic_settings=settings or CommandTrafficSettings())

    def raw(self, tracker):
        return tracker.journal.path.read_bytes() if tracker.journal.path.exists() else b""

    def test_valid_and_duplicate_traffic_matches_baseline_journal_and_governed_bytes(self):
        baseline = ExecutionTracker(OfflineProtocol(self.lease), DurableJournal(self.root / "off"))
        active = self.tracker()
        encoded = json.dumps(asdict(self.lease), default=str, sort_keys=True).encode()
        before = hashlib.sha256(encoded).hexdigest()
        for tracker in (baseline, active):
            self.assertEqual(ExecutionState.SENT, tracker.execute("command-1", "observe", self.now.isoformat()))
            self.assertEqual(ExecutionState.SENT, tracker.execute("command-1", "observe", self.now.isoformat()))
        self.assertEqual(self.raw(baseline), self.raw(active))
        self.assertEqual(before, hashlib.sha256(json.dumps(asdict(self.lease), default=str, sort_keys=True).encode()).hexdigest())
        self.assertEqual(2, active._traffic_intake.snapshot()["delivered"])
        self.assertEqual(0, active._traffic_intake.snapshot()["duplicate"])

    def test_queue_and_byte_backpressure_reject_without_canonical_mutation(self):
        tracker = self.tracker(settings=CommandTrafficSettings(max_items=1))
        tracker._traffic_intake._router.submit(b"already queued")
        with self.assertRaises(CommandTrafficRejected) as caught:
            tracker.execute("command-1", "observe", self.now.isoformat())
        self.assertEqual(("REJECT", "queue_budget_exhausted"), (caught.exception.status, caught.exception.reason))
        self.assertEqual(b"", self.raw(tracker))
        snapshot = tracker._traffic_intake.snapshot()
        self.assertEqual((1, 1), (snapshot["depth"], snapshot["peak_depth"]))
        self.assertLessEqual(snapshot["bytes"], tracker.traffic_settings.max_bytes)
        byte_limited = self.tracker("bytes", CommandTrafficSettings(max_bytes=64, max_command_bytes=64))
        byte_limited._traffic_intake._router.submit(b"x" * 40)
        with self.assertRaises(CommandTrafficRejected) as caught:
            byte_limited.execute("command-1", "observe", self.now.isoformat())
        self.assertEqual("queue_budget_exhausted", caught.exception.reason)
        self.assertEqual(b"", self.raw(byte_limited))

    def test_contended_transport_rejects_without_wait_or_evidence(self):
        tracker = self.tracker()
        self.assertTrue(tracker._traffic_intake._lock.acquire(blocking=False))
        try:
            with self.assertRaises(CommandTrafficRejected) as caught:
                tracker.execute("command-1", "observe", self.now.isoformat())
            self.assertEqual("traffic_busy", caught.exception.reason)
            self.assertEqual(b"", self.raw(tracker))
        finally:
            tracker._traffic_intake._lock.release()
        self.assertEqual(ExecutionState.SENT, tracker.execute("command-1", "observe", self.now.isoformat()))

    def test_ttl_exhaustion_is_terminal_drop_without_authority_or_evidence(self):
        tracker = self.tracker(settings=CommandTrafficSettings(ttl_ns=1))
        with patch("sentry_traffic.router.monotonic_ns", side_effect=[0, 1]):
            with self.assertRaises(CommandTrafficRejected) as caught:
                tracker.execute("command-1", "observe", self.now.isoformat())
        self.assertEqual(("DROP", "ttl_budget_exhausted"), (caught.exception.status, caught.exception.reason))
        self.assertEqual(b"", self.raw(tracker))
        self.assertEqual(0, tracker._traffic_intake.snapshot()["depth"])

    def test_fault_or_substituted_bytes_never_reach_existing_execution(self):
        from sentry_traffic import TrafficRouter
        for method, kwargs in (("drain", {"return_value": SimpleNamespace(ready=(b"forged",))}),
                               ("submit", {"side_effect": OSError("router unavailable")})):
            tracker = self.tracker(method)
            with patch.object(TrafficRouter, method, **kwargs), patch.object(tracker, "plan") as plan:
                with self.assertRaises(CommandTrafficRejected):
                    tracker.execute("command-1", "observe", self.now.isoformat())
                plan.assert_not_called()
            self.assertEqual(b"", self.raw(tracker))

    def test_expired_authority_and_wrong_action_still_use_existing_denial_path(self):
        tracker = self.tracker()
        with self.assertRaisesRegex(PermissionError, "offline_action_not_authorized"):
            tracker.execute("command-1", "purchase", self.now.isoformat())
        expired = self.now + timedelta(hours=3)
        self.assertEqual(ExecutionState.SAFE_FALLBACK, tracker.execute("command-2", "observe", expired.isoformat()))
        self.assertNotIn("sent", [r.event for r in tracker.journal.read()])

    def test_reconciliation_blocks_commands_and_boot_guard_remains_authoritative(self):
        tracker = self.tracker()
        tracker.protocol.disconnect(self.now)
        tracker.protocol.reconnect()
        tracker.protocol.begin_reconciliation()
        with self.assertRaisesRegex(PermissionError, "reconciliation"):
            tracker.execute("command-1", "observe", self.now.isoformat())
        self.assertEqual(b"", self.raw(tracker))
        blocked = self.tracker("boot", security=SimpleNamespace(can_execute=lambda: False))
        with self.assertRaisesRegex(PermissionError, "verified_boot"):
            blocked.execute("command-1", "observe", self.now.isoformat())
        self.assertNotIn("sent", [r.event for r in blocked.journal.read()])

    def test_unknown_restart_replay_and_tamper_boss_round(self):
        tracker = self.tracker()
        tracker.protocol.disconnect(self.now)
        tracker.execute("command-1", "observe", self.now.isoformat())
        tracker.observe("command-1", ExecutionState.UNKNOWN, self.now.isoformat())
        before = self.raw(tracker)
        restarted = ExecutionTracker(tracker.protocol, DurableJournal(tracker.journal.path),
                                     traffic_settings=CommandTrafficSettings())
        self.assertEqual(ExecutionState.UNKNOWN, restarted.execute("command-1", "observe", self.now.isoformat()))
        self.assertEqual(before, self.raw(restarted))
        restarted.journal.path.write_bytes(before.replace(b'command-1', b'command-X'))
        tampered = self.raw(restarted)
        with self.assertRaisesRegex(ValueError, "journal_integrity_failure"):
            restarted.execute("command-2", "observe", self.now.isoformat())
        self.assertEqual(tampered, self.raw(restarted))

    def test_fallback_and_observations_bypass_transport_saturation_but_keep_original_guards(self):
        tracker = self.tracker(settings=CommandTrafficSettings(max_items=1))
        tracker._traffic_intake._router.submit(b"full")
        self.assertEqual(ExecutionState.SAFE_FALLBACK, tracker.run_safe_fallback(self.now.isoformat()))
        self.assertEqual(ExecutionState.UNKNOWN, tracker.observe("command-1", ExecutionState.UNKNOWN, self.now.isoformat()))
        self.assertEqual(1, tracker._traffic_intake.snapshot()["depth"])

    def test_passive_intake_has_no_governed_handle_and_no_priority_dedup_or_recirculation(self):
        intake = CommandTrafficIntake(CommandTrafficSettings())
        self.assertEqual({"settings", "_router", "_lock"}, set(intake.__slots__))
        config = intake._router.config
        self.assertFalse(config.deduplicate_pending)
        self.assertFalse(config.prioritize)
        self.assertEqual(1, config.batch_size)
        self.assertFalse(hasattr(intake, "execute"))
        self.assertFalse(hasattr(intake._router, "recirculate"))

    def test_malformed_and_oversize_transport_inputs_are_terminal_rejections(self):
        tracker = self.tracker(settings=CommandTrafficSettings(max_command_bytes=64))
        for command in ({"grant": "authority"}, "x" * 100, "\ud800", "é" * 60):
            with self.assertRaises(CommandTrafficRejected):
                tracker.execute(command, "observe", self.now.isoformat())
        self.assertEqual(b"", self.raw(tracker))


if __name__ == "__main__":
    unittest.main()
