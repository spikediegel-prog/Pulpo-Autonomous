from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from core import (
    ConnectivityState,
    DurableJournal,
    ExecutionEnvelope,
    ExecutionState,
    ExecutionTracker,
    OfflineMissionLease,
    OfflineProtocol,
)
from adapters.simulated.offline import SimulatedOfflineUnit


class OfflineAutonomyTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2030, 1, 1, tzinfo=timezone.utc)
        envelope = ExecutionEnvelope(
            permit_id="permit-1",
            action="observe",
            target="unit-1",
            machine_id="unit-1",
            domain="robotics",
            issued_at=self.start,
            expires_at=self.start + timedelta(hours=2),
        )
        lease = OfflineMissionLease.issue(
            envelope,
            lease_id="lease-1",
            principal="operator-1",
            policy_id="policy-1",
            deployment_id="deployment-1",
            session_id="session-1",
            nonce="nonce-1",
            max_disconnected=timedelta(hours=1),
            safe_fallback="hold",
            issued_at=self.start,
            max_commands=1,
        )
        self.protocol = OfflineProtocol(lease)

    def test_disconnection_preserves_but_does_not_extend_authority(self):
        self.protocol.disconnect(self.start + timedelta(minutes=1))
        self.assertTrue(self.protocol.can_execute(self.start + timedelta(minutes=30)))
        self.assertFalse(
            self.protocol.can_execute(self.start + timedelta(hours=1, minutes=1, seconds=1))
        )
        self.assertEqual(self.protocol.connectivity, ConnectivityState.DISCONNECTED)

    def test_reconciliation_blocks_execution_until_complete(self):
        self.protocol.disconnect(self.start)
        self.protocol.reconnect()
        self.protocol.begin_reconciliation()
        self.assertFalse(self.protocol.can_execute(self.start + timedelta(minutes=1)))
        self.protocol.finish_reconciliation()
        self.assertTrue(self.protocol.can_execute(self.start + timedelta(minutes=1)))

    def test_unknown_does_not_retry(self):
        with TemporaryDirectory() as directory:
            journal = DurableJournal(Path(directory) / "events.jsonl")
            tracker = ExecutionTracker(self.protocol, journal)
            unit = SimulatedOfflineUnit(tracker)
            unit.execute("command-1", "observe", self.start)
            self.assertEqual(
                unit.report_unknown("command-1", self.start),
                ExecutionState.UNKNOWN,
            )
            self.assertEqual(
                [record.event for record in journal.read()],
                ["planned", "sent", "unknown"],
            )

    def test_duplicate_command_is_not_resent(self):
        with TemporaryDirectory() as directory:
            journal = DurableJournal(Path(directory) / "events.jsonl")
            tracker = ExecutionTracker(self.protocol, journal)
            unit = SimulatedOfflineUnit(tracker)
            self.assertEqual(
                unit.execute("command-1", "observe", self.start),
                ExecutionState.SENT,
            )
            self.assertEqual(
                unit.execute("command-1", "observe", self.start + timedelta(seconds=1)),
                ExecutionState.SENT,
            )
            self.assertEqual(
                [record.event for record in journal.read()],
                ["planned", "sent"],
            )

    def test_command_budget_runs_only_pre_authorized_fallback(self):
        with TemporaryDirectory() as directory:
            journal = DurableJournal(Path(directory) / "events.jsonl")
            tracker = ExecutionTracker(self.protocol, journal)
            unit = SimulatedOfflineUnit(tracker)
            unit.execute("command-1", "observe", self.start)
            self.assertEqual(
                unit.execute("command-2", "observe", self.start),
                ExecutionState.SAFE_FALLBACK,
            )
            self.assertEqual(journal.read()[-1].payload["fallback"], "hold")

    def test_expired_lease_runs_fallback_not_new_command(self):
        with TemporaryDirectory() as directory:
            journal = DurableJournal(Path(directory) / "events.jsonl")
            tracker = ExecutionTracker(self.protocol, journal)
            unit = SimulatedOfflineUnit(tracker)
            expired = self.start + timedelta(hours=2, seconds=1)
            self.assertEqual(
                unit.execute("command-1", "observe", expired),
                ExecutionState.SAFE_FALLBACK,
            )
            self.assertEqual(journal.read()[-1].event, "safe_fallback")

    def test_journal_tampering_fails_closed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = DurableJournal(path)
            journal.append("received_permit", {"permit_id": "permit-1"})
            path.write_text(path.read_text().replace("permit-1", "permit-2"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "journal_integrity_failure"):
                journal.read()


if __name__ == "__main__":
    unittest.main()
