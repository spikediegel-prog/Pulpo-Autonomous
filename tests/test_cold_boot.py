from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from core import (
    BootEvidence,
    ColdBootGuard,
    DurableJournal,
    ExecutionEnvelope,
    ExecutionTracker,
    KeyUseRequest,
    OfflineMissionLease,
    OfflineProtocol,
)


class ColdBootTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2030, 1, 1, tzinfo=timezone.utc)

    def _guard(self, directory: str) -> ColdBootGuard:
        return ColdBootGuard(
            machine_id="unit-1",
            deployment_id="deployment-1",
            expected_firmware_measurement="fw-good",
            journal=DurableJournal(Path(directory) / "events.jsonl"),
        )

    def test_key_use_requires_verified_current_boot(self):
        with TemporaryDirectory() as directory:
            guard = self._guard(directory)
            request = KeyUseRequest(
                "unit-key", "unit-1", "deployment-1", "fw-good", "command-authentication"
            )
            with self.assertRaisesRegex(PermissionError, "verified_boot"):
                guard.authorize_key_use(request)
            guard.attest_boot(BootEvidence("unit-1", "deployment-1", "fw-good", 1, True))
            guard.authorize_key_use(request)

    def test_reset_invalidates_volatile_authority_until_new_attestation(self):
        with TemporaryDirectory() as directory:
            guard = self._guard(directory)
            guard.attest_boot(BootEvidence("unit-1", "deployment-1", "fw-good", 1, True))
            guard.reset()
            self.assertFalse(guard.can_execute())
            with self.assertRaisesRegex(PermissionError, "verified_boot"):
                guard.authorize_key_use(
                    KeyUseRequest(
                        "unit-key", "unit-1", "deployment-1", "fw-good", "command-authentication"
                    )
                )
            guard.attest_boot(BootEvidence("unit-1", "deployment-1", "fw-good", 2, True))
            self.assertTrue(guard.can_execute())

    def test_boot_rollback_and_substitution_fail_closed(self):
        with TemporaryDirectory() as directory:
            guard = self._guard(directory)
            guard.attest_boot(BootEvidence("unit-1", "deployment-1", "fw-good", 2, True))
            for evidence in (
                BootEvidence("unit-1", "deployment-1", "fw-good", 1, True),
                BootEvidence("unit-1", "deployment-1", "fw-old", 3, True),
                BootEvidence("attacker", "deployment-1", "fw-good", 3, True),
                BootEvidence("unit-1", "deployment-1", "fw-good", 4, False),
            ):
                with self.assertRaisesRegex(PermissionError, "boot_attestation_rejected"):
                    guard.attest_boot(evidence)
            self.assertFalse(guard.can_execute())

    def test_reset_blocks_offline_execution(self):
        with TemporaryDirectory() as directory:
            guard = self._guard(directory)
            guard.attest_boot(BootEvidence("unit-1", "deployment-1", "fw-good", 1, True))
            envelope = ExecutionEnvelope(
                "permit-1", "observe", "unit-1", "unit-1", "robotics",
                issued_at=self.start, expires_at=self.start + timedelta(hours=1),
            )
            lease = OfflineMissionLease.issue(
                envelope,
                lease_id="lease-1", principal="operator", policy_id="policy",
                deployment_id="deployment-1", session_id="session", nonce="nonce",
                max_disconnected=timedelta(minutes=30), safe_fallback="hold",
                issued_at=self.start, max_commands=1,
            )
            journal = DurableJournal(Path(directory) / "execution.jsonl")
            tracker = ExecutionTracker(OfflineProtocol(lease), journal, guard)
            guard.reset()
            with self.assertRaisesRegex(PermissionError, "key_release_requires_verified_boot"):
                tracker.execute("command-1", "observe", self.start.isoformat())


if __name__ == "__main__":
    unittest.main()
