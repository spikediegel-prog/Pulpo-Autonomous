"""Observer snapshot contract (Control Center design v0, item 5.1).

The single frozen JSON document the Control Center polls. Tests pin the
contract, not the CC: frozen shape, primitives only, bounded size,
byte-identical repeated reads, non-mutation, and fail-to-Unknown on
malformed / oversize / wrong-schema input -- never a stale good value.

Adversarial note: a snapshot that looks authoritative while wrong is
the failure this contract exists to prevent (design section 3). Every
test below that mutates, tampers, or substitutes an input asserts the
snapshot refuses it or reports Unknown, and none of them asserts
enforcement from a successful read.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from core import DurableJournal, ExecutionEnvelope, OfflineMissionLease
from core.drift import O2HeadSample, evaluate_sample
from pulpo import GovernanceKernel, Policy, PulpoOrchestrator, anchor_state
from pulpo.anchor import AuditAnchor, InMemoryAnchorStore
from pulpo.incident_channel import freeze_incident_report
from pulpo.mcp_boundary import MCPBoundaryError
from pulpo.observer_snapshot import (
    MAX_OBSERVER_SNAPSHOT_BYTES,
    OBSERVER_SNAPSHOT_SCHEMA,
    ObserverAnchorState,
    ObserverDriftHead,
    ObserverJournalTip,
    ObserverLeaseSummary,
    ObserverSignatureSummary,
    ObserverSnapshot,
    export_observer_snapshot,
    freeze_observer_snapshot,
    load_observer_snapshot,
)
from pulpo.state import AuditSigner, InMemoryKernelState

AUDIT_SECRET = "observer-test-audit-secret".encode("utf-8")
KERNEL_SECRET = "observer-test-kernel-secret".encode("utf-8")
START = datetime(2030, 1, 1, tzinfo=timezone.utc)
# Fixed freeze clock: 2030-01-01 00:30 UTC, halfway through the test
# lease's envelope window (issued 00:00, expires 02:00).
CLOCK_NS = int(datetime(2030, 1, 1, 0, 30, tzinfo=timezone.utc).timestamp() * 1_000_000_000)


def _kernel(*, signing: bool = False):
    if signing:
        state = InMemoryKernelState(audit_signer=AuditSigner(AUDIT_SECRET))
    else:
        state = InMemoryKernelState()
    kernel = GovernanceKernel(
        Policy(frozenset({"read"}), 0),
        secret=KERNEL_SECRET,
        state=state,
        clock=lambda: 2_000_000,
    )
    return kernel, state, PulpoOrchestrator(kernel)


def _lease(**overrides):
    values = {
        "lease_id": "lease-1",
        "principal": "operator-1",
        "policy_id": "policy-1",
        "deployment_id": "deployment-1",
        "session_id": "session-1",
        "nonce": "nonce-1",
        "max_disconnected": timedelta(hours=1),
        "safe_fallback": "fans_on",
        "issued_at": START,
        "max_commands": 3,
    }
    values.update(overrides)
    envelope = ExecutionEnvelope(
        permit_id="permit-1",
        action="observe",
        target="unit-1",
        machine_id="unit-1",
        domain="robotics",
        issued_at=START,
        expires_at=START + timedelta(hours=2),
    )
    return OfflineMissionLease.issue(envelope, **values)


def _dying_head_sample():
    """Appendix C, section C1: the dying sensor, not bad air."""
    return O2HeadSample(
        sensor_id="O2-E04-01",
        raw_o2_pct=18.9,
        drift_pct_per_hour=-1.4,
        step_change_pct_per_minute=-1.8,
        neighbor_median_pct=20.8,
        age_seconds=4,
        fault_code=None,
        calibrating=False,
        calibration_age_days=5,
        rated_life_expired=False,
        span_check_passed=True,
        accuracy_within_spec=False,
        reading_compensated=True,
        airflow_active=True,
        pump_running=True,
        personnel_in_zone=True,
    )


def _as_json_primitives(value):
    if isinstance(value, dict):
        return {key: _as_json_primitives(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_as_json_primitives(item) for item in value]
    assert type(value) in (str, bool, int, float, type(None)), type(value)
    return value


class ObserverSnapshotTests(unittest.TestCase):
    def test_minimal_freeze_shape_matches_section_5_1(self):
        _, _, orchestrator = _kernel()
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        self.assertIs(type(snapshot), ObserverSnapshot)
        self.assertEqual(snapshot.schema, OBSERVER_SNAPSHOT_SCHEMA)
        self.assertEqual(snapshot.frozen_at_ns, CLOCK_NS)
        self.assertEqual(snapshot.source_id, orchestrator.kernel.state_source_id())
        self.assertIsNone(snapshot.deployment_id)
        self.assertIsNone(snapshot.device_id)
        evidence = orchestrator.evidence_snapshot()
        self.assertEqual(snapshot.policy_hash, evidence.policy_hash)
        self.assertEqual(snapshot.audit_valid, evidence.audit_valid)
        self.assertEqual(snapshot.audit_records, evidence.audit_records)
        self.assertEqual(snapshot.audit_tip, evidence.audit_tip)
        self.assertEqual(snapshot.signatures.signing_enabled, False)
        self.assertEqual(snapshot.signatures.total_records, evidence.audit_records)
        self.assertFalse(snapshot.anchor.available)
        self.assertIsNone(snapshot.anchor.head_hash)
        self.assertIsNone(snapshot.anchor.verified)
        self.assertEqual(snapshot.anchor.reason, "anchor_store_absent")
        self.assertFalse(snapshot.journal.available)
        self.assertIsNone(snapshot.journal.verified)
        self.assertEqual(snapshot.leases, ())
        self.assertEqual(snapshot.drift_heads, ())
        self.assertEqual(snapshot.incidents, 0)
        self.assertEqual(snapshot.near_misses, 0)
        self.assertTrue(snapshot.incident_report_available)
        self.assertIsNotNone(snapshot.incident_report_frozen_at_ns)
        # Design item 5.5: no surface exposes reconciliation state yet.
        self.assertEqual(snapshot.reconciliation_state, "unknown")
        self.assertIsNone(snapshot.reconciliation_since_ns)
        self.assertIsNone(snapshot.last_reconciliation_completed_ns)

    def test_snapshot_carries_only_primitives(self):
        _, _, orchestrator = _kernel()
        lease = _lease()
        evaluation = evaluate_sample(_dying_head_sample())
        snapshot = freeze_observer_snapshot(
            orchestrator,
            deployment_id="deployment-1",
            device_id="unit-1",
            leases=[lease],
            drift_evaluations=[evaluation],
            clock=lambda: CLOCK_NS,
        )
        document = asdict(snapshot)
        # asdict keeps tuples; JSON carries them as arrays -- the
        # round-trip target is the tuple-to-list conversion.
        expected = _as_json_primitives(document)
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        self.assertLessEqual(len(payload.encode("utf-8")), MAX_OBSERVER_SNAPSHOT_BYTES)
        self.assertEqual(json.loads(payload), expected)

    def test_repeated_freeze_is_byte_identical_and_non_mutating(self):
        kernel, state, orchestrator = _kernel()
        with tempfile.TemporaryDirectory() as tmp:
            journal = DurableJournal(Path(tmp) / "journal.jsonl")
            journal.append("o2_drift_evaluation", {"sensor_id": "O2-E04-01"})
            journal_bytes_before = (Path(tmp) / "journal.jsonl").read_bytes()
            audit_before = list(kernel.audit)
            # The incident report is frozen once and supplied, so every
            # input is pinned: a derived report would carry its own
            # wall-clock freeze time (see the next test).
            report = freeze_incident_report(orchestrator)
            first = freeze_observer_snapshot(
                orchestrator,
                journal=journal,
                incident_report=report,
                clock=lambda: CLOCK_NS,
            )
            second = freeze_observer_snapshot(
                orchestrator,
                journal=journal,
                incident_report=report,
                clock=lambda: CLOCK_NS,
            )
            self.assertEqual(
                json.dumps(asdict(first), sort_keys=True),
                json.dumps(asdict(second), sort_keys=True),
            )
            self.assertEqual(list(kernel.audit), audit_before)
            self.assertEqual(
                (Path(tmp) / "journal.jsonl").read_bytes(), journal_bytes_before
            )
            self.assertEqual(
                orchestrator.evidence_snapshot().audit_tip, first.audit_tip
            )

    def test_derived_incident_report_is_the_only_moving_part(self):
        # With no supplied report the freeze derives one, and the derived
        # report carries its own wall-clock freeze time -- so two freezes
        # differ in exactly that one field, and nowhere else.
        _, _, orchestrator = _kernel()
        first = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        second = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        self.assertEqual(first.frozen_at_ns, CLOCK_NS)
        self.assertEqual(second.frozen_at_ns, CLOCK_NS)
        first_doc = asdict(first)
        second_doc = asdict(second)
        self.assertEqual(
            {key: value for key, value in first_doc.items() if key != "incident_report_frozen_at_ns"},
            {key: value for key, value in second_doc.items() if key != "incident_report_frozen_at_ns"},
        )

    def test_freeze_rejects_non_orchestrator_and_bad_inputs(self):
        _, _, orchestrator = _kernel()
        with self.assertRaises(TypeError):
            freeze_observer_snapshot(orchestrator.kernel)
        with self.assertRaises(TypeError):
            freeze_observer_snapshot(orchestrator, leases=[object()])
        with self.assertRaises(TypeError):
            freeze_observer_snapshot(orchestrator, journal=object())
        with self.assertRaises(TypeError):
            freeze_observer_snapshot(orchestrator, drift_evaluations=[object()])
        with self.assertRaises(ValueError):
            freeze_observer_snapshot(orchestrator, deployment_id="")
        with self.assertRaises(ValueError):
            freeze_observer_snapshot(orchestrator, device_ids={"": "unit-1"})
        with self.assertRaises(ValueError):
            freeze_observer_snapshot(orchestrator, clock=lambda: 0)
        naive = _lease(issued_at=datetime(2030, 1, 1))
        with self.assertRaises(ValueError):
            freeze_observer_snapshot(orchestrator, leases=[naive], clock=lambda: CLOCK_NS)

    def test_lease_summary_window_state_and_device_identity(self):
        _, _, orchestrator = _kernel()
        lease = _lease()
        other = _lease(lease_id="lease-2", deployment_id="deployment-2")
        snapshot = freeze_observer_snapshot(
            orchestrator,
            leases=[lease, other],
            device_ids={"deployment-1": "unit-1"},
            clock=lambda: CLOCK_NS,
        )
        self.assertEqual(snapshot.deployment_id, "deployment-1")
        self.assertEqual(snapshot.device_id, "unit-1")
        first, second = snapshot.leases
        self.assertIs(type(first), ObserverLeaseSummary)
        self.assertEqual(first.lease_id, "lease-1")
        self.assertEqual(first.principal, "operator-1")
        self.assertEqual(first.deployment_id, "deployment-1")
        self.assertEqual(first.device_id, "unit-1")
        self.assertEqual(first.safe_fallback, "fans_on")
        self.assertEqual(first.issued_at_ns, int(START.timestamp() * 1_000_000_000))
        # Envelope expires 02:00; frozen at 00:30: 90 minutes remain.
        self.assertEqual(first.window_remaining_ns, 90 * 60 * 1_000_000_000)
        self.assertEqual(first.max_disconnected_ns, 60 * 60 * 1_000_000_000)
        self.assertEqual(first.max_commands, 3)
        self.assertEqual(first.state, "active")
        # Design section 4.6: no device identity supplied for this
        # lease's deployment -- None, never guessed into a device.
        self.assertIsNone(second.device_id)

    def test_expired_lease_reports_expired_with_zero_window(self):
        _, _, orchestrator = _kernel()
        lease = _lease()
        expired_ns = int(
            datetime(2030, 1, 1, 3, 0, tzinfo=timezone.utc).timestamp() * 1_000_000_000
        )
        snapshot = freeze_observer_snapshot(
            orchestrator, leases=[lease], clock=lambda: expired_ns
        )
        (summary,) = snapshot.leases
        self.assertEqual(summary.state, "expired")
        self.assertEqual(summary.window_remaining_ns, 0)

    def test_journal_tip_reports_last_verified_record(self):
        _, _, orchestrator = _kernel()
        with tempfile.TemporaryDirectory() as tmp:
            journal = DurableJournal(Path(tmp) / "journal.jsonl")
            journal.append("mission_started", {"lease_id": "lease-1"})
            evaluation = evaluate_sample(_dying_head_sample())
            journal.append("o2_drift_evaluation", evaluation.to_journal_payload())
            snapshot = freeze_observer_snapshot(
                orchestrator,
                journal=journal,
                deployment_id="deployment-1",
                device_id="unit-1",
                clock=lambda: CLOCK_NS,
            )
            tip = snapshot.journal
            self.assertIs(type(tip), ObserverJournalTip)
            self.assertTrue(tip.available)
            self.assertTrue(tip.verified)
            self.assertIsNone(tip.verification_reason)
            self.assertEqual(tip.sequence, 2)
            self.assertEqual(tip.last_event, "o2_drift_evaluation")
            self.assertEqual(len(tip.last_record_hash), 64)
            self.assertEqual(tip.deployment_id, "deployment-1")
            self.assertEqual(tip.device_id, "unit-1")

    def test_empty_journal_is_available_and_verified_with_no_tip(self):
        _, _, orchestrator = _kernel()
        with tempfile.TemporaryDirectory() as tmp:
            journal = DurableJournal(Path(tmp) / "journal.jsonl")
            snapshot = freeze_observer_snapshot(
                orchestrator, journal=journal, clock=lambda: CLOCK_NS
            )
            self.assertTrue(snapshot.journal.available)
            self.assertTrue(snapshot.journal.verified)
            self.assertIsNone(snapshot.journal.sequence)
            self.assertIsNone(snapshot.journal.last_event)
            self.assertIsNone(snapshot.journal.last_record_hash)

    def test_tampered_journal_fails_closed_with_no_tip(self):
        _, _, orchestrator = _kernel()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            journal = DurableJournal(path)
            journal.append("mission_started", {"lease_id": "lease-1"})
            lines = path.read_text().splitlines()
            tampered = json.loads(lines[0])
            tampered["payload"] = {"lease_id": "lease-forged"}
            path.write_text(json.dumps(tampered) + "\n")
            snapshot = freeze_observer_snapshot(
                orchestrator, journal=journal, clock=lambda: CLOCK_NS
            )
            self.assertTrue(snapshot.journal.available)
            self.assertFalse(snapshot.journal.verified)
            self.assertEqual(
                snapshot.journal.verification_reason, "journal_integrity_failure"
            )
            self.assertIsNone(snapshot.journal.sequence)
            self.assertIsNone(snapshot.journal.last_event)
            self.assertIsNone(snapshot.journal.last_record_hash)

    def test_anchor_store_verified_when_head_matches(self):
        kernel, state, orchestrator = _kernel()
        store = InMemoryAnchorStore()
        anchor_state(state, store, clock=lambda: 5_000_000)
        snapshot = freeze_observer_snapshot(
            orchestrator, anchor_store=store, clock=lambda: CLOCK_NS
        )
        self.assertTrue(snapshot.anchor.available)
        self.assertTrue(snapshot.anchor.verified)
        self.assertIsNone(snapshot.anchor.reason)
        self.assertEqual(snapshot.anchor.anchored_records, len(kernel.audit))
        self.assertEqual(snapshot.anchor.anchors_checked, 1)
        self.assertEqual(snapshot.anchor.head_hash, store.anchors()[-1].head_hash)

    def test_empty_anchor_store_reports_anchor_history_empty(self):
        _, _, orchestrator = _kernel()
        snapshot = freeze_observer_snapshot(
            orchestrator, anchor_store=InMemoryAnchorStore(), clock=lambda: CLOCK_NS
        )
        self.assertTrue(snapshot.anchor.available)
        self.assertFalse(snapshot.anchor.verified)
        self.assertEqual(snapshot.anchor.reason, "anchor_history_empty")
        self.assertIsNone(snapshot.anchor.head_hash)

    def test_forged_anchor_head_fails_verification(self):
        _, _, orchestrator = _kernel()
        store = InMemoryAnchorStore()
        store.append(
            AuditAnchor(
                sequence=0,
                record_count=1,
                head_hash="a" * 64,
                previous_anchor_hash="0" * 64,
                timestamp_ns=5_000_000,
            )
        )
        snapshot = freeze_observer_snapshot(
            orchestrator, anchor_store=store, clock=lambda: CLOCK_NS
        )
        self.assertTrue(snapshot.anchor.available)
        self.assertFalse(snapshot.anchor.verified)
        self.assertEqual(snapshot.anchor.head_hash, "a" * 64)

    def test_signature_summary_unsigned_and_signed(self):
        _, _, unsigned = _kernel()
        snapshot = freeze_observer_snapshot(unsigned, clock=lambda: CLOCK_NS)
        self.assertFalse(snapshot.signatures.signing_enabled)
        self.assertEqual(snapshot.signatures.signed_records, 0)
        self.assertEqual(
            snapshot.signatures.unsigned_records, snapshot.signatures.total_records
        )

        kernel, state, signed = _kernel(signing=True)
        state.append("decision", {"decision": "permit"}, 2_000_001)
        snapshot = freeze_observer_snapshot(signed, clock=lambda: CLOCK_NS)
        self.assertTrue(snapshot.signatures.signing_enabled)
        self.assertEqual(snapshot.signatures.signed_records, 1)
        self.assertEqual(snapshot.signatures.unsigned_records, 0)
        self.assertEqual(snapshot.signatures.total_records, 1)
        self.assertTrue(snapshot.audit_valid)

    def test_drift_head_summary_carries_rates_limits_and_unknowns(self):
        _, _, orchestrator = _kernel()
        evaluation = evaluate_sample(_dying_head_sample())
        self.assertEqual(evaluation.decision, "UNTRUSTED")
        snapshot = freeze_observer_snapshot(
            orchestrator,
            drift_evaluations=[evaluation],
            drift_evaluated_at_ns={"O2-E04-01": CLOCK_NS},
            clock=lambda: CLOCK_NS,
        )
        (head,) = snapshot.drift_heads
        self.assertIs(type(head), ObserverDriftHead)
        self.assertEqual(head.sensor_id, "O2-E04-01")
        self.assertEqual(head.decision, "UNTRUSTED")
        self.assertEqual(head.raw_o2_pct, 18.9)
        self.assertEqual(head.drift_pct_per_hour, -1.4)
        self.assertEqual(head.step_change_pct_per_minute, -1.8)
        self.assertEqual(head.neighbor_median_pct, 20.8)
        self.assertAlmostEqual(head.neighbor_deviation_pct, -1.9)
        self.assertEqual(head.rate_limit_pct_per_hour, 0.25)
        self.assertEqual(head.step_limit_pct_per_minute, 0.50)
        self.assertEqual(head.max_neighbor_deviation_pct, 0.5)
        self.assertEqual(head.age_seconds, 4)
        self.assertEqual(head.last_evaluated_ns, CLOCK_NS)
        # No fan-stop field exists on a drift summary: the monitor never
        # authorizes a fan stop.
        self.assertFalse(hasattr(head, "authorizes_fan_stop"))
        # DriftEvaluation does not carry calibration age: unknown, and
        # the evaluation time is unknown unless the deployment supplies
        # it -- neither is invented.
        self.assertIsNone(head.calibration_age_days)
        without_time = freeze_observer_snapshot(
            orchestrator, drift_evaluations=[evaluation], clock=lambda: CLOCK_NS
        )
        self.assertIsNone(without_time.drift_heads[0].last_evaluated_ns)

    def test_incident_counts_come_from_the_derived_report(self):
        kernel, state, orchestrator = _kernel()
        state.append(
            "permit_rejected",
            {"reason": "permit_intent_mismatch"},
            2_000_001,
        )
        state.append(
            "purchase_consequence_unknown",
            {
                "order_hash": "a" * 64,
                "intent_hash": "b" * 64,
                "permit_hash": "c" * 64,
                "reservation_id": "res-1",
            },
            2_000_002,
        )
        report = freeze_incident_report(orchestrator)
        snapshot = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        self.assertEqual(snapshot.incidents, report.incidents)
        self.assertEqual(snapshot.near_misses, report.near_misses)
        # The snapshot derives its own report, frozen at derivation
        # time -- so its freeze time is the derivation's, not the
        # earlier report's; it can only be at or after it.
        self.assertGreaterEqual(
            snapshot.incident_report_frozen_at_ns, report.observed_at_ns
        )
        self.assertGreaterEqual(snapshot.near_misses, 1)
        self.assertGreaterEqual(snapshot.incidents, 1)

    def test_supplied_incident_report_freeze_time_is_used(self):
        _, _, orchestrator = _kernel()
        report = freeze_incident_report(orchestrator)
        snapshot = freeze_observer_snapshot(
            orchestrator, incident_report=report, clock=lambda: CLOCK_NS
        )
        self.assertEqual(snapshot.incidents, report.incidents)
        self.assertEqual(snapshot.near_misses, report.near_misses)
        self.assertEqual(snapshot.incident_report_frozen_at_ns, report.observed_at_ns)

    def test_export_load_round_trip_is_exact(self):
        _, _, orchestrator = _kernel()
        lease = _lease()
        evaluation = evaluate_sample(_dying_head_sample())
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "observer-snapshot.json"
            exported = export_observer_snapshot(
                orchestrator,
                destination,
                deployment_id="deployment-1",
                device_id="unit-1",
                leases=[lease],
                drift_evaluations=[evaluation],
                clock=lambda: CLOCK_NS,
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            loaded = load_observer_snapshot(destination)
            self.assertEqual(loaded, exported)
            # The file is exactly the canonical serialization.
            self.assertEqual(
                destination.read_text(),
                json.dumps(asdict(exported), sort_keys=True, separators=(",", ":"))
                + "\n",
            )

    def test_export_rejects_relative_and_symlinked_destinations(self):
        _, _, orchestrator = _kernel()
        with self.assertRaises(MCPBoundaryError):
            export_observer_snapshot(orchestrator, "relative.json")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "snapshot.json"
            link_dir = Path(tmp) / "link"
            os.symlink(tmp, link_dir)
            with self.assertRaises(MCPBoundaryError):
                export_observer_snapshot(orchestrator, link_dir / "snapshot.json")

    def test_export_prefights_oversize_before_publishing(self):
        _, _, orchestrator = _kernel()
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "snapshot.json"
            with patch(
                "pulpo.observer_snapshot.MAX_OBSERVER_SNAPSHOT_BYTES", 64
            ):
                with self.assertRaisesRegex(
                    MCPBoundaryError, "observer_snapshot_too_large"
                ):
                    export_observer_snapshot(
                        orchestrator, destination, clock=lambda: CLOCK_NS
                    )
            self.assertFalse(destination.exists())

    def test_load_rejects_malformed_stale_and_wrong_schema(self):
        _, _, orchestrator = _kernel()
        good = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        document = asdict(good)

        def _write(payload, name="snapshot.json"):
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            path = Path(tmp.name) / name
            if isinstance(payload, str):
                path.write_text(payload)
            else:
                path.write_text(json.dumps(payload))
            os.chmod(path, 0o600)
            return path

        cases = {}

        wrong_schema = dict(document, schema="pulpo.observer-snapshot.v99")
        cases["wrong schema"] = wrong_schema

        missing = dict(document)
        del missing["audit_tip"]
        cases["missing field"] = missing

        extra = dict(document, unexpected=1)
        cases["extra field"] = extra

        bad_hash = dict(document, policy_hash="not-a-hash")
        cases["bad policy hash"] = bad_hash

        bad_count = dict(document, audit_records=-1)
        cases["negative count"] = bad_count

        bad_reconciliation = dict(document, reconciliation_state="reconciling")
        cases["unreported reconciliation state"] = bad_reconciliation

        bad_nested = json.loads(json.dumps(document))
        bad_nested["signatures"]["signed_records"] = -1
        cases["bad nested count"] = bad_nested

        bad_lease = json.loads(json.dumps(document))
        bad_lease["leases"] = [{"lease_id": "lease-1"}]
        cases["truncated lease"] = bad_lease

        bad_drift = json.loads(json.dumps(document))
        bad_drift["drift_heads"] = [
            {
                "sensor_id": "O2-E04-01",
                "decision": "MAYBE",
                "reasons": [],
                "raw_o2_pct": 20.9,
                "drift_pct_per_hour": 0.0,
                "step_change_pct_per_minute": 0.0,
                "neighbor_median_pct": 20.8,
                "neighbor_deviation_pct": 0.0,
                "rate_limit_pct_per_hour": 0.25,
                "step_limit_pct_per_minute": 0.5,
                "max_neighbor_deviation_pct": 0.5,
                "max_reading_age_seconds": 30.0,
                "age_seconds": 4,
                "calibration_age_days": None,
                "retrust_soak_minutes": 0.0,
                "retrust_soak_required_minutes": 30.0,
                "last_evaluated_ns": None,
            }
        ]
        cases["unknown drift decision"] = bad_drift

        for label, payload in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    load_observer_snapshot(_write(payload))

        with self.assertRaises(MCPBoundaryError):
            load_observer_snapshot(_write("{not json"))
        with self.assertRaises(MCPBoundaryError):
            load_observer_snapshot(_write(json.dumps(["not", "a", "dict"])))

    def test_load_rejects_oversize_file(self):
        _, _, orchestrator = _kernel()
        good = freeze_observer_snapshot(orchestrator, clock=lambda: CLOCK_NS)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(asdict(good)))
            os.chmod(path, 0o600)
            with patch("pulpo.observer_snapshot.MAX_OBSERVER_SNAPSHOT_BYTES", 64):
                with self.assertRaises(MCPBoundaryError):
                    load_observer_snapshot(path)


if __name__ == "__main__":
    unittest.main()
