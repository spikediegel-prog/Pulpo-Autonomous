"""Drift ingestion feed (Control Center design v0, item 5.4).

The sensor-app side of the drift monitor: a feed that accepts head
samples from a deployment-supplied source, runs them through the
existing ``DriftMonitor``, and appends each evaluation to the
``DurableJournal`` as an ``o2_drift_evaluation`` event.

Adversarial note: the feed is the one place evaluations become
evidence, so every test below pins what it must never do as well as
what it does — no invented samples, no driver, no permit, no fan/PLC
effect, no second sensor plane. A feed with no samples produces no
evaluations, and a tampered journal fails closed instead of silently
dropping an evaluation.
"""

from __future__ import annotations

import ast
import math
import tempfile
import unittest
from pathlib import Path

from core import DurableJournal
from core.drift import JOURNAL_EVENT, O2HeadSample
from core.drift_feed import DriftFeed, DriftSnapshotInputs
from pulpo import GovernanceKernel, Policy, PulpoOrchestrator
from pulpo.observer_snapshot import freeze_observer_snapshot
from pulpo.state import InMemoryKernelState

KERNEL_SECRET = "drift-feed-test-kernel-secret".encode("utf-8")
CLOCK_NS = 1_800_000_000_000_000_000


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


def _breaching_sample(sensor_id="O2-E04-01", **overrides):
    values = {
        "sensor_id": sensor_id,
        "raw_o2_pct": 20.8,
        "drift_pct_per_hour": -0.3,
        "step_change_pct_per_minute": 0.0,
        "neighbor_median_pct": 20.8,
        "age_seconds": 4,
        "calibration_age_days": 5,
        "reading_compensated": True,
    }
    values.update(overrides)
    return O2HeadSample(**values)


def _clean_sample(sensor_id="O2-E04-01"):
    return O2HeadSample(
        sensor_id=sensor_id,
        raw_o2_pct=20.8,
        drift_pct_per_hour=0.0,
        step_change_pct_per_minute=0.0,
        neighbor_median_pct=20.8,
        age_seconds=4,
        calibration_age_days=5,
        reading_compensated=True,
    )


class DriftIngestionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.journal_path = Path(self._tmp.name) / "journal.jsonl"
        self.journal = DurableJournal(self.journal_path)

    def _feed(self, **kwargs):
        kwargs.setdefault("clock", lambda: CLOCK_NS)
        return DriftFeed(self.journal, **kwargs)

    def test_dying_sensor_end_to_end(self):
        feed = self._feed()
        evaluation = feed.ingest(_dying_head_sample())
        self.assertEqual(evaluation.decision, "UNTRUSTED")
        self.assertIn("accuracy_out_of_spec", evaluation.reasons)
        records = self.journal.read()
        self.assertEqual(len(records), 1)
        (record,) = records
        self.assertEqual(record.event, JOURNAL_EVENT)
        self.assertEqual(record.payload["sensor_id"], "O2-E04-01")
        self.assertEqual(record.payload["decision"], "UNTRUSTED")
        self.assertFalse(record.payload["authorizes_fan_stop"])
        self.assertFalse(record.payload["sensor_triggered_stop_allowed"])
        # The feed supplies the snapshot inputs §5.1 left unknown.
        inputs = feed.snapshot_inputs()
        self.assertIs(type(inputs), DriftSnapshotInputs)
        self.assertEqual([item.sensor_id for item in inputs.evaluations], ["O2-E04-01"])
        self.assertEqual(inputs.evaluated_at_ns, {"O2-E04-01": CLOCK_NS})
        self.assertEqual(inputs.calibration_age_days, {"O2-E04-01": 5})

    def test_no_samples_means_no_evaluations_and_untouched_journal(self):
        feed = self._feed()
        self.assertEqual(feed.latest_evaluations(), ())
        self.assertEqual(feed.head_ids(), ())
        self.assertEqual(feed.evaluated_at_ns(), {})
        self.assertEqual(feed.calibration_age_days(), {})
        inputs = feed.snapshot_inputs()
        self.assertEqual(inputs.evaluations, ())
        self.assertEqual(inputs.evaluated_at_ns, {})
        self.assertEqual(inputs.calibration_age_days, {})
        # The journal file is never even created: no samples, no writes.
        self.assertFalse(self.journal_path.exists())
        self.assertEqual(self.journal.read(), [])

    def test_invalid_stale_and_calibrating_samples_are_unknown_not_crashes(self):
        feed = self._feed()
        invalid = feed.ingest(_breaching_sample(raw_o2_pct=math.nan))
        self.assertEqual(invalid.decision, "UNKNOWN")
        self.assertIn("invalid_reading", invalid.reasons)
        stale = feed.ingest(_breaching_sample(age_seconds=31))
        self.assertEqual(stale.decision, "UNKNOWN")
        self.assertIn("reading_stale", stale.reasons)
        calibrating = feed.ingest(_breaching_sample(calibrating=True))
        self.assertEqual(calibrating.decision, "UNKNOWN")
        self.assertIn("calibrating", calibrating.reasons)
        # UNKNOWN breaks consecutiveness but never crashes the feed: a
        # clean sample afterwards is still TRUSTED.
        self.assertEqual(feed.ingest(_clean_sample()).decision, "TRUSTED")
        records = self.journal.read()
        self.assertEqual(len(records), 4)
        self.assertTrue(all(record.event == JOURNAL_EVENT for record in records))

    def test_repeated_identical_samples_are_each_recorded_and_persist(self):
        """One sample -> one evaluation -> one journal event, no dedup.

        The monitor's persistence rule (3 consecutive breaching samples)
        *requires* each sample to be recorded: skipping "duplicates"
        would break the promotion from SUSPECT to UNTRUSTED.
        """
        feed = self._feed()
        first = feed.ingest(_breaching_sample())
        second = feed.ingest(_breaching_sample())
        third = feed.ingest(_breaching_sample())
        self.assertEqual(first.decision, "SUSPECT")
        self.assertEqual(first.breach_streak, 1)
        self.assertEqual(second.decision, "SUSPECT")
        self.assertEqual(second.breach_streak, 2)
        self.assertEqual(third.decision, "UNTRUSTED")
        self.assertIn("breach_persisted", third.reasons)
        records = self.journal.read()
        self.assertEqual(len(records), 3)
        self.assertEqual(
            [record.payload["decision"] for record in records],
            ["SUSPECT", "SUSPECT", "UNTRUSTED"],
        )

    def test_ingestion_writes_only_drift_evaluations_to_the_journal(self):
        feed = self._feed()
        feed.ingest(_dying_head_sample())
        feed.ingest(_clean_sample(sensor_id="O2-E04-02"))
        records = self.journal.read()
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record.event == JOURNAL_EVENT for record in records))
        # No permit, no fan/PLC effect, no audit write: the journal holds
        # drift evaluations and nothing else.
        self.assertTrue(
            all(
                record.payload["authorizes_fan_stop"] is False
                for record in records
            )
        )

    def test_feed_imports_no_driver_no_kernel_no_observer_code(self):
        source = Path(__file__).parent.parent / "core" / "drift_feed.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        forbidden = {
            "pulpo", "observer", "socket", "serial", "requests",
            "mqtt", "subprocess", "urllib", "pymodbus", "opcua",
        }
        self.assertEqual(imported & forbidden, set())

    def test_tampered_journal_fails_closed_without_bookkeeping(self):
        feed = self._feed()
        first = feed.ingest(_clean_sample())
        self.assertEqual(first.decision, "TRUSTED")
        # Tamper with the journal file: flip a payload value.
        lines = self.journal_path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"TRUSTED"', '"SUSPECT"')
        self.journal_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "journal_integrity_failure"):
            feed.ingest(_clean_sample())
        # The unevidenced evaluation is not reported as evaluated: the
        # feed's bookkeeping still reflects only the first sample.
        self.assertEqual(feed.latest_evaluations(), (first,))
        self.assertEqual(feed.evaluated_at_ns(), {"O2-E04-01": CLOCK_NS})

    def test_recalibration_requires_known_head_and_soak_retrusts(self):
        feed = self._feed()
        for _ in range(3):
            feed.ingest(_breaching_sample())
        self.assertEqual(feed.latest_evaluations()[0].decision, "UNTRUSTED")
        with self.assertRaisesRegex(ValueError, "drift_feed_unknown_sensor"):
            feed.record_recalibration("O2-NOPE-99")
        feed.record_recalibration("O2-E04-01")
        # 10 minutes of clean soak per sample; the latch clears at 30.
        first_soak = feed.ingest(_clean_sample(), elapsed_seconds=600)
        self.assertEqual(first_soak.decision, "UNTRUSTED")
        self.assertAlmostEqual(first_soak.retrust_soak_minutes, 10)
        second_soak = feed.ingest(_clean_sample(), elapsed_seconds=600)
        self.assertEqual(second_soak.decision, "UNTRUSTED")
        self.assertAlmostEqual(second_soak.retrust_soak_minutes, 20)
        retrusted = feed.ingest(_clean_sample(), elapsed_seconds=600)
        self.assertEqual(retrusted.decision, "TRUSTED")
        self.assertAlmostEqual(retrusted.retrust_soak_minutes, 30)

    def test_feed_rejects_bad_inputs(self):
        feed = self._feed()
        with self.assertRaises(TypeError):
            DriftFeed(object())
        with self.assertRaises(TypeError):
            feed.ingest(object())
        with self.assertRaisesRegex(ValueError, "drift_feed_sensor_id_invalid"):
            feed.ingest(_breaching_sample(sensor_id=""))
        with self.assertRaisesRegex(ValueError, "drift_feed_sensor_id_invalid"):
            feed.record_recalibration("")
        with self.assertRaises(ValueError):
            feed.ingest(_clean_sample(), elapsed_seconds=-1)
        with self.assertRaises(ValueError):
            feed.ingest(_clean_sample(), elapsed_seconds=math.inf)
        bad_clock = DriftFeed(self.journal, clock=lambda: 0)
        with self.assertRaisesRegex(ValueError, "drift_feed_clock_invalid"):
            bad_clock.ingest(_clean_sample())

    def test_sample_without_calibration_age_leaves_mapping_absent(self):
        feed = self._feed()
        evaluation = feed.ingest(_breaching_sample(calibration_age_days=None))
        self.assertEqual(evaluation.decision, "SUSPECT")
        self.assertIn("calibration_age_unknown", evaluation.reasons)
        self.assertEqual(feed.calibration_age_days(), {})
        # A later sample that reports an age supplies it.
        feed.ingest(_breaching_sample(calibration_age_days=7))
        self.assertEqual(feed.calibration_age_days(), {"O2-E04-01": 7})

    def test_snapshot_wiring_carries_time_and_calibration_age(self):
        feed = self._feed()
        feed.ingest(_dying_head_sample())
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=KERNEL_SECRET,
            state=state,
            clock=lambda: 2_000_000,
        )
        orchestrator = PulpoOrchestrator(kernel)
        inputs = feed.snapshot_inputs()
        snapshot = freeze_observer_snapshot(
            orchestrator,
            drift_evaluations=list(inputs.evaluations),
            drift_evaluated_at_ns=inputs.evaluated_at_ns,
            drift_calibration_age_days=inputs.calibration_age_days,
            clock=lambda: CLOCK_NS,
        )
        (head,) = snapshot.drift_heads
        self.assertEqual(head.sensor_id, "O2-E04-01")
        self.assertEqual(head.decision, "UNTRUSTED")
        self.assertEqual(head.calibration_age_days, 5)
        self.assertEqual(head.last_evaluated_ns, CLOCK_NS)

    def test_snapshot_calibration_age_mapping_validation(self):
        feed = self._feed()
        feed.ingest(_dying_head_sample())
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=KERNEL_SECRET,
            state=state,
            clock=lambda: 2_000_000,
        )
        orchestrator = PulpoOrchestrator(kernel)
        inputs = feed.snapshot_inputs()
        for bad in (
            {"O2-E04-01": -1},
            {"O2-E04-01": math.nan},
            {"O2-E04-01": True},
            {"": 5},
            ["not-a-mapping"],
        ):
            with self.assertRaises(ValueError):
                freeze_observer_snapshot(
                    orchestrator,
                    drift_evaluations=list(inputs.evaluations),
                    drift_calibration_age_days=bad,
                    clock=lambda: CLOCK_NS,
                )
        # Age zero (just calibrated) is a real value, not Unknown.
        zero = freeze_observer_snapshot(
            orchestrator,
            drift_evaluations=list(inputs.evaluations),
            drift_calibration_age_days={"O2-E04-01": 0},
            clock=lambda: CLOCK_NS,
        )
        self.assertEqual(zero.drift_heads[0].calibration_age_days, 0)
        # An entry for a head the snapshot does not carry is ignored.
        stale = freeze_observer_snapshot(
            orchestrator,
            drift_evaluations=list(inputs.evaluations),
            drift_calibration_age_days={"O2-NOPE-99": 3},
            clock=lambda: CLOCK_NS,
        )
        self.assertIsNone(stale.drift_heads[0].calibration_age_days)

    def _snapshot(self, feed, **overrides):
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=KERNEL_SECRET,
            state=state,
            clock=lambda: 2_000_000,
        )
        orchestrator = PulpoOrchestrator(kernel)
        inputs = feed.snapshot_inputs()
        return freeze_observer_snapshot(
            orchestrator,
            drift_evaluations=list(inputs.evaluations),
            drift_evaluated_at_ns=inputs.evaluated_at_ns,
            drift_calibration_age_days=inputs.calibration_age_days,
            drift_last_calibration_ns=inputs.last_calibration_ns,
            drift_calibration_interval_days=inputs.calibration_interval_days,
            drift_next_calibration_due_ns=inputs.next_calibration_due_ns,
            drift_rated_life_expiry_ns=inputs.rated_life_expiry_ns,
            drift_span_check_passed=inputs.span_check_passed,
            drift_span_check_ns=inputs.span_check_ns,
            clock=lambda: CLOCK_NS,
            **overrides,
        )

    def test_calibration_provenance_is_recorded_and_supplied(self):
        feed = self._feed()
        feed.ingest(_dying_head_sample())
        feed.record_calibration_provenance(
            "O2-E04-01",
            last_calibration_ns=CLOCK_NS - 5 * 86_400 * 1_000_000_000,
            calibration_interval_days=21,
            rated_life_expiry_ns=CLOCK_NS + 365 * 86_400 * 1_000_000_000,
        )
        feed.record_span_check(
            "O2-E04-01", passed=True, checked_at_ns=CLOCK_NS - 5 * 86_400 * 1_000_000_000
        )
        inputs = feed.snapshot_inputs()
        self.assertEqual(
            inputs.last_calibration_ns,
            {"O2-E04-01": CLOCK_NS - 5 * 86_400 * 1_000_000_000},
        )
        self.assertEqual(inputs.calibration_interval_days, {"O2-E04-01": 21})
        self.assertEqual(inputs.next_calibration_due_ns, {})
        self.assertEqual(
            inputs.rated_life_expiry_ns,
            {"O2-E04-01": CLOCK_NS + 365 * 86_400 * 1_000_000_000},
        )
        self.assertEqual(inputs.span_check_passed, {"O2-E04-01": True})
        self.assertEqual(
            inputs.span_check_ns,
            {"O2-E04-01": CLOCK_NS - 5 * 86_400 * 1_000_000_000},
        )
        # No supplied deadline: the freeze derives last + interval.
        (head,) = self._snapshot(feed).drift_heads
        self.assertEqual(head.decision, "UNTRUSTED")
        self.assertEqual(
            head.last_calibration_ns, CLOCK_NS - 5 * 86_400 * 1_000_000_000
        )
        self.assertEqual(head.calibration_interval_days, 21)
        self.assertEqual(
            head.next_calibration_due_ns,
            CLOCK_NS + 16 * 86_400 * 1_000_000_000,
        )
        self.assertEqual(
            head.rated_life_expiry_ns,
            CLOCK_NS + 365 * 86_400 * 1_000_000_000,
        )
        self.assertIs(head.span_check_passed, True)
        self.assertEqual(
            head.span_check_ns, CLOCK_NS - 5 * 86_400 * 1_000_000_000
        )

    def test_calibration_provenance_absent_means_unknown_not_guessed(self):
        feed = self._feed()
        feed.ingest(_dying_head_sample())
        inputs = feed.snapshot_inputs()
        self.assertEqual(inputs.last_calibration_ns, {})
        self.assertEqual(inputs.calibration_interval_days, {})
        self.assertEqual(inputs.next_calibration_due_ns, {})
        self.assertEqual(inputs.rated_life_expiry_ns, {})
        self.assertEqual(inputs.span_check_passed, {})
        self.assertEqual(inputs.span_check_ns, {})
        (head,) = self._snapshot(feed).drift_heads
        self.assertIsNone(head.last_calibration_ns)
        self.assertIsNone(head.calibration_interval_days)
        self.assertIsNone(head.next_calibration_due_ns)
        self.assertIsNone(head.rated_life_expiry_ns)
        self.assertIsNone(head.span_check_passed)
        self.assertIsNone(head.span_check_ns)

    def test_calibration_provenance_rejects_contradictory_input(self):
        feed = self._feed()
        feed.ingest(_clean_sample())
        with self.assertRaisesRegex(ValueError, "drift_feed_sensor_id_invalid"):
            feed.record_calibration_provenance("")
        with self.assertRaisesRegex(ValueError, "drift_feed_sensor_id_invalid"):
            feed.record_span_check("", passed=True, checked_at_ns=CLOCK_NS)
        for bad in (
            {"last_calibration_ns": -1},
            {"last_calibration_ns": 1.5},
            {"last_calibration_ns": True},
            {"calibration_interval_days": 0},
            {"calibration_interval_days": -21},
            {"calibration_interval_days": math.nan},
            {"calibration_interval_days": math.inf},
            {"calibration_interval_days": True},
            {"rated_life_expiry_ns": -1},
            {"rated_life_expiry_ns": 1.5},
            {"next_calibration_due_ns": -1},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    feed.record_calibration_provenance("O2-E04-01", **bad)
        # A deadline before the last calibration is contradictory,
        # whichever order the two facts arrive in.
        feed.record_calibration_provenance(
            "O2-E04-01", last_calibration_ns=CLOCK_NS
        )
        with self.assertRaisesRegex(
            ValueError, "drift_feed_calibration_due_invalid"
        ):
            feed.record_calibration_provenance(
                "O2-E04-01", next_calibration_due_ns=CLOCK_NS - 1
            )
        other = self._feed()
        other.ingest(_clean_sample())
        other.record_calibration_provenance(
            "O2-E04-01", next_calibration_due_ns=CLOCK_NS
        )
        with self.assertRaisesRegex(
            ValueError, "drift_feed_calibration_due_invalid"
        ):
            other.record_calibration_provenance(
                "O2-E04-01", last_calibration_ns=CLOCK_NS + 1
            )
        # A span check is a result AND a time: each is validated.
        with self.assertRaisesRegex(
            ValueError, "drift_feed_span_check_passed_invalid"
        ):
            feed.record_span_check("O2-E04-01", passed="yes", checked_at_ns=CLOCK_NS)
        for bad_ns in (-1, 1.5, True):
            with self.subTest(bad_ns=bad_ns):
                with self.assertRaises(ValueError):
                    feed.record_span_check(
                        "O2-E04-01", passed=True, checked_at_ns=bad_ns
                    )
        # Nothing was stored by the rejected calls.
        self.assertEqual(feed.last_calibration_ns(), {"O2-E04-01": CLOCK_NS})
        self.assertEqual(feed.span_check_passed(), {})
        self.assertEqual(feed.span_check_ns(), {})

    def test_sample_span_check_flag_does_not_write_provenance(self):
        # A sample's span_check_passed flag affects its evaluation but
        # carries no span-check time, so it must not write provenance:
        # a result without a time would violate both-or-neither.
        feed = self._feed()
        passed = feed.ingest(_clean_sample())
        self.assertEqual(passed.decision, "TRUSTED")
        self.assertEqual(feed.span_check_passed(), {})
        self.assertEqual(feed.span_check_ns(), {})
        failed = feed.ingest(_breaching_sample(span_check_passed=False))
        self.assertEqual(failed.decision, "UNTRUSTED")
        self.assertIn("span_check_failed", failed.reasons)
        self.assertEqual(feed.span_check_passed(), {})
        self.assertEqual(feed.span_check_ns(), {})

    def test_provenance_before_first_sample_is_held_then_applied(self):
        feed = self._feed()
        feed.record_calibration_provenance(
            "O2-E04-01",
            last_calibration_ns=CLOCK_NS - 5 * 86_400 * 1_000_000_000,
            calibration_interval_days=21,
        )
        self.assertEqual(
            feed.last_calibration_ns(),
            {"O2-E04-01": CLOCK_NS - 5 * 86_400 * 1_000_000_000},
        )
        # No evaluations yet: the snapshot has no drift heads, and the
        # provenance entry for an unevaluated head is ignored, not
        # invented into a head.
        self.assertEqual(self._snapshot(feed).drift_heads, ())
        feed.ingest(_clean_sample())
        (head,) = self._snapshot(feed).drift_heads
        self.assertEqual(
            head.last_calibration_ns, CLOCK_NS - 5 * 86_400 * 1_000_000_000
        )
        self.assertEqual(head.calibration_interval_days, 21)
        self.assertEqual(
            head.next_calibration_due_ns,
            CLOCK_NS + 16 * 86_400 * 1_000_000_000,
        )

    def test_fresh_calibration_is_a_real_value_not_unknown(self):
        feed = self._feed()
        feed.ingest(_breaching_sample(calibration_age_days=0))
        feed.record_calibration_provenance(
            "O2-E04-01",
            last_calibration_ns=CLOCK_NS,
            calibration_interval_days=21,
        )
        (head,) = self._snapshot(feed).drift_heads
        self.assertEqual(head.calibration_age_days, 0)
        self.assertEqual(head.last_calibration_ns, CLOCK_NS)
        self.assertEqual(
            head.next_calibration_due_ns,
            CLOCK_NS + 21 * 86_400 * 1_000_000_000,
        )

    def test_supplied_deadline_wins_when_consistent(self):
        feed = self._feed()
        feed.ingest(_clean_sample())
        feed.record_calibration_provenance(
            "O2-E04-01",
            last_calibration_ns=CLOCK_NS - 5 * 86_400 * 1_000_000_000,
            calibration_interval_days=21,
            # The maintenance schedule moved the deadline later than
            # last + interval; the supplied deadline is authoritative.
            next_calibration_due_ns=CLOCK_NS + 30 * 86_400 * 1_000_000_000,
        )
        (head,) = self._snapshot(feed).drift_heads
        self.assertEqual(
            head.next_calibration_due_ns,
            CLOCK_NS + 30 * 86_400 * 1_000_000_000,
        )


if __name__ == "__main__":
    unittest.main()
