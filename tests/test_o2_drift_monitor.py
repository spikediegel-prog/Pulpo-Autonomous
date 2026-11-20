"""Tests for the O2 drift-rate monitor (``core/drift.py``).

Design source: design file Appendices C, D, E
(``~/workspace/goals/pulpo-ai-governance-layer/files/pulpo-autonomous-mine-ventilation-o2.md``).

The monitor is an observer/evaluator ONLY, mode SHADOW_ADVISORY:
advisory only, no permit, no effect, no fan/PLC write. It feeds the
sensor-health gate in Rule 1 as an UNKNOWN-producing claim, and UNKNOWN
means fans ON. Nothing here authorizes a fan stop.
"""

import math
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core import (
    JOURNAL_EVENT,
    SUSPECT,
    TRUSTED,
    UNKNOWN,
    UNTRUSTED,
    DriftMonitor,
    DurableJournal,
    O2HeadSample,
    evaluate_sample,
)


def _sample(**overrides):
    values = {
        "sensor_id": "O2-E04-01",
        "raw_o2_pct": 20.8,
        "drift_pct_per_hour": 0.0,
        "step_change_pct_per_minute": 0.0,
        "neighbor_median_pct": 20.8,
        "age_seconds": 4,
        "fault_code": None,
        "calibrating": False,
        "calibration_age_days": 5,
        "rated_life_expired": False,
        "span_check_passed": True,
        "accuracy_within_spec": True,
        "reading_compensated": True,
        "airflow_active": True,
        "pump_running": True,
        "personnel_in_zone": True,
    }
    values.update(overrides)
    return O2HeadSample(**values)


def _example_sample(**overrides):
    """Appendix C, section C1 evaluation input example."""
    values = {
        "raw_o2_pct": 18.9,
        "drift_pct_per_hour": -1.4,
        "step_change_pct_per_minute": -1.8,
        "neighbor_median_pct": 20.8,
        "age_seconds": 4,
        "fault_code": None,
        "calibrating": False,
        "accuracy_within_spec": False,
    }
    values.update(overrides)
    return _sample(**values)


class DriftMonitorTests(unittest.TestCase):
    def test_example_o2_e04_01_is_untrusted(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_example_sample())
        self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertEqual(evaluation.mode, "SHADOW_ADVISORY")
        self.assertFalse(evaluation.authorizes_fan_stop)
        self.assertFalse(evaluation.sensor_triggered_stop_allowed)
        self.assertTrue(evaluation.personnel_underground_blocks_stop)
        self.assertTrue(evaluation.vote_counts_as_unknown)
        self.assertEqual(evaluation.confidence, 0.0)
        for reason in (
            "accuracy_out_of_spec",
            "drift_rate_exceeded",
            "step_change_exceeded",
            "neighbor_deviation_exceeded",
        ):
            self.assertIn(reason, evaluation.reasons)

    def test_example_drift_alone_needs_persistence(self):
        # Same readings, but the head itself reports in-spec: the drift,
        # step, and deviation breaches must persist before UNTRUSTED.
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _example_sample(accuracy_within_spec=True)
        self.assertEqual(monitor.observe(sample).decision, SUSPECT)
        self.assertEqual(monitor.observe(sample).decision, SUSPECT)
        evaluation = monitor.observe(sample)
        self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertIn("breach_persisted", evaluation.reasons)
        self.assertEqual(evaluation.breach_streak, 3)

    def test_steady_20_4_with_neighbor_deviation(self):
        # Zero slope passes both drift checks, but 20.4% against a 20.9%
        # neighbor median is 0.5% out — more than double the AS 2290.3
        # ±0.2% tolerance. The deviation check must catch it.
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _sample(raw_o2_pct=20.4, neighbor_median_pct=20.9)
        first = monitor.observe(sample)
        self.assertEqual(first.decision, SUSPECT)
        self.assertIn("neighbor_deviation_exceeded", first.reasons)
        self.assertNotIn("drift_rate_exceeded", first.reasons)
        self.assertNotIn("step_change_exceeded", first.reasons)
        monitor.observe(sample)
        self.assertEqual(monitor.observe(sample).decision, UNTRUSTED)

    def test_single_sample_breach_does_not_flip(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(drift_pct_per_hour=-1.4))
        self.assertEqual(evaluation.decision, SUSPECT)
        self.assertEqual(evaluation.breach_streak, 1)
        self.assertTrue(evaluation.vote_counts_as_unknown)

    def test_breach_duration_60s_flips(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _sample(drift_pct_per_hour=-1.4)
        self.assertEqual(monitor.observe(sample, elapsed_seconds=30).decision, SUSPECT)
        evaluation = monitor.observe(sample, elapsed_seconds=30)
        self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertGreaterEqual(evaluation.breach_duration_seconds, 60)

    def test_false_high_drift_flagged_by_absolute_value(self):
        # A false-high drift is rarer but worse: it can mask a real
        # deficiency. Limits apply to |rate|, so +1.4%/hr breaches.
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _sample(drift_pct_per_hour=+1.4)
        self.assertEqual(monitor.observe(sample).decision, SUSPECT)
        monitor.observe(sample)
        self.assertEqual(monitor.observe(sample).decision, UNTRUSTED)

    def test_overdue_calibration_is_untrusted_immediately(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(calibration_age_days=22))
        self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertIn("calibration_overdue", evaluation.reasons)

    def test_rated_life_expired_is_untrusted_immediately(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(rated_life_expired=True))
        self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertIn("rated_life_expired", evaluation.reasons)

    def test_failed_span_check_is_untrusted_immediately(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(span_check_passed=False))
        self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertIn("span_check_failed", evaluation.reasons)

    def test_retrust_requires_recalibration_and_soak(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        breaching = _sample(drift_pct_per_hour=-1.4)
        for _ in range(3):
            monitor.observe(breaching)
        self.assertTrue(monitor.is_untrusted)

        # A single good reading does not re-admit the head.
        good = _sample()
        self.assertEqual(monitor.observe(good).decision, UNTRUSTED)
        self.assertTrue(monitor.is_untrusted)

        # Recalibration starts the soak, but 29 minutes is not enough.
        monitor.record_recalibration()
        for _ in range(29):
            evaluation = monitor.observe(good, elapsed_seconds=60)
            self.assertEqual(evaluation.decision, UNTRUSTED)
        self.assertTrue(monitor.is_untrusted)

        # The 30th minute completes the soak.
        evaluation = monitor.observe(good, elapsed_seconds=60)
        self.assertEqual(evaluation.decision, TRUSTED)
        self.assertFalse(monitor.is_untrusted)

    def test_breach_during_soak_invalidates_recalibration(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        breaching = _sample(drift_pct_per_hour=-1.4)
        for _ in range(3):
            monitor.observe(breaching)
        monitor.record_recalibration()
        good = _sample()
        for _ in range(15):
            monitor.observe(good, elapsed_seconds=60)
        # A breach during the soak: soak resets and a new
        # recalibration is required — good readings alone no longer
        # re-admit the head, even for a full 30 minutes.
        self.assertEqual(monitor.observe(breaching).decision, UNTRUSTED)
        for _ in range(30):
            self.assertEqual(
                monitor.observe(good, elapsed_seconds=60).decision, UNTRUSTED
            )
        monitor.record_recalibration()
        for _ in range(29):
            monitor.observe(good, elapsed_seconds=60)
        self.assertEqual(monitor.observe(good, elapsed_seconds=60).decision, TRUSTED)

    def test_stale_reading_is_unknown(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(age_seconds=31))
        self.assertEqual(evaluation.decision, UNKNOWN)
        self.assertIn("reading_stale", evaluation.reasons)
        self.assertTrue(evaluation.vote_counts_as_unknown)

    def test_invalid_reading_is_unknown(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(raw_o2_pct=math.nan))
        self.assertEqual(evaluation.decision, UNKNOWN)
        self.assertIn("invalid_reading", evaluation.reasons)

    def test_calibrating_head_is_unknown(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample(calibrating=True))
        self.assertEqual(evaluation.decision, UNKNOWN)
        self.assertIn("calibrating", evaluation.reasons)

    def test_uncompensated_drift_capped_at_suspect(self):
        # A barometric swing moves an uncompensated reading by a few
        # tenths of a percent, so drift/step alone are inconclusive.
        # They stay SUSPECT and never promote on drift/step.
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _sample(drift_pct_per_hour=-1.4, reading_compensated=False)
        for _ in range(3):
            evaluation = monitor.observe(sample)
            self.assertEqual(evaluation.decision, SUSPECT)
        self.assertIn(
            "uncompensated_reading_barometric_swing_possible", evaluation.reasons
        )
        self.assertEqual(evaluation.breach_streak, 0)

    def test_uncompensated_deviation_still_counts(self):
        # Neighbors share the same barometric pressure, so a deviation
        # against the neighbor median is pressure independent.
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _sample(
            raw_o2_pct=20.4, neighbor_median_pct=20.9, reading_compensated=False
        )
        monitor.observe(sample)
        monitor.observe(sample)
        self.assertEqual(monitor.observe(sample).decision, UNTRUSTED)

    def test_fault_code_is_suspect_then_untrusted(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        sample = _sample(fault_code="cell_fault")
        self.assertEqual(monitor.observe(sample).decision, SUSPECT)
        monitor.observe(sample)
        self.assertEqual(monitor.observe(sample).decision, UNTRUSTED)

    def test_good_head_is_trusted(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample())
        self.assertEqual(evaluation.decision, TRUSTED)
        self.assertEqual(evaluation.reasons, ())
        self.assertFalse(evaluation.vote_counts_as_unknown)
        self.assertEqual(evaluation.confidence, 1.0)

    def test_sensor_mismatch_rejected(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        with self.assertRaises(ValueError):
            monitor.observe(_sample(sensor_id="O2-E04-02"))

    def test_evaluate_sample_is_stateless(self):
        sample = _sample(drift_pct_per_hour=-1.4)
        first = evaluate_sample(sample)
        second = evaluate_sample(sample)
        self.assertEqual(first.decision, SUSPECT)
        self.assertEqual(first, second)

    def test_journal_payload_is_reproducible(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_example_sample())
        payload = evaluation.to_journal_payload()
        self.assertEqual(payload["decision"], UNTRUSTED)
        self.assertEqual(payload["readings"]["raw_o2_pct"], 18.9)
        self.assertEqual(payload["readings"]["drift_pct_per_hour"], -1.4)
        self.assertEqual(payload["thresholds_applied"]["rate_limit_pct_per_hour"], 0.25)
        self.assertEqual(payload["thresholds_applied"]["step_limit_pct_per_minute"], 0.50)
        self.assertEqual(payload["corroboration"]["neighbor_agreement"], False)
        self.assertTrue(payload["corroboration"]["airflow_active"])
        self.assertTrue(payload["corroboration"]["personnel_in_zone"])
        self.assertFalse(payload["authorizes_fan_stop"])
        self.assertFalse(payload["sensor_triggered_stop_allowed"])

        with TemporaryDirectory() as tmp:
            journal = DurableJournal(Path(tmp) / "journal.jsonl")
            record = journal.append(JOURNAL_EVENT, payload)
            self.assertEqual(record.event, JOURNAL_EVENT)
            read_back = journal.read(verify=True)
            self.assertEqual(len(read_back), 1)
            self.assertEqual(read_back[0].payload, payload)

        observation = evaluation.to_observation()
        self.assertEqual(observation.source, "O2-E04-01")
        self.assertEqual(observation.state, "untrusted")
        self.assertEqual(observation.confidence, 0.0)

    def test_sensor_health_fields_follow_sensor_health_shape(self):
        monitor = DriftMonitor(sensor_id="O2-E04-01")
        evaluation = monitor.observe(_sample())
        fields = evaluation.to_sensor_health_fields()
        self.assertEqual(fields["confidence"], 1.0)
        self.assertTrue(fields["independent_agreement"])
        self.assertEqual(fields["max_age_seconds"], 30)


if __name__ == "__main__":
    unittest.main()
