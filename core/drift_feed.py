"""Drift ingestion feed — the sensor-app side of design item 5.4.

Control Center design v0, item 5.4: something must call
``DriftMonitor.observe()`` on live head samples and append
``to_journal_payload()`` to the journal, per Appendix E of the
mine-ventilation design (one governance system, sensor apps plug in).
Until this exists, the Sensors page shows Unknown.

This module is that something — the feed interface between a
deployment's sample source and the existing evaluator — and nothing
more:

- The deployment supplies the samples (from its AMS/SCADA bridge or
  recorded feed). This component does NOT invent a sensor driver, does
  NOT speak Modbus / OPC UA / MQTT, does NOT generate fake live data,
  and does NOT poll any sensor. A feed with no samples produces no
  evaluations, and the Sensors page stays Unknown.
- One sample produces exactly one evaluation and exactly one journal
  event. There is no de-duplication: the monitor's persistence rule
  (3 consecutive breaching samples, or 60 s of breach) *requires*
  each sample to be recorded — skipping "duplicate" samples would
  break the rule that promotes a suspect head to UNTRUSTED.
- SHADOW_ADVISORY only. The feed is an observer/evaluator path: no
  permit, no effect, no fan/PLC write, no new authority, no kernel,
  no audit-chain write. The only canonical write it makes is the
  journal append it is defined to make, and the journal is evidence,
  not authority. The feed never imports ``pulpo`` or any observer/CC
  code — the CC must not become the ingestion path, and the ingestion
  path must not depend on the CC.
- Evaluation bookkeeping the snapshot needs: the feed records, per
  head, when it last evaluated (``last_evaluated_ns``) and the last
  calibration age a sample reported. Both are supplied to
  ``freeze_observer_snapshot`` by the deployment, exactly like the
  ``drift_evaluated_at_ns`` mapping §5.1 already accepts. A head
  with no reported calibration age carries none — unknown, never
  invented. The calibration age is the last age a sample reported
  for that head; a sample that reports no age leaves the last
  reported value in place.
- Calibration provenance the snapshot needs: the deployment records,
  per head, the maintenance facts samples cannot carry — the last
  calibration date, the profile interval, the rated-life expiry, an
  explicit deadline, and the last span check — through
  ``record_calibration_provenance`` and ``record_span_check``. These
  are deployment-reported facts, not sample data: a sample's
  ``span_check_passed`` flag affects its evaluation (a failed span
  check makes the head UNTRUSTED) but does not write provenance,
  because the sample carries no span-check time and a result without
  a time would violate the both-or-neither rule. Provenance may be
  recorded before a head's first sample; the snapshot only includes
  evaluated heads, and entries for unevaluated heads are ignored
  there, exactly like the other mappings.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Callable

from .drift import (
    JOURNAL_EVENT,
    DriftEvaluation,
    DriftLimits,
    DriftMonitor,
    O2HeadSample,
)
from .journal import DurableJournal


def _is_non_negative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _is_positive_finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


@dataclass(frozen=True)
class DriftSnapshotInputs:
    """What ``freeze_observer_snapshot`` needs from this feed.

    ``evaluations`` are the latest evaluation per head, in first-seen
    head order. ``evaluated_at_ns`` maps sensor id to the epoch
    nanoseconds of that head's last evaluation. ``calibration_age_days``
    maps sensor id to the last calibration age a sample reported for
    that head — heads that never reported an age are absent, never
    guessed. The remaining mappings are the head's calibration
    provenance, recorded by the deployment through
    ``record_calibration_provenance`` and ``record_span_check``:
    ``last_calibration_ns`` (when the head was last calibrated),
    ``calibration_interval_days`` (how often it should be calibrated,
    from the sensor profile), ``next_calibration_due_ns`` (a
    deployment-supplied deadline; the freeze derives one from last
    calibration plus interval when none was supplied),
    ``rated_life_expiry_ns`` (when the sensor is past its rated life),
    and the last span check as ``span_check_passed`` plus
    ``span_check_ns``. A head with no recorded value for a field is
    absent from that mapping, never guessed.
    """

    evaluations: tuple[DriftEvaluation, ...]
    evaluated_at_ns: dict[str, int]
    calibration_age_days: dict[str, float]
    last_calibration_ns: dict[str, int]
    calibration_interval_days: dict[str, float]
    next_calibration_due_ns: dict[str, int]
    rated_life_expiry_ns: dict[str, int]
    span_check_passed: dict[str, bool]
    span_check_ns: dict[str, int]


class DriftFeed:
    """Per-head drift ingestion feed over one ``DurableJournal``.

    One ``DriftMonitor`` per sensor head, created on first sight of
    that head's samples. ``ingest`` evaluates one sample and appends
    the evaluation to the journal as an ``o2_drift_evaluation`` event.
    If the journal append fails (a tampered journal fails closed),
    the exception propagates and no bookkeeping is recorded for that
    sample — an unevidenced evaluation is not reported as evaluated.
    """

    def __init__(
        self,
        journal: DurableJournal,
        *,
        limits: DriftLimits | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if type(journal) is not DurableJournal:
            raise TypeError("drift_feed_journal_invalid")
        self._journal = journal
        self._limits = limits if limits is not None else DriftLimits()
        if clock is not None and not callable(clock):
            raise TypeError("drift_feed_clock_invalid")
        self._clock = clock if clock is not None else time.time_ns
        self._monitors: dict[str, DriftMonitor] = {}
        self._latest: dict[str, DriftEvaluation] = {}
        self._evaluated_at_ns: dict[str, int] = {}
        self._calibration_age_days: dict[str, float] = {}
        self._last_calibration_ns: dict[str, int] = {}
        self._calibration_interval_days: dict[str, float] = {}
        self._next_calibration_due_ns: dict[str, int] = {}
        self._rated_life_expiry_ns: dict[str, int] = {}
        self._span_check_passed: dict[str, bool] = {}
        self._span_check_ns: dict[str, int] = {}

    def head_ids(self) -> tuple[str, ...]:
        """Sensor ids this feed has evaluated, in first-seen order."""
        return tuple(self._monitors)

    def ingest(
        self, sample: O2HeadSample, *, elapsed_seconds: float = 0.0
    ) -> DriftEvaluation:
        """Evaluate one head sample and append the evaluation to the journal.

        Returns the evaluation. The monitor decides per Appendix C:
        invalid / stale / calibrating samples are UNKNOWN, a breaching
        sample is SUSPECT, a health-gate failure or a persisted breach
        is UNTRUSTED. Every outcome — including UNKNOWN — is appended
        as evidence: an unreadable sample is itself a fact about the
        head. The clock is read once, before the append, so the
        recorded evaluation time is the time the sample was evaluated.
        """
        if type(sample) is not O2HeadSample:
            raise TypeError("drift_feed_sample_invalid")
        if type(sample.sensor_id) is not str or not sample.sensor_id:
            raise ValueError("drift_feed_sensor_id_invalid")
        now_ns = self._clock()
        if type(now_ns) is not int or now_ns <= 0:
            raise ValueError("drift_feed_clock_invalid")
        monitor = self._monitors.get(sample.sensor_id)
        if monitor is None:
            monitor = DriftMonitor(limits=self._limits, sensor_id=sample.sensor_id)
            self._monitors[sample.sensor_id] = monitor
        evaluation = monitor.observe(sample, elapsed_seconds=elapsed_seconds)
        # Fail-closed journal: a tampered journal raises here, the
        # exception propagates, and no bookkeeping is recorded.
        self._journal.append(JOURNAL_EVENT, evaluation.to_journal_payload())
        self._latest[sample.sensor_id] = evaluation
        self._evaluated_at_ns[sample.sensor_id] = now_ns
        if sample.calibration_age_days is not None:
            self._calibration_age_days[sample.sensor_id] = sample.calibration_age_days
        return evaluation

    def record_recalibration(self, sensor_id: str) -> None:
        """Record that a head was recalibrated; starts its re-trust soak.

        The head must already be known to this feed — recalibrating a
        head with no samples is a caller error, not a no-op. This is a
        monitor-state event only: it appends nothing to the journal.
        The soak itself is visible in later evaluations through
        ``retrust_soak_minutes``. This does not write calibration
        provenance: the calibration date is a maintenance fact the
        deployment records through ``record_calibration_provenance``.
        """
        if type(sensor_id) is not str or not sensor_id:
            raise ValueError("drift_feed_sensor_id_invalid")
        monitor = self._monitors.get(sensor_id)
        if monitor is None:
            raise ValueError("drift_feed_unknown_sensor")
        monitor.record_recalibration()

    def record_calibration_provenance(
        self,
        sensor_id: str,
        *,
        last_calibration_ns: int | None = None,
        calibration_interval_days: float | None = None,
        rated_life_expiry_ns: int | None = None,
        next_calibration_due_ns: int | None = None,
    ) -> None:
        """Record one head's calibration provenance, as the deployment reports it.

        Each supplied value is validated fail-closed; an argument left
        as ``None`` is not provided in this call and leaves the value
        already held in place (it does not clear it). A supplied
        deadline must not precede the last calibration -- checked
        against the merged view of what this call supplies and what is
        already held, so a later update cannot silently create a
        contradictory pair. Provenance may be recorded before the
        head's first sample: the snapshot only includes evaluated
        heads, and entries for unevaluated heads are ignored there.
        This appends nothing to the journal: it is bookkeeping for
        the snapshot, not an evaluation.
        """
        if type(sensor_id) is not str or not sensor_id:
            raise ValueError("drift_feed_sensor_id_invalid")
        if last_calibration_ns is not None and not _is_non_negative_int(
            last_calibration_ns
        ):
            raise ValueError("drift_feed_last_calibration_ns_invalid")
        if calibration_interval_days is not None and not _is_positive_finite_number(
            calibration_interval_days
        ):
            raise ValueError("drift_feed_calibration_interval_days_invalid")
        if rated_life_expiry_ns is not None and not _is_non_negative_int(
            rated_life_expiry_ns
        ):
            raise ValueError("drift_feed_rated_life_expiry_ns_invalid")
        if next_calibration_due_ns is not None and not _is_non_negative_int(
            next_calibration_due_ns
        ):
            raise ValueError("drift_feed_next_calibration_due_ns_invalid")
        merged_last = (
            last_calibration_ns
            if last_calibration_ns is not None
            else self._last_calibration_ns.get(sensor_id)
        )
        merged_due = (
            next_calibration_due_ns
            if next_calibration_due_ns is not None
            else self._next_calibration_due_ns.get(sensor_id)
        )
        if (
            merged_last is not None
            and merged_due is not None
            and merged_due < merged_last
        ):
            raise ValueError("drift_feed_calibration_due_invalid")
        if last_calibration_ns is not None:
            self._last_calibration_ns[sensor_id] = last_calibration_ns
        if calibration_interval_days is not None:
            self._calibration_interval_days[sensor_id] = calibration_interval_days
        if rated_life_expiry_ns is not None:
            self._rated_life_expiry_ns[sensor_id] = rated_life_expiry_ns
        if next_calibration_due_ns is not None:
            self._next_calibration_due_ns[sensor_id] = next_calibration_due_ns

    def record_span_check(
        self, sensor_id: str, *, passed: bool, checked_at_ns: int
    ) -> None:
        """Record one head's last span check, as the deployment reports it.

        Both the result and the time it ran are required: a span check
        is a maintenance event with a result AND a time, and the
        snapshot enforces both-or-neither. This appends nothing to the
        journal. A sample's ``span_check_passed`` flag does not write
        here -- the sample carries no span-check time, and a result
        without a time would violate the rule. The flag still affects
        the evaluation: a failed span check makes the head UNTRUSTED,
        with the reason visible in the evaluation either way.
        """
        if type(sensor_id) is not str or not sensor_id:
            raise ValueError("drift_feed_sensor_id_invalid")
        if type(passed) is not bool:
            raise ValueError("drift_feed_span_check_passed_invalid")
        if not _is_non_negative_int(checked_at_ns):
            raise ValueError("drift_feed_span_check_ns_invalid")
        self._span_check_passed[sensor_id] = passed
        self._span_check_ns[sensor_id] = checked_at_ns

    def latest_evaluations(self) -> tuple[DriftEvaluation, ...]:
        """Latest evaluation per head, in first-seen head order."""
        return tuple(self._latest[sensor_id] for sensor_id in self._monitors)

    def evaluated_at_ns(self) -> dict[str, int]:
        """Epoch nanoseconds of each head's last evaluation, by sensor id."""
        return dict(self._evaluated_at_ns)

    def calibration_age_days(self) -> dict[str, float]:
        """Last reported calibration age per head, by sensor id.

        Only heads whose samples reported an age appear here.
        """
        return dict(self._calibration_age_days)

    def last_calibration_ns(self) -> dict[str, int]:
        """Last calibration time per head, by sensor id.

        Only heads the deployment recorded a calibration date for
        appear here.
        """
        return dict(self._last_calibration_ns)

    def calibration_interval_days(self) -> dict[str, float]:
        """Calibration interval per head, by sensor id.

        Only heads the deployment recorded an interval for appear here.
        """
        return dict(self._calibration_interval_days)

    def next_calibration_due_ns(self) -> dict[str, int]:
        """Deployment-supplied calibration deadline per head, by sensor id.

        Only heads the deployment supplied a deadline for appear here;
        the freeze derives a deadline from last calibration plus
        interval when none was supplied.
        """
        return dict(self._next_calibration_due_ns)

    def rated_life_expiry_ns(self) -> dict[str, int]:
        """Rated-life expiry per head, by sensor id.

        Only heads the deployment recorded an expiry for appear here.
        """
        return dict(self._rated_life_expiry_ns)

    def span_check_passed(self) -> dict[str, bool]:
        """Last span-check result per head, by sensor id.

        Only heads the deployment recorded a span check for appear
        here, always alongside ``span_check_ns``.
        """
        return dict(self._span_check_passed)

    def span_check_ns(self) -> dict[str, int]:
        """Last span-check time per head, by sensor id.

        Only heads the deployment recorded a span check for appear
        here, always alongside ``span_check_passed``.
        """
        return dict(self._span_check_ns)

    def snapshot_inputs(self) -> DriftSnapshotInputs:
        """The inputs ``freeze_observer_snapshot`` takes from a feed."""
        return DriftSnapshotInputs(
            evaluations=self.latest_evaluations(),
            evaluated_at_ns=self.evaluated_at_ns(),
            calibration_age_days=self.calibration_age_days(),
            last_calibration_ns=self.last_calibration_ns(),
            calibration_interval_days=self.calibration_interval_days(),
            next_calibration_due_ns=self.next_calibration_due_ns(),
            rated_life_expiry_ns=self.rated_life_expiry_ns(),
            span_check_passed=self.span_check_passed(),
            span_check_ns=self.span_check_ns(),
        )
