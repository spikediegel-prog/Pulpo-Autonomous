"""O2 drift-rate monitor — sensor-health gate, SHADOW_ADVISORY only.

Scope: design file Appendices C, D, E
(`~/workspace/goals/pulpo-ai-governance-layer/files/pulpo-autonomous-mine-ventilation-o2.md`).

This module is an observer/evaluator ONLY. It is advisory only: no permit,
no effect, no fan/PLC write, no new authority, policy engine, permit system,
or execution gateway. It feeds the existing sensor-health gate in Rule 1 as
an UNKNOWN-producing claim.

- A drift/step/deviation breach never authorizes or blocks a fan action by
  itself. It only ever marks a head suspect, and after persistence
  untrusted, so the head is excluded from the 2-of-3 vote and counts as
  UNKNOWN in that vote.
- UNKNOWN means fans ON (Rule 2 invariant, added 2026-11-19). That fallback
  is decided by the governance layer, not here: this module has no fan
  output at all. Every evaluation carries ``authorizes_fan_stop=False`` and
  ``sensor_triggered_stop_allowed=False``.
- Pure functions and one small per-head state holder. No I/O, no network,
  no clock, no sensor driver. Callers supply samples; callers append the
  evaluation payload to the DurableJournal as evidence.
- Adapters stay outside the trusted core. There is no Modbus/OPC UA/MQTT
  driver in this module. Sensor packs are profiles, not code per sensor:
  a new head is a register map, not a new evaluator.
- Mode is ``SHADOW_ADVISORY`` by design. There is no active-guard mode in
  this module. Graduating out of shadow is a separate authorized change,
  not a flag flip here.

Reuse, not reinvention: the decision vocabulary mirrors
``domains/safety.py`` ``SensorHealth`` (confidence + age + independent
agreement -> veto) and ``core/observation.py`` ``ObservationRecord``; the
unresolved-default follows the ``IndependentDomainObservation`` pattern
(incomplete or conflicting evidence is UNKNOWN, never a success). The
module does not import ``domains`` — core must not depend on a domain
package. Callers build a ``SensorHealth`` from ``to_sensor_health_fields()``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .observation import ObservationRecord

MODE_SHADOW_ADVISORY = "SHADOW_ADVISORY"

#: Journal event name for an evaluation payload. Callers append via
#: ``DurableJournal.append(JOURNAL_EVENT, evaluation.to_journal_payload())``.
JOURNAL_EVENT = "o2_drift_evaluation"

TRUSTED = "TRUSTED"
SUSPECT = "SUSPECT"
UNTRUSTED = "UNTRUSTED"
UNKNOWN = "UNKNOWN"

DECISIONS = (TRUSTED, SUSPECT, UNTRUSTED, UNKNOWN)


@dataclass(frozen=True)
class DriftLimits:
    """Suspect thresholds from Appendix C, section C6.

    Rate/step limits apply to the absolute value ``|rate|``: a false-high
    drift is rarer but worse, because it can mask a real deficiency.
    The neighbor-deviation limit is an absolute error against the neighbor
    median: a deviation at the limit is already out of tolerance, so it
    breaches at ``>=``; rate/step breach at ``>`` (at the maximum normal
    rate the head is still within spec).
    """

    rate_limit_pct_per_hour: float = 0.25
    step_limit_pct_per_minute: float = 0.50
    max_neighbor_deviation_pct: float = 0.5
    max_reading_age_seconds: float = 30
    min_breach_duration_seconds: float = 60
    consecutive_breach_samples: int = 3
    calibration_max_age_days: float = 21
    retrust_soak_minutes: float = 30
    low_o2_alarm_pct: float = 19.5
    normal_baseline_pct: float = 20.9


@dataclass(frozen=True)
class O2HeadSample:
    """One evaluated reading for one O2 head.

    All rates are already computed on the pressure- and
    temperature-compensated value when ``reading_compensated`` is true.
    When it is false, drift/step breaches are inconclusive — a barometric
    swing moves an uncompensated electrochemical reading by a few tenths
    of a percent — and are capped at SUSPECT. The neighbor deviation is
    unaffected by that: neighbors share the same barometric pressure, so
    a deviation against the neighbor median still counts.
    """

    sensor_id: str
    raw_o2_pct: float
    drift_pct_per_hour: float
    step_change_pct_per_minute: float
    neighbor_median_pct: float | None
    age_seconds: float
    fault_code: str | None = None
    calibrating: bool = False
    calibration_age_days: float | None = None
    rated_life_expired: bool = False
    span_check_passed: bool | None = None
    accuracy_within_spec: bool = True
    reading_compensated: bool = True
    airflow_active: bool | None = None
    pump_running: bool | None = None
    personnel_in_zone: bool = False


@dataclass(frozen=True)
class DriftEvaluation:
    """The defined output of one drift evaluation (Appendix C, section C7).

    Every field needed to reproduce the decision is carried here, so the
    journal payload is a cold-reproducible record of why a head was
    distrusted and why the fans stayed on. ``authorizes_fan_stop`` is
    always False: this evaluation never authorizes a fan stop.
    """

    decision: str
    reasons: tuple[str, ...]
    sensor_id: str
    raw_o2_pct: float
    drift_pct_per_hour: float
    step_change_pct_per_minute: float
    neighbor_median_pct: float | None
    neighbor_deviation_pct: float | None
    age_seconds: float
    fault_code: str | None
    calibrating: bool
    airflow_active: bool | None
    pump_running: bool | None
    personnel_in_zone: bool
    breach_streak: int = 0
    breach_duration_seconds: float = 0.0
    retrust_soak_minutes: float = 0.0
    retrust_soak_required_minutes: float = 30.0
    rate_limit_pct_per_hour: float = 0.25
    step_limit_pct_per_minute: float = 0.50
    max_neighbor_deviation_pct: float = 0.5
    max_reading_age_seconds: float = 30.0
    vote_counts_as_unknown: bool = False
    confidence: float = 0.0
    independent_agreement: bool = False
    mode: str = MODE_SHADOW_ADVISORY
    authorizes_fan_stop: bool = False
    sensor_triggered_stop_allowed: bool = False
    personnel_underground_blocks_stop: bool = True

    def to_journal_payload(self) -> dict[str, Any]:
        """Evidence payload, appendable to ``DurableJournal`` as-is."""
        return {
            "sensor_id": self.sensor_id,
            "decision": self.decision,
            "reasons": list(self.reasons),
            "mode": self.mode,
            "readings": {
                "raw_o2_pct": self.raw_o2_pct,
                "drift_pct_per_hour": self.drift_pct_per_hour,
                "step_change_pct_per_minute": self.step_change_pct_per_minute,
                "neighbor_median_pct": self.neighbor_median_pct,
                "neighbor_deviation_pct": self.neighbor_deviation_pct,
                "age_seconds": self.age_seconds,
                "fault_code": self.fault_code,
                "calibrating": self.calibrating,
            },
            "thresholds_applied": {
                "rate_limit_pct_per_hour": self.rate_limit_pct_per_hour,
                "step_limit_pct_per_minute": self.step_limit_pct_per_minute,
                "max_neighbor_deviation_pct": self.max_neighbor_deviation_pct,
                "max_reading_age_seconds": self.max_reading_age_seconds,
            },
            "corroboration": {
                "neighbor_agreement": self.independent_agreement,
                "airflow_active": self.airflow_active,
                "pump_running": self.pump_running,
                "personnel_in_zone": self.personnel_in_zone,
            },
            "breach_streak": self.breach_streak,
            "breach_duration_seconds": self.breach_duration_seconds,
            "retrust_soak_minutes": self.retrust_soak_minutes,
            "retrust_soak_required_minutes": self.retrust_soak_required_minutes,
            "vote_counts_as_unknown": self.vote_counts_as_unknown,
            "authorizes_fan_stop": False,
            "sensor_triggered_stop_allowed": False,
            "personnel_underground_blocks_stop": True,
        }

    def to_observation(self) -> ObservationRecord:
        """This evaluation as an ``ObservationRecord`` claim.

        The state is the decision itself. An UNTRUSTED or UNKNOWN head
        is a claim about the sensor, never authority for an effect.
        """
        return ObservationRecord(
            source=self.sensor_id,
            state=self.decision.lower(),
            detail=", ".join(self.reasons) or self.decision,
            confidence=self.confidence,
            data=self.to_journal_payload(),
        )

    def to_sensor_health_fields(self) -> dict[str, Any]:
        """Fields for a ``domains.safety.SensorHealth``.

        Core does not import ``domains``; callers construct the
        ``SensorHealth`` from these fields. Confidence follows the
        decision: TRUSTED 1.0, SUSPECT 0.5, UNTRUSTED/UNKNOWN 0.0.
        """
        return {
            "confidence": self.confidence,
            "independent_agreement": self.independent_agreement,
            "max_age_seconds": self.max_reading_age_seconds,
        }


def _is_finite(value: float | None) -> bool:
    return value is not None and math.isfinite(value)


def _confidence_for(decision: str) -> float:
    return {TRUSTED: 1.0, SUSPECT: 0.5, UNTRUSTED: 0.0, UNKNOWN: 0.0}[decision]


def evaluate_sample(
    sample: O2HeadSample,
    limits: DriftLimits | None = None,
    *,
    breach_streak: int = 0,
    breach_duration_seconds: float = 0.0,
    retrust_soak_minutes: float = 0.0,
) -> DriftEvaluation:
    """Stateless single-sample evaluation.

    Persistence and re-trust are *not* applied here: a breaching sample
    is SUSPECT, a health-gate failure is UNTRUSTED, an invalid/stale/
    calibrating sample is UNKNOWN, a clean sample is TRUSTED. Use
    :class:`DriftMonitor` for persistence (3 samples / 60 s) and for the
    re-trust latch and soak.
    """
    limits = limits or DriftLimits()
    reasons: list[str] = []

    deviation: float | None = None
    if sample.neighbor_median_pct is not None:
        if math.isfinite(sample.neighbor_median_pct):
            deviation = sample.raw_o2_pct - sample.neighbor_median_pct
        else:
            reasons.append("neighbor_median_unavailable")
    else:
        reasons.append("neighbor_median_unavailable")

    agreement = deviation is not None and abs(deviation) < limits.max_neighbor_deviation_pct

    def build(decision: str, extra_reasons: list[str] | None = None) -> DriftEvaluation:
        all_reasons = list(dict.fromkeys(reasons + (extra_reasons or [])))
        if decision == TRUSTED:
            # A trusted head carries no reasons: a missing neighbor
            # median is a corroboration gap for the voter, not a defect
            # in this sample.
            all_reasons = [r for r in all_reasons if r != "neighbor_median_unavailable"]
        return DriftEvaluation(
            decision=decision,
            reasons=tuple(all_reasons),
            sensor_id=sample.sensor_id,
            raw_o2_pct=sample.raw_o2_pct,
            drift_pct_per_hour=sample.drift_pct_per_hour,
            step_change_pct_per_minute=sample.step_change_pct_per_minute,
            neighbor_median_pct=sample.neighbor_median_pct,
            neighbor_deviation_pct=deviation,
            age_seconds=sample.age_seconds,
            fault_code=sample.fault_code,
            calibrating=sample.calibrating,
            airflow_active=sample.airflow_active,
            pump_running=sample.pump_running,
            personnel_in_zone=sample.personnel_in_zone,
            breach_streak=breach_streak,
            breach_duration_seconds=breach_duration_seconds,
            retrust_soak_minutes=retrust_soak_minutes,
            retrust_soak_required_minutes=limits.retrust_soak_minutes,
            rate_limit_pct_per_hour=limits.rate_limit_pct_per_hour,
            step_limit_pct_per_minute=limits.step_limit_pct_per_minute,
            max_neighbor_deviation_pct=limits.max_neighbor_deviation_pct,
            max_reading_age_seconds=limits.max_reading_age_seconds,
            vote_counts_as_unknown=decision != TRUSTED,
            confidence=_confidence_for(decision),
            independent_agreement=agreement,
        )

    # UNKNOWN: the sample cannot be evaluated at all. No breach is
    # inferred from an invalid, stale, or calibrating reading.
    if not all(
        math.isfinite(value)
        for value in (
            sample.raw_o2_pct,
            sample.drift_pct_per_hour,
            sample.step_change_pct_per_minute,
            sample.age_seconds,
        )
    ):
        return build(UNKNOWN, ["invalid_reading"])
    if sample.calibrating:
        return build(UNKNOWN, ["calibrating"])
    if sample.age_seconds < 0 or sample.age_seconds > limits.max_reading_age_seconds:
        return build(UNKNOWN, ["reading_stale"])

    # Suspect conditions: drift, step, neighbor deviation, fault code,
    # unknown calibration age. Drift/step are judged on |rate|. These are
    # computed before the health gate so an UNTRUSTED evaluation carries
    # every applicable reason, not just the health failure.
    suspect: list[str] = []
    drift_breach = abs(sample.drift_pct_per_hour) > limits.rate_limit_pct_per_hour
    step_breach = abs(sample.step_change_pct_per_minute) > limits.step_limit_pct_per_minute
    deviation_breach = deviation is not None and abs(deviation) >= limits.max_neighbor_deviation_pct
    if drift_breach:
        suspect.append("drift_rate_exceeded")
    if step_breach:
        suspect.append("step_change_exceeded")
    if deviation_breach:
        suspect.append("neighbor_deviation_exceeded")
    if sample.fault_code is not None:
        suspect.append("sensor_fault_code")
    if sample.calibration_age_days is None:
        suspect.append("calibration_age_unknown")

    # Health gate: definitive failures. No persistence needed — a head
    # past calibration, past rated life, failed span, or out of spec is
    # UNTRUSTED by definition.
    health_failures: list[str] = []
    if sample.calibration_age_days is not None and sample.calibration_age_days > limits.calibration_max_age_days:
        health_failures.append("calibration_overdue")
    if sample.rated_life_expired:
        health_failures.append("rated_life_expired")
    if sample.span_check_passed is False:
        health_failures.append("span_check_failed")
    if not sample.accuracy_within_spec:
        health_failures.append("accuracy_out_of_spec")
    if health_failures:
        return build(UNTRUSTED, health_failures + suspect)

    if not suspect:
        return build(TRUSTED)

    # Uncompensated readings: a barometric swing moves an
    # electrochemical reading by a few tenths of a percent, so a drift or
    # step breach alone is inconclusive. It stays SUSPECT and never
    # promotes on drift/step. The neighbor deviation is pressure
    # independent — neighbors share the same pressure — so it still counts.
    if not sample.reading_compensated and not deviation_breach and sample.fault_code is None:
        return build(SUSPECT, suspect + ["uncompensated_reading_barometric_swing_possible"])

    return build(SUSPECT, suspect)


@dataclass
class DriftMonitor:
    """Per-head drift monitor with persistence and re-trust.

    One instance per sensor head. ``sensor_id`` is enforced when set:
    feeding another head's samples raises ``ValueError`` so heads can
    never be mixed into one streak or soak.

    Persistence: a suspect condition flips a head to UNTRUSTED only when
    it holds for ``consecutive_breach_samples`` (3) consecutive samples
    *or* ``min_breach_duration_seconds`` (60 s). A single breaching
    sample is SUSPECT. A clean sample resets the streak and duration.

    Re-trust: once UNTRUSTED the decision latches. A single good reading
    does not re-admit the head. Re-trust requires an explicit
    ``record_recalibration()`` *plus* a soak of ``retrust_soak_minutes``
    (30) of consecutive in-tolerance samples with neighbors agreeing.
    A breaching sample during the soak resets the soak to zero.
    """

    limits: DriftLimits = field(default_factory=DriftLimits)
    sensor_id: str | None = None
    _breach_streak: int = field(default=0, init=False, repr=False)
    _breach_duration_seconds: float = field(default=0.0, init=False, repr=False)
    _untrusted: bool = field(default=False, init=False, repr=False)
    _recalibrated: bool = field(default=False, init=False, repr=False)
    _soak_minutes: float = field(default=0.0, init=False, repr=False)

    @property
    def is_untrusted(self) -> bool:
        return self._untrusted

    @property
    def retrust_soak_minutes(self) -> float:
        return self._soak_minutes

    def record_recalibration(self) -> None:
        """Record that this head was recalibrated. Starts the re-trust soak.

        This is an explicit event, not a reading: a good reading alone
        never starts a soak. Without a preceding UNTRUSTED latch this is
        a no-op for trust, and the soak is only consumed on re-trust.
        """
        self._recalibrated = True
        self._soak_minutes = 0.0

    def observe(self, sample: O2HeadSample, *, elapsed_seconds: float = 0.0) -> DriftEvaluation:
        """Evaluate one sample for this head, applying persistence and re-trust.

        ``elapsed_seconds`` is the time since the previous sample from
        this head; it accumulates breach duration and, after
        recalibration, re-trust soak. Callers that cannot supply it may
        leave it at 0, in which case persistence is by sample count only.
        """
        if self.sensor_id is not None and sample.sensor_id != self.sensor_id:
            raise ValueError("drift_monitor_sensor_mismatch")
        if not math.isfinite(elapsed_seconds) or elapsed_seconds < 0:
            raise ValueError("elapsed_seconds_must_be_finite_and_non_negative")

        base = evaluate_sample(sample, self.limits)

        # Latched UNTRUSTED: only recalibration + a full soak re-admits.
        if self._untrusted:
            clean = base.decision == TRUSTED
            if self._recalibrated and clean:
                self._soak_minutes += elapsed_seconds / 60.0
                if self._soak_minutes >= self.limits.retrust_soak_minutes:
                    self._untrusted = False
                    self._recalibrated = False
                    self._soak_minutes = 0.0
                    self._breach_streak = 0
                    self._breach_duration_seconds = 0.0
                    return evaluate_sample(
                        sample,
                        self.limits,
                        retrust_soak_minutes=self.limits.retrust_soak_minutes,
                    )
            elif clean:
                # Good readings without recalibration: soak does not start.
                pass
            else:
                # Any non-clean sample during the soak invalidates the
                # recalibration, not just the clock: the head must be
                # recalibrated again before a new soak can start.
                self._soak_minutes = 0.0
                self._recalibrated = False
            return DriftEvaluation(
                **{
                    **base.__dict__,
                    "decision": UNTRUSTED,
                    "reasons": tuple(
                        dict.fromkeys(
                            ["previously_untrusted", "retrust_soak_incomplete", *base.reasons]
                            if self._recalibrated
                            else ["previously_untrusted", *base.reasons]
                        )
                    ),
                    "retrust_soak_minutes": self._soak_minutes,
                    "vote_counts_as_unknown": True,
                    "confidence": 0.0,
                }
            )

        # Not latched: UNKNOWN samples break consecutiveness, nothing latches.
        if base.decision == UNKNOWN:
            self._breach_streak = 0
            self._breach_duration_seconds = 0.0
            return base

        # Health-gate UNTRUSTED latches immediately.
        if base.decision == UNTRUSTED:
            self._untrusted = True
            self._recalibrated = False
            self._soak_minutes = 0.0
            return base

        if base.decision == TRUSTED:
            self._breach_streak = 0
            self._breach_duration_seconds = 0.0
            return base

        # SUSPECT: advance persistence. Uncompensated drift/step alone
        # never promotes: it is inconclusive, not a confirmed breach.
        # A metadata-only gap (unknown calibration age, with no drift,
        # step, deviation, or fault) likewise stays SUSPECT without
        # advancing the streak: it is unverified, not a confirmed breach.
        uncompensated_only = (
            not sample.reading_compensated
            and "uncompensated_reading_barometric_swing_possible" in base.reasons
        )
        if uncompensated_only:
            return base
        promotes = any(
            reason in base.reasons
            for reason in (
                "drift_rate_exceeded",
                "step_change_exceeded",
                "neighbor_deviation_exceeded",
                "sensor_fault_code",
            )
        )
        if not promotes:
            return base
        self._breach_streak += 1
        self._breach_duration_seconds += elapsed_seconds
        persisted = (
            self._breach_streak >= self.limits.consecutive_breach_samples
            or self._breach_duration_seconds >= self.limits.min_breach_duration_seconds
        )
        if not persisted:
            return DriftEvaluation(
                **{
                    **base.__dict__,
                    "breach_streak": self._breach_streak,
                    "breach_duration_seconds": self._breach_duration_seconds,
                }
            )
        self._untrusted = True
        self._recalibrated = False
        self._soak_minutes = 0.0
        return DriftEvaluation(
            **{
                **base.__dict__,
                "decision": UNTRUSTED,
                "reasons": tuple(dict.fromkeys([*base.reasons, "breach_persisted"])),
                "breach_streak": self._breach_streak,
                "breach_duration_seconds": self._breach_duration_seconds,
                "vote_counts_as_unknown": True,
                "confidence": 0.0,
            }
        )
