from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import math


class SpacecraftAction(str, Enum):
    TELEMETRY = "telemetry"
    ATTITUDE = "attitude"
    THRUSTER = "thruster"
    ORBIT_CHANGE = "orbit_change"
    DOCKING = "docking"
    PAYLOAD = "payload"
    SAFE_MODE = "safe_mode"


@dataclass(frozen=True)
class MissionTimeEvidence:
    mission_time: datetime
    monotonic_counter: int
    uncertainty: timedelta

    def __post_init__(self) -> None:
        if self.mission_time.tzinfo is None:
            raise ValueError("mission_time_requires_timezone")
        if self.monotonic_counter < 0 or self.uncertainty < timedelta(0):
            raise ValueError("invalid_mission_time_evidence")


@dataclass
class MissionClockGuard:
    max_uncertainty: timedelta
    last_counter: int = -1
    last_time: datetime | None = None

    def accept(self, evidence: MissionTimeEvidence) -> None:
        if evidence.uncertainty > self.max_uncertainty:
            raise PermissionError("mission_time_uncertainty_exceeded")
        if evidence.monotonic_counter <= self.last_counter:
            raise PermissionError("mission_time_counter_rollback")
        if self.last_time is not None and evidence.mission_time < self.last_time:
            raise PermissionError("mission_time_rollback")
        self.last_counter = evidence.monotonic_counter
        self.last_time = evidence.mission_time


@dataclass(frozen=True)
class ContactWindow:
    ground_station_id: str
    opens_at: datetime
    closes_at: datetime

    def __post_init__(self) -> None:
        if (
            not self.ground_station_id
            or self.opens_at.tzinfo is None
            or self.closes_at.tzinfo is None
            or self.closes_at <= self.opens_at
        ):
            raise ValueError("invalid_contact_window")

    def contains(self, now: datetime) -> bool:
        return self.opens_at <= now <= self.closes_at


@dataclass(frozen=True)
class SpacecraftCommand:
    sequence_id: str
    ordinal: int
    action: SpacecraftAction
    target: str
    issued_at: datetime
    expires_at: datetime
    mission_phase: str
    contact_window: ContactWindow | None = None

    def __post_init__(self) -> None:
        if not self.sequence_id or self.ordinal < 0 or not self.target:
            raise ValueError("invalid_spacecraft_command")
        if self.issued_at.tzinfo is None or self.expires_at <= self.issued_at:
            raise ValueError("invalid_command_time_bounds")
        if not self.mission_phase:
            raise ValueError("mission_phase_required")


@dataclass
class CommandSequenceGuard:
    last_ordinal: int = -1
    active_sequence_id: str | None = None

    def admit(
        self,
        command: SpacecraftCommand,
        *,
        now: datetime,
        expected_phase: str,
        ground_station_id: str | None = None,
    ) -> None:
        if command.mission_phase != expected_phase:
            raise PermissionError("mission_phase_mismatch")
        if not command.issued_at <= now <= command.expires_at:
            raise PermissionError("command_stale_or_expired")
        if command.contact_window is not None:
            if ground_station_id != command.contact_window.ground_station_id:
                raise PermissionError("ground_station_mismatch")
            if not command.contact_window.contains(now):
                raise PermissionError("outside_contact_window")
        if (
            self.active_sequence_id != command.sequence_id
            and command.ordinal != 0
        ):
            raise PermissionError("sequence_must_start_at_zero")
        if command.sequence_id == self.active_sequence_id:
            if command.ordinal != self.last_ordinal + 1:
                raise PermissionError("command_sequence_gap_or_replay")
        elif command.ordinal != 0:
            raise PermissionError("unexpected_command_sequence")
        self.active_sequence_id = command.sequence_id
        self.last_ordinal = command.ordinal


@dataclass(frozen=True)
class ResourceState:
    power_margin: float
    thermal_margin: float
    propellant_margin: float
    storage_margin: float

    def __post_init__(self) -> None:
        if not all(
            math.isfinite(value)
            for value in (
                self.power_margin,
                self.thermal_margin,
                self.propellant_margin,
                self.storage_margin,
            )
        ):
            raise ValueError("resource_margins_must_be_finite")

    def supports(self, minimums: "ResourceMinimums") -> bool:
        return (
            self.power_margin >= minimums.power_margin
            and self.thermal_margin >= minimums.thermal_margin
            and self.propellant_margin >= minimums.propellant_margin
            and self.storage_margin >= minimums.storage_margin
        )


@dataclass(frozen=True)
class ResourceMinimums:
    power_margin: float = 0.0
    thermal_margin: float = 0.0
    propellant_margin: float = 0.0
    storage_margin: float = 0.0

    def __post_init__(self) -> None:
        values = (
            self.power_margin,
            self.thermal_margin,
            self.propellant_margin,
            self.storage_margin,
        )
        if not all(math.isfinite(value) for value in values):
            raise ValueError("resource_minimums_must_be_finite")
        if min(values) < 0:
            raise ValueError("resource_minimums_must_be_non_negative")


@dataclass(frozen=True)
class SensorState:
    navigation_confidence: float
    independent_sensor_agreement: bool
    attitude_valid: bool

    def __post_init__(self) -> None:
        if not math.isfinite(self.navigation_confidence):
            raise ValueError("navigation_confidence_must_be_finite")

    def supports(self, minimum_navigation_confidence: float) -> bool:
        return (
            0 <= self.navigation_confidence <= 1
            and self.navigation_confidence >= minimum_navigation_confidence
            and self.independent_sensor_agreement
            and self.attitude_valid
        )


@dataclass
class SpacecraftSafetyGate:
    phase: str
    minimums: dict[SpacecraftAction, ResourceMinimums]
    minimum_navigation_confidence: float = 0.95
    faulted: bool = False

    def __post_init__(self) -> None:
        if not self.phase or not 0 <= self.minimum_navigation_confidence <= 1:
            raise ValueError("invalid_spacecraft_safety_gate")

    def veto(
        self,
        action: SpacecraftAction,
        *,
        resources: ResourceState,
        sensors: SensorState,
    ) -> None:
        if self.faulted:
            raise PermissionError("spacecraft_faulted")
        if not sensors.supports(self.minimum_navigation_confidence):
            raise PermissionError("sensor_or_navigation_veto")
        if not resources.supports(self.minimums.get(action, ResourceMinimums())):
            raise PermissionError("resource_budget_veto")

    def enter_fault(self) -> None:
        self.faulted = True

    def recover(self, *, fresh_attestation: bool, reconciled: bool) -> None:
        if not fresh_attestation or not reconciled:
            raise PermissionError("fault_recovery_requires_attestation_and_reconciliation")
        self.faulted = False
