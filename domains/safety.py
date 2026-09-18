from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import math


class DegradedMode(str, Enum):
    NOMINAL = "nominal"
    LIMITED = "limited"
    SAFE = "safe"
    EMERGENCY_STOP = "emergency_stop"


@dataclass(frozen=True)
class GeoFence:
    minimum_latitude: float
    maximum_latitude: float
    minimum_longitude: float
    maximum_longitude: float
    minimum_altitude: float | None = None
    maximum_altitude: float | None = None

    def __post_init__(self) -> None:
        if not (
            -90 <= self.minimum_latitude <= self.maximum_latitude <= 90
            and -180 <= self.minimum_longitude <= self.maximum_longitude <= 180
            and (
                self.minimum_altitude is None
                or self.maximum_altitude is None
                or self.minimum_altitude <= self.maximum_altitude
            )
        ):
            raise ValueError("invalid_geofence")

    def contains(self, latitude: float, longitude: float, altitude: float | None = None) -> bool:
        values = (latitude, longitude) if altitude is None else (latitude, longitude, altitude)
        if not all(math.isfinite(value) for value in values):
            return False
        if not (
            self.minimum_latitude <= latitude <= self.maximum_latitude
            and self.minimum_longitude <= longitude <= self.maximum_longitude
        ):
            return False
        if (
            (self.minimum_altitude is not None or self.maximum_altitude is not None)
            and altitude is None
        ):
            return False
        if self.minimum_altitude is not None and altitude < self.minimum_altitude:
            return False
        if self.maximum_altitude is not None and altitude is not None and altitude > self.maximum_altitude:
            return False
        return True


@dataclass(frozen=True)
class SensorHealth:
    observed_at: datetime
    confidence: float
    independent_agreement: bool
    max_age_seconds: float

    def usable_at(self, now: datetime) -> bool:
        if self.observed_at.tzinfo is None or now.tzinfo is None:
            return False
        age = (now - self.observed_at).total_seconds()
        return (
            math.isfinite(self.confidence)
            and 0 <= self.confidence <= 1
            and math.isfinite(self.max_age_seconds)
            and self.max_age_seconds >= 0
            and 0 <= age <= self.max_age_seconds
            and self.independent_agreement
        )


@dataclass(frozen=True)
class ResourceBudget:
    battery_minimum: float = 0
    fuel_minimum: float = 0
    thermal_minimum: float = 0
    compute_minimum: float = 0
    storage_minimum: float = 0

    def __post_init__(self) -> None:
        values = (
            self.battery_minimum,
            self.fuel_minimum,
            self.thermal_minimum,
            self.compute_minimum,
            self.storage_minimum,
        )
        if not all(math.isfinite(value) and value >= 0 for value in values):
            raise ValueError("resource_budget_must_be_finite_and_non_negative")

    def supports(self, available: "ResourceAvailability") -> bool:
        return (
            available.battery >= self.battery_minimum
            and available.fuel >= self.fuel_minimum
            and available.thermal >= self.thermal_minimum
            and available.compute >= self.compute_minimum
            and available.storage >= self.storage_minimum
        )


@dataclass(frozen=True)
class ResourceAvailability:
    battery: float
    fuel: float
    thermal: float
    compute: float
    storage: float

    def __post_init__(self) -> None:
        if not all(math.isfinite(value) for value in (
            self.battery, self.fuel, self.thermal, self.compute, self.storage
        )):
            raise ValueError("resource_availability_must_be_finite")


@dataclass
class SafetyState:
    mode: DegradedMode = DegradedMode.NOMINAL
    emergency_stop_latched: bool = False

    def enter(self, mode: DegradedMode) -> None:
        if mode == DegradedMode.NOMINAL and self.mode != DegradedMode.NOMINAL:
            raise PermissionError("nominal_recovery_requires_attestation_and_reconciliation")
        self.mode = mode
        if mode == DegradedMode.EMERGENCY_STOP:
            self.emergency_stop_latched = True

    def reset_emergency_stop(self, *, local_reset: bool, attested: bool, reconciled: bool) -> None:
        if not local_reset or not attested or not reconciled:
            raise PermissionError("emergency_stop_reset_requirements_not_met")
        self.emergency_stop_latched = False
        self.mode = DegradedMode.SAFE

    def allows_motion(self) -> bool:
        return self.mode in {DegradedMode.NOMINAL, DegradedMode.LIMITED} and not self.emergency_stop_latched


@dataclass(frozen=True)
class CommandFreshness:
    command_id: str
    issued_at: datetime
    expires_at: datetime
    sequence: int
    target: str

    def valid_at(self, now: datetime, last_sequence: int) -> bool:
        return (
            bool(self.command_id and self.target)
            and self.issued_at.tzinfo is not None
            and self.expires_at > self.issued_at
            and self.issued_at <= now <= self.expires_at
            and self.sequence > last_sequence
        )


@dataclass
class SharedSafetyGate:
    geofence: GeoFence
    resource_budget: ResourceBudget
    minimum_sensor_confidence: float = 0.8
    state: SafetyState = field(default_factory=SafetyState)
    last_sequence: int = -1

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_sensor_confidence <= 1:
            raise ValueError("invalid_sensor_confidence_threshold")

    def admit(
        self,
        command: CommandFreshness,
        *,
        now: datetime,
        latitude: float,
        longitude: float,
        altitude: float | None,
        sensor: SensorHealth,
        available: ResourceAvailability,
        human_present: bool = False,
    ) -> None:
        if not self.state.allows_motion():
            raise PermissionError("safety_mode_blocks_motion")
        if human_present:
            raise PermissionError("human_presence_veto")
        if not self.geofence.contains(latitude, longitude, altitude):
            raise PermissionError("geofence_veto")
        if not sensor.usable_at(now) or sensor.confidence < self.minimum_sensor_confidence:
            raise PermissionError("sensor_health_veto")
        if not self.resource_budget.supports(available):
            raise PermissionError("resource_budget_veto")
        if not command.valid_at(now, self.last_sequence):
            raise PermissionError("stale_or_replayed_command")
        self.last_sequence = command.sequence
