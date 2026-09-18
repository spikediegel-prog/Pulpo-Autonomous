from ..base import PhysicalSystemDomain
from .operations import (
    CommandSequenceGuard,
    ContactWindow,
    MissionClockGuard,
    MissionTimeEvidence,
    ResourceMinimums,
    ResourceState,
    SensorState,
    SpacecraftAction,
    SpacecraftCommand,
    SpacecraftSafetyGate,
)


class SpacecraftDomain(PhysicalSystemDomain):
    def __init__(self, **kwargs):
        constraints = {
            "power_budget_w": 200,
            "thermal_margin_c": 10,
            "command_window_s": 120,
            "no_retry_on_uncertain_orbit": True,
        }
        constraints.update(kwargs.pop("constraints", {}))
        super().__init__(name="spacecraft", constraints=constraints, **kwargs)

__all__ = [
    "CommandSequenceGuard",
    "ContactWindow",
    "MissionClockGuard",
    "MissionTimeEvidence",
    "ResourceMinimums",
    "ResourceState",
    "SensorState",
    "SpacecraftAction",
    "SpacecraftCommand",
    "SpacecraftDomain",
    "SpacecraftSafetyGate",
]
