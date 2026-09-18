from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhysicalSystemDomain:
    name: str
    mission_phase: str = "standby"
    constraints: dict[str, Any] = field(default_factory=dict)

    def with_constraint(self, key: str, value: Any) -> "PhysicalSystemDomain":
        self.constraints[key] = value
        return self

    def update_phase(self, phase: str) -> "PhysicalSystemDomain":
        self.mission_phase = phase
        return self

    def describe(self) -> str:
        return f"{self.name}:{self.mission_phase}:{sorted(self.constraints.keys())}"
