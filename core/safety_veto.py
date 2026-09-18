from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VetoResult:
    allowed: bool
    reason: str
    payload: dict[str, Any] | None = None


@dataclass
class SafetyVeto:
    name: str
    check: Any

    def evaluate(self, context: dict[str, Any] | None = None) -> VetoResult:
        context = context or {}
        result = self.check(context)
        if result is True:
            return VetoResult(allowed=False, reason=f"{self.name}: veto triggered")
        if result is False:
            return VetoResult(allowed=True, reason=f"{self.name}: cleared")
        if isinstance(result, str):
            return VetoResult(allowed=False, reason=result)
        return VetoResult(allowed=True, reason=f"{self.name}: no veto")
