from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ObservationRecord:
    source: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    state: str = "unknown"
    detail: str = ""
    confidence: float = 0.0
    data: dict[str, Any] | None = None

    def mark_unknown(self, detail: str) -> "ObservationRecord":
        return ObservationRecord(
            source=self.source,
            observed_at=datetime.now(timezone.utc),
            state="unknown",
            detail=detail,
            confidence=0.0,
            data=self.data,
        )
