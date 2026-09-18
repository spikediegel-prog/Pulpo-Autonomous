from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ExecutionEnvelope:
    permit_id: str
    action: str
    target: str
    machine_id: str
    domain: str
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    authority_scope: dict[str, Any] | None = None
    max_retry: int = 0

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        if self.expires_at is not None and current > self.expires_at:
            return False
        return True

    def describe(self) -> str:
        return f"{self.action}:{self.target}:{self.permit_id}"
