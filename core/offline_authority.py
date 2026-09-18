from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .envelope import ExecutionEnvelope


@dataclass
class OfflineAuthority:
    permit: ExecutionEnvelope
    disconnected_since: datetime | None = None
    max_disconnected_seconds: int = 0

    def can_continue(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        if not self.permit.is_active(current):
            return False
        if self.disconnected_since is None:
            return True
        elapsed = (current - self.disconnected_since).total_seconds()
        return elapsed <= self.max_disconnected_seconds

    def mark_disconnected(self, now: datetime | None = None) -> None:
        if self.disconnected_since is None:
            self.disconnected_since = now or datetime.now(timezone.utc)
