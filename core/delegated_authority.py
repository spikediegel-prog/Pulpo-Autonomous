from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .envelope import ExecutionEnvelope


@dataclass(frozen=True)
class DelegatedAuthority:
    envelope: ExecutionEnvelope
    granted_by: str
    subject: str
    issued_at: datetime = None

    def __post_init__(self) -> None:
        if self.issued_at is None:
            object.__setattr__(self, "issued_at", datetime.now(timezone.utc))

    def allows(self, action: str, target: str, now: datetime | None = None) -> bool:
        if not self.envelope.is_active(now):
            return False
        if action != self.envelope.action:
            return False
        if target != self.envelope.target:
            return False
        return True

    def describe(self) -> str:
        return f"{self.granted_by}->{self.subject}:{self.envelope.describe()}"
