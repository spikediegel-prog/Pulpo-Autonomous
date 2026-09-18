from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set


@dataclass
class ReplayGuard:
    seen_ids: Set[str] = field(default_factory=set)

    def consume(self, record_id: str) -> bool:
        if record_id in self.seen_ids:
            return False
        self.seen_ids.add(record_id)
        return True

    def reset(self) -> None:
        self.seen_ids.clear()
