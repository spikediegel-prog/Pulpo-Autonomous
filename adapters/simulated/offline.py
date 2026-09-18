from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from core.execution import ExecutionTracker
from core.offline_protocol import ExecutionState


@dataclass
class SimulatedOfflineUnit:
    tracker: ExecutionTracker

    def execute(self, command_id: str, action: str, now: datetime) -> ExecutionState:
        timestamp = now.isoformat()
        self.tracker.plan(command_id, action, timestamp)
        self.tracker.send(command_id, timestamp)
        return ExecutionState.SENT

    def report_unknown(self, command_id: str, now: datetime) -> ExecutionState:
        return self.tracker.observe(command_id, ExecutionState.UNKNOWN, now.isoformat())
