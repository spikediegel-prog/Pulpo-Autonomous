from __future__ import annotations

from dataclasses import dataclass

from .journal import DurableJournal
from .offline_protocol import ExecutionState, OfflineProtocol


@dataclass
class ExecutionTracker:
    protocol: OfflineProtocol
    journal: DurableJournal

    def plan(self, command_id: str, action: str, now: str) -> ExecutionState:
        self.journal.append(
            "planned",
            {"command_id": command_id, "action": action, "at": now},
        )
        return ExecutionState.PLANNED

    def send(self, command_id: str, now: str) -> ExecutionState:
        if not self.protocol.can_execute(_parse_time(now)):
            self.journal.append("vetoed", {"command_id": command_id, "at": now})
            raise PermissionError("offline_authority_unavailable")
        self.journal.append("sent", {"command_id": command_id, "at": now})
        return ExecutionState.SENT

    def observe(self, command_id: str, state: ExecutionState, now: str) -> ExecutionState:
        if state not in {
            ExecutionState.OBSERVED_SUCCESS,
            ExecutionState.OBSERVED_FAILURE,
            ExecutionState.UNKNOWN,
        }:
            raise ValueError("observation_state_required")
        self.journal.append(
            state.value,
            {"command_id": command_id, "at": now},
        )
        return state


def _parse_time(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)
